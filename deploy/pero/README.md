# Pero Docker 部署

构建机需要 Docker Buildx。生产环境需要 x86_64 Linux、Docker Compose V2、PostgreSQL 18+ 和 Redis。应用通过 host 网络访问存储，现有 Nginx 将生产域名转发到应用端口 `8080`。

## 构建与加载

在仓库根目录构建镜像。首次部署、清空重部署或重装配置时，按[服务配置指南](../../services/user-center/config/README.md)准备私有文件，再执行配置打包。

```bash
bash scripts/build-docker-image.sh
bash scripts/package-production-config.sh  # 需要安装生产配置时执行
```

将 `deploy/` 下的镜像归档、对应的 `.sha256`、`pero-image.env` 和 [compose.yaml](compose.yaml) 传到服务器。需要安装配置时，一并传送 `pero-config.tar.gz` 和对应的 `.sha256`。配置包含凭据和私钥，使用 SSH 等受保护的方式传输。

在服务器的发布文件目录校验并加载镜像。

```bash
sha256sum -c pero-user-center-linux-amd64.tar.gz.sha256 &&
  docker load -i pero-user-center-linux-amd64.tar.gz
sha256sum -c pero-config.tar.gz.sha256  # 需要安装生产配置时执行
```

校验通过后选择部署场景。运行目录自行选定，Compose 命令在对应的运行目录执行。

## 初始化部署

初始化需要空 PostgreSQL 库和空的专用 Redis 逻辑库。以下以容器 `postgres`、`redis`、数据库及角色 `pero` / `postgres`、Redis DB 0 为例，按实际配置调整。

### 清空重部署

首次部署直接进入「安装并初始化」。清空重部署先在旧运行目录停止 Pero，并备份旧配置和数据库。以下将数据库备份写入 `pero-before-reset.dump`，执行前选定新的备份文件名。

```bash
umask 077
docker compose stop pero &&
  docker exec postgres pg_dump -U postgres -d pero -Fc > pero-before-reset.dump &&
  docker exec -i postgres pg_restore --list < pero-before-reset.dump > /dev/null
```

确认备份可用、数据库和 Redis 逻辑库均为 Pero 专用后，再清理。若 Redis 库共享，只删除已确认属于 Pero 的键，并为新部署选用专用库。存储容器及其卷继续使用。

```bash
docker exec postgres psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'DROP DATABASE pero WITH (FORCE);' &&
  test "$(docker exec redis redis-cli --raw -e -n 0 FLUSHDB SYNC)" = OK &&
  test "$(docker exec redis redis-cli --raw -e -n 0 DBSIZE)" = 0
```

### 安装并初始化

创建数据库。已备好空库时跳过此命令。

```bash
docker exec postgres psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE pero OWNER postgres TEMPLATE template0 ENCODING 'UTF8';"
```

将 `compose.yaml` 放入运行目录，并将 `pero-image.env` 在运行目录下安装为 `.env`，在运行目录解包。权限示例对应容器 UID/GID `10001:10001`。

```bash
tar -xzf ./pero-config.tar.gz &&
  chown -R root:10001 config &&
  find config -type d -exec chmod 750 {} + &&
  find config -type f -exec chmod 640 {} + &&
  install -d -o 10001 -g 10001 -m 750 logs logs/prd &&
  docker compose config --quiet &&
  docker compose run --rm --no-deps -T --entrypoint python3 pero initialize.py
```

看到 `Initialization complete` 后进入启动与验收。初始化失败时先检查错误和数据库状态。

## 更新现有部署

备份运行文件和数据库，用新版本的 `compose.yaml` 和 `pero-image.env` 分别更新运行目录的 `compose.yaml` 和 `.env`，沿用现有生产配置和数据。随后执行启动与验收，服务启动时自动执行兼容迁移。

回退时恢复配套的旧镜像标签、Compose 和配置。数据库迁移历史需与目标版本匹配，详见[迁移与恢复](../../docs/database-migrations.md#运行环境恢复)。

## 启动与验收

```bash
docker compose up -d --no-build --wait --wait-timeout 120 pero
docker compose ps pero
curl -fsS http://127.0.0.1:8080/ready
```

访问 `/dashboard` 验证管理员登录。首次进入后台需绑定 TOTP 并保存恢复码。清空重部署后重新登记业务 OAuth 客户端和回调地址，并验证业务登录。

启动失败时查看 `docker compose logs --tail=100 pero`。
