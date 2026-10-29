# Linux x86_64 Docker 部署

在本机构建 Linux amd64 镜像，上传到服务器后加载运行。服务器无需编译，也无需安装 Rust、Node.js 或 Zig。PostgreSQL、Redis 复用已有 Docker 容器，生产配置和日志保存在独立运行目录。

## 1. 目录与环境

服务器目录：

```text
/root/projects/pero/
├── source/                 # GitHub 源码，可选保留，不参与镜像加载后的运行
└── runtime/
    ├── .env                   # 构建生成的 Git 镜像标签
    ├── compose.yaml
    ├── config/
    │   ├── default.toml
    │   ├── production.toml
    │   ├── bootstrap.toml
    │   └── keys/{private,public}.pem
    └── logs/prd/
```

程序、内嵌迁移和 React 静态资源位于镜像内的 `/opt/pero/prd`。Compose 挂载 runtime 下的 config 和 logs，使用 host 网络监听宿主机 8080；原域名映射可继续指向该端口。

本机需要 Docker 引擎及 Buildx，配置打包另需 Python 3.11+。启动 Docker 后检查：

```bash
docker version
docker buildx version
python3 --version
```

`docker version` 应同时显示 Client 和 Server。脚本会识别 Mac 常用的 `~/.docker/bin/docker` 路径。若需要代理，在 Docker Desktop 中配置可用代理；CLI 必要时也设置 HTTP_PROXY/HTTPS_PROXY，地址按本机实际环境填写。

服务器需要 Docker Engine、Compose V2 和 x86_64 架构。以下服务器命令以 root 执行：

```bash
uname -m
docker version
docker compose version
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
docker port postgres
docker port redis
docker exec postgres psql -U postgres -d postgres -X -c 'SHOW server_version;'
```

PostgreSQL 必须为 **18+**，SQL 使用 `uuidv7()`。存储容器名为 postgres、redis；默认配置通过宿主机 127.0.0.1:5432/6379 访问，因此需要发布对应端口或使用 host 网络。不要直接将连接地址改为容器名。

## 2. 准备生产配置

本机私有配置默认位于 `local/deploy/pero/config/`。已有环境复用原连接信息、密码、密钥及管理员信息；首次配置可参考 `deploy/pero/production.toml.example` 和 `services/user-center/config/bootstrap.toml.example`。

关键配置：

| 配置 | 用途 |
| --- | --- |
| database.url / encrypt_key | PostgreSQL 连接与数据加密密钥 |
| redis.url | Redis 连接及专用逻辑库，默认 /0 |
| oidc.issuer / sso.base_url | 对外 HTTPS 域名 |
| sso.cookie_signing_secret / password_reset.signing_key | 独立随机密钥，各至少 32 字符 |
| frontend.static_dir | 容器内相对路径 `prd/ui/static` |
| log.dir | `./logs/prd` |
| bootstrap.toml 的 admin | 初始化管理员的用户名和密码 |

根据反向代理实际来源配置 `server.trusted_proxies`，并匹配代理清洗的 `client_ip_header`。未配置 notification 网关时，不提供邮件/短信通知投递。

在本机仓库根目录打包：

```bash
bash scripts/package-production-config.sh
# 默认 python3 低于 3.11 时指定可执行文件：
# PERO_PYTHON=/可用Python路径 bash scripts/package-production-config.sh
```

脚本以当前源码 default.toml 的结构生成 production.toml，迁入原匹配字段的值，新增字段使用最新默认值；旧 askama.static_dir 会迁入 frontend.static_dir。bootstrap 和 RSA 密钥保留。输出 `deploy/pero-config.tar.gz` 及 `.sha256` 校验文件。

配置包包含真实密码和私钥，只通过 SSH 传输，不提交 Git。打包前确认本机配置与实际生产信息一致。已有服务更新时，按新版配置结构调整生产配置，避免用示例或过期的本机配置覆盖服务器上的有效值。

## 3. 本机构建镜像

在仓库根目录执行：

```bash
bash scripts/build-docker-image.sh
```

脚本使用 Docker 多阶段构建，锁定 Rust 和前端依赖，固定目标为 linux/amd64。构建镜像包含编译工具，最终运行镜像仅保留程序、内嵌迁移、React 构建产物和初始化工具，不包含生产配置。

输出：

```text
deploy/pero-user-center-linux-amd64.tar.gz
deploy/pero-user-center-linux-amd64.tar.gz.sha256
deploy/pero-image.env
```

镜像标签为 `pero-user-center:git-<12位提交号>`，取当前仓库 HEAD。构建使用当前工作区文件，发布前应先提交要发布的改动，让提交号对应实际版本。`pero-image.env` 保存本次镜像标签，部署时安装为运行目录的 `.env`；无需服务器具有 Git 源码。

构建成功后再上传镜像包、校验文件和标签文件，不使用失败构建遗留的旧包。默认 Rust 编译并行度为 2，可通过 `PERO_BUILD_JOBS=4 bash scripts/build-docker-image.sh` 调整。基础镜像摘要固定在 Dockerfile 中，维护时应核对并更新摘要以获取系统安全更新。

## 4. 上传与加载

替换服务器地址，在本机执行：

```bash
scp deploy/pero-user-center-linux-amd64.tar.gz \
    deploy/pero-user-center-linux-amd64.tar.gz.sha256 \
    deploy/pero-image.env \
    deploy/pero-config.tar.gz deploy/pero-config.tar.gz.sha256 \
    root@SERVER:/tmp/
scp deploy/pero/compose.yaml root@SERVER:/tmp/pero-compose.yaml
```

服务器校验文件，两项均显示 OK 后再加载：

```bash
cd /tmp
sha256sum -c pero-user-center-linux-amd64.tar.gz.sha256
sha256sum -c pero-config.tar.gz.sha256
docker load -i /tmp/pero-user-center-linux-amd64.tar.gz
cat /tmp/pero-image.env
```

加载结果应显示 `pero-user-center:git-<提交号>`，并与 `pero-image.env` 一致，架构为 linux/amd64。Compose 使用 `pull_policy: never` 且没有 build 配置，只运行已加载的镜像。

## 5. 安装运行文件

首次部署先创建运行目录。如果已有服务正在运行，修改配置前先在原 runtime 中执行 `docker compose stop pero`。

```bash
install -d -m 700 /root/projects/pero/runtime
tar -xzf /tmp/pero-config.tar.gz -C /root/projects/pero/runtime
install -m 644 /tmp/pero-compose.yaml /root/projects/pero/runtime/compose.yaml
install -m 644 /tmp/pero-image.env /root/projects/pero/runtime/.env
cd /root/projects/pero/runtime

chown -R root:10001 config
find config -type d -exec chmod 750 {} +
find config -type f -exec chmod 640 {} +
install -d -o 10001 -g 10001 -m 750 logs logs/prd
docker compose config --quiet
docker image inspect "$(docker compose config --images)" --format '{{.Os}}/{{.Architecture}}'
ss -ltnp 'sport = :8080'
```

容器使用 UID/GID 10001，配置只读挂载，日志可写；rootless/userns-remap 环境需按实际 UID 映射调整目录权限。启动前确认 8080 没有旧进程监听。

## 6. 数据库准备与初始化

初始化要求空的 pero 数据库和专用 Redis 逻辑库。首次部署尚未建库时执行：

```bash
docker exec postgres psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE pero OWNER postgres TEMPLATE template0 ENCODING 'UTF8';"
```

已有数据需要保留时跳过建库和清理命令，不重复 bootstrap；schema 变化应先评估升级路径。**仅当明确需要丢弃全部 Pero 数据时**，先停止应用，再手动删除并重建专用数据库：

```bash
cd /root/projects/pero/runtime
docker compose down
docker exec postgres psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 \
  -c 'DROP DATABASE IF EXISTS pero WITH (FORCE);'
docker exec postgres psql -U postgres -d postgres -X -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE pero OWNER postgres TEMPLATE template0 ENCODING 'UTF8';"
```

清理 Redis 时，必须确认配置使用的逻辑库 `/0` 仅属于 Pero；共享时先识别数据归属，不整库删除：

```bash
docker exec redis redis-cli -n 0 FLUSHDB SYNC
docker exec redis redis-cli -n 0 DBSIZE
```

DBSIZE 应为 0。不删除存储容器或卷，不执行 FLUSHALL。需要清除旧日志时，在应用停止后执行 `find /root/projects/pero/runtime/logs -type f -delete`。

空库准备好后执行一次初始化：

```bash
cd /root/projects/pero/runtime
docker compose run --rm --no-deps --entrypoint python3 pero initialize.py
```

bootstrap 使用与服务启动相同的 Rust 迁移器检查 PostgreSQL 版本、校验历史、自动迁移并验收，然后创建 Provider、签名 key、管理员密码身份及系统应用访问权限。看到 `Initialization complete` 后继续；失败时先排查错误。管理员创建不幂等，成功后不要重复执行初始化。

## 7. 启动与验收

```bash
cd /root/projects/pero/runtime
docker compose up -d --no-build --force-recreate
docker compose ps
docker compose logs --tail=100 pero
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/ready
```

替换为生产配置中的域名，验证外部访问：

```bash
AUTH_URL=https://auth.example.com
curl -fsS "$AUTH_URL/health"
curl -fsS "$AUTH_URL/.well-known/openid-configuration"
curl -fsS "$AUTH_URL/api/oauth2/jwks"
curl -fsS "$AUTH_URL/static/index.html" -o /dev/null
```

浏览器打开生产域名 `/dashboard`，使用 bootstrap.toml 中的管理员账号密码登录，验证用户/应用管理、退出重登和静态资源。该密码不是 PostgreSQL 密码。清空数据后可用无痕窗口避开旧会话，并重新注册业务 OAuth client、登记回调地址、更新接入方凭证。

`/health`（兼容 `/api/health`）只检查进程存活；`/ready`（兼容 `/api/ready`）通过应用连接池并发检查数据库和 Redis，单项最多等待 2 秒。全部成功返回 200，否则返回 503，只输出依赖布尔状态。Compose healthcheck 使用 `/ready`；Kubernetes liveness 应使用 `/health`，readiness 使用 `/ready`。

## 8. 更新与维护

日常管理在运行目录执行：

```bash
cd /root/projects/pero/runtime
docker compose logs -f --tail=100 pero
docker compose restart pero
docker compose stop pero
```

更新代码后，本机重新构建并上传镜像包、校验文件及同次生成的 `pero-image.env`。服务器校验、docker load 后执行：

```bash
cd /root/projects/pero/runtime
install -m 644 /tmp/pero-compose.yaml compose.yaml
install -m 644 /tmp/pero-image.env .env
docker compose up -d --no-build --force-recreate
docker compose logs --tail=100 pero
```

查看当前镜像可执行 `docker compose config --images`。需要回退时，将 `.env` 中的 `PERO_IMAGE_TAG` 改为服务器已保留的旧提交标签，再重新创建容器；数据库迁移历史必须与目标版本匹配。

常规更新保留数据库和生产配置，不重复初始化。每次启动服务都会自动检查并迁移至镜像内最新版本，验收通过后才监听端口；无需单独运行迁移容器。迁移或验收失败则事务回滚，容器以失败状态退出，通过 `docker compose logs --tail=100 pero` 排查并修正原因后重启。此次合并初始迁移不接受旧 001–011 历史，旧环境应先备份并使用新库初始化、按需导入业务数据，不能直接覆盖迁移记录。配置结构变化时同步调整；Compose 有变化时同步模板。服务器 source 可保留用于同步源码，但运行服务不依赖它，不需要先 git pull，也不执行 docker compose build。

通用 Docker 文件、构建脚本、配置示例和本指南随代码追踪。local/ 下真实配置与私钥，以及 deploy 下的镜像包、配置包、校验文件、缓存和日志均不提交 Git。旧 scripts/deploy.sh 的 Zig 交叉编译入口独立保留，不用于此 Docker 部署。
