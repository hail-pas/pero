# Linux x86_64：GitHub 源码 + Docker 多阶段构建

数据已手动清理，本流程不再清库。原 PostgreSQL、Redis 容器继续使用。源码与运行数据分开：

```text
/root/projects/pero/
├── source/                    # GitHub 仓库，可 git pull
│   ├── Cargo.toml / Cargo.lock
│   ├── crates/ / services/
│   └── deploy/pero/            # 通用 Docker 文件、初始化程序、指南
└── runtime/                   # 不属于 Git 仓库
    ├── compose.yaml           # 从 source/deploy/pero 复制
    ├── config/                # 生产配置、bootstrap、keys
    └── logs/prd/              # 持久化日志
```

容器内部仍使用 /opt/pero；程序、SQL、静态资源在镜像内 prd/，宿主机无需放二进制。原 /root/projects/pero 下的历史 config/prd 不会被本流程删除，确认迁移完成后可自行归档。

## 1. 首先提交并推送部署文件

本次新增/修改的部署文件须先提交推送到 GitHub，服务器才能拉到。推送前查看 git status，确认不包含生产秘密。

| 可以追踪 | 不追踪 |
| --- | --- |
| deploy/pero/Dockerfile、Dockerfile.dockerignore、compose.yaml、initialize.py、README.md、production.toml.example | local/ 下真实生产配置和私钥 |
| scripts/package-production-config.sh、sync-deploy-config.py、tests/docker_deploy_test.py | deploy/*.tar.gz、校验文件、日志、构建缓存 |
| Cargo.lock、业务源码、原默认配置及示例 | runtime 中全部运行信息（其本身在仓库外） |

旧 scripts/deploy.sh 是单独的二进制交叉编译入口，Docker 流程不再调用它，不需要 Zig/cargo-zigbuild 或本机 Rust。原 prepare-docker-release.sh 已移除。

## 2. 本机只打包原生产配置

在本机仓库根目录运行。只需 Python 3.11+、bash/tar/shasum，不需要本机 Docker 或 Rust：

```bash
bash scripts/package-production-config.sh
# python3 低于 3.11 时：
# PERO_PYTHON=/可用Python路径 bash scripts/package-production-config.sh
```

默认读取 local/deploy/pero/config，生成最新 default.toml，并按其字段结构生成 production.toml，再迁入原匹配字段的值；bootstrap 与 RSA 密钥原样保留。输出：

```text
deploy/pero-config.tar.gz
deploy/pero-config.tar.gz.sha256
```

私有包仅含 config/，没有源码或二进制。原域名、数据库/Redis 连接、密码、密钥、管理员保持不变。配置包和 GitHub 源码应来自同一版本；以后新增可选字段按最新代码在生产配置中补充。

上传到服务器，替换服务器地址：

```bash
scp deploy/pero-config.tar.gz deploy/pero-config.tar.gz.sha256 root@SERVER:/tmp/
```

## 3. 服务器准备目录与源码

以下以 root 登录 x86_64 Linux 服务器执行。需要 Git、Docker Engine、Compose V2/BuildKit；不需要宿主机 Rust、Zig、Python、psql。构建需访问 Docker Hub、Debian 软件源及 crates.io。

```bash
uname -m
git --version
docker version
docker compose version
install -d -m 700 /root/projects/pero
install -d -m 700 /root/projects/pero/runtime
```

首次拉取（需服务器已配置该 GitHub 仓库的 SSH 访问权限）：

```bash
git clone git@github.com:hail-pas/pero.git /root/projects/pero/source
```

如果 source 已经是该仓库，则改为：

```bash
git -C /root/projects/pero/source status --short
git -C /root/projects/pero/source pull --ff-only
```

不要在有未处理本地改动时覆盖。默认使用仓库默认分支/当前跟踪分支；需要特定发布版本时自行 checkout 已确认的分支或 tag。

```bash
git -C /root/projects/pero/source log -1 --oneline
ls /root/projects/pero/source/deploy/pero/Dockerfile
cp /root/projects/pero/source/deploy/pero/compose.yaml /root/projects/pero/runtime/compose.yaml
```

compose.yaml 必须放在 runtime：其构建上下文 ../source 指向源码，./config、./logs 指向 runtime 内的私有数据。

## 4. 安装原生产配置与权限

```bash
cd /tmp
chmod 600 pero-config.tar.gz
sha256sum -c pero-config.tar.gz.sha256
```

必须看到 OK，再继续：

```bash
tar -xzf /tmp/pero-config.tar.gz -C /root/projects/pero/runtime
cd /root/projects/pero/runtime
chown -R root:10001 config
find config -type d -exec chmod 750 {} +
find config -type f -exec chmod 640 {} +
install -d -o 10001 -g 10001 -m 750 logs logs/prd
```

镜像进程按 UID/GID 10001 运行，配置只读挂载、日志可写。权限适用于普通 Docker Engine；rootless/userns-remap 场景需按宿主机 UID 映射调整。

原配置采用 0.0.0.0:8080、127.0.0.1:5432/pero、127.0.0.1:6379/0。Compose 使用 Linux host 网络，因此这些连接信息无需改为容器名，也无需 ports 映射。确认存储容器发布了对应宿主机端口或本身采用 host 网络，PostgreSQL 必须为 18+，8080 不被旧服务占用：

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
docker exec 实际PostgreSQL容器名 postgres --version
ss -ltnp 'sport = :8080'
```

## 5. 在服务器 Docker 内构建

```bash
cd /root/projects/pero/runtime
docker compose config --quiet
docker compose build --pull
```

Dockerfile 使用 rust:1.95.0-bookworm 在 Linux amd64 构建阶段原生编译，使用 Cargo.lock；GNU 工具链由构建镜像提供，不涉及 Zig/musl 交叉编译。同次构建生成的字典会复制到运行镜像。第二阶段使用同代 Debian 运行环境，复制二进制、静态资源和 SQL，不包含 Rust 工具链或源码。

Dockerfile.dockerignore 从构建上下文中排除 Git 数据、local/、生产配置、私钥及缓存；生产配置目录又在源码目录外。构建默认并行任务数为 2，可按机器资源调整：

```bash
# 资源有限时可用此命令代替上面的 build；链接仍需足够内存。
docker compose build --pull --build-arg CARGO_BUILD_JOBS=1
```

首次编译耗时取决于服务器 CPU、内存和网络；后续可复用 Docker/Cargo 缓存。构建失败时先排查完整编译输出，不启动旧镜像充当本次部署。

## 6. 初始化已清空的数据库（本次仅一次）

构建成功后执行：

```bash
docker compose run --rm --no-deps --entrypoint python3 pero initialize.py
```

先核对数据库连接与 PostgreSQL 18+，再执行最新 migrate.sh，最后按原配置创建 Provider、签名 key 和管理员。不删除任何数据。看到 Initialization complete 后继续。管理员创建不幂等，成功后不要再次初始化；失败时先查看原因，不盲目重复或再次清库。

如需代理后的真实客户端 IP，在 production.toml 已有 [server] 中按实际代理来源添加 trusted_proxies，匹配代理清洗的 client_ip_header。同机 loopback 代理可用 ["127.0.0.1/32", "::1/128"]；容器/远端代理需实际核对。notification 未配置时不会发送邮件/短信。

## 7. 启动和验收

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100 pero
curl -fsS http://127.0.0.1:8080/health
```

将下面域名替换为生产配置中的 issuer：

```bash
AUTH_URL=https://auth.example.com
curl -fsS "$AUTH_URL/health"
curl -fsS "$AUTH_URL/.well-known/openid-configuration"
curl -fsS "$AUTH_URL/api/oauth2/jwks"
curl -fsS "$AUTH_URL/static/js/i18n.js" -o /dev/null
```

原域名映射继续指向 8080。推荐 /static 一并反向代理到服务；如果原代理直接 alias 到旧 prd/ui/static，需改为转发到 8080，或另行导出静态资源并调整 alias，不能继续指向历史资源目录。

浏览器打开生产域名 /dashboard，用原管理员登录，验证用户/应用管理与退出重登。/health 仅为进程存活检查，不能代替真实登录验收。清库后业务 OAuth client 需重新创建并更新业务端凭证。

## 8. 后续维护

```bash
cd /root/projects/pero/runtime
docker compose logs -f --tail=100 pero
docker compose restart pero
docker compose stop pero
```

以后更新源码并重新构建：

```bash
git -C /root/projects/pero/source pull --ff-only
cp /root/projects/pero/source/deploy/pero/compose.yaml /root/projects/pero/runtime/compose.yaml
cd /root/projects/pero/runtime
docker compose build --pull
docker compose up -d
```

不重新清库、不重复 bootstrap，不从示例覆盖真实配置。如果未来 schema 改变，需要先评估升级路径。配置变更后使用 docker compose up -d --force-recreate 使进程重新读取。

容器退出会按 unless-stopped 策略恢复；健康检查失败仅标记 unhealthy，不自动重启。日志权限错误先检查组 10001；数据库连接失败检查存储端口、密码和 pg_hba；端口冲突检查旧服务。镜像构建阶段内存不足应增加可用内存/交换空间或降低并行度。

参考：[Docker 多阶段构建](https://docs.docker.com/build/building/multi-stage/)、[构建上下文排除规则](https://docs.docker.com/build/concepts/context/#dockerignore-files)、[Linux host 网络](https://docs.docker.com/engine/network/drivers/host/)。
