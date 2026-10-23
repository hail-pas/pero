# Linux x86_64：本地构建镜像，服务器加载运行

适用当前状态：服务器 /root/projects/pero/source 和 runtime 已配置，数据库/Redis 已手动清理。复用 runtime/config 中的原生产信息，本流程不再次清库、不重新传配置，服务器不再编译。

```text
本机 Git 仓库                  /root/projects/pero/
├── scripts/build-docker-image.sh   ├── source/       # 现有源码可保留
├── deploy/pero/                    └── runtime/      # 服务器实际运行目录
│   ├── Dockerfile                     ├── compose.yaml
│   ├── Dockerfile.dockerignore         ├── config/    # 原配置及密钥
│   └── compose.yaml                   └── logs/prd/
└── deploy/*.tar.gz             Docker 镜像存储由 Docker 引擎管理
```

## 1. 本机准备 Docker

本机需要可用的 Docker 引擎和 Buildx（例如 Docker Desktop），不需要本机 Rust、Zig 或 Python。先启动 Docker，再在本机终端确认：

```bash
docker version
docker buildx version
docker info
```

docker version 必须同时显示 Client 和 Server。Mac 安装说明见 [Docker 官方文档](https://docs.docker.com/desktop/setup/install/mac-install/)。

脚本会识别 Mac 常见的 ~/.docker/bin/docker 路径。若本机需通过代理访问 Docker Hub，在 Docker Desktop 的代理设置中使用当前可用代理；CLI 访问认证服务也可能需要显式设置 HTTP_PROXY/HTTPS_PROXY，例如 HTTP_PROXY=http://127.0.0.1:7890 HTTPS_PROXY=http://127.0.0.1:7890 bash scripts/build-docker-image.sh。代理地址按本机实际配置填写，不在 Dockerfile 中固定。

## 2. 本机构建并导出

在本机仓库根目录执行：

```bash
bash scripts/build-docker-image.sh
```

脚本固定 linux/amd64，即服务器 x86_64；即使本机是 Apple Silicon 也不会误生成 ARM 镜像。使用 Docker 多阶段构建，--load 将结果放入本机引擎；检查架构后用 docker image save 导出压缩包。镜像名固定为 pero-user-center:local。

Dockerfile 保持官方基础镜像摘要锁定，避免加速源的陈旧 tag。编译采用 Rust 1.95/Cargo.lock、原生 GNU 工具链；静态字典来自同次构建。私有配置不进入构建上下文或镜像。

输出：

```text
deploy/pero-user-center-linux-amd64.tar.gz
deploy/pero-user-center-linux-amd64.tar.gz.sha256
```

第一次会下载基础镜像和依赖，并执行完整编译。构建失败时脚本退出，不能把上次遗留的压缩包当作此次成功产物。默认编译并行度为 2，调整方式为 PERO_BUILD_JOBS=4 bash scripts/build-docker-image.sh。

## 3. 上传镜像和最新 Compose

替换服务器地址，在本机执行：

```bash
scp deploy/pero-user-center-linux-amd64.tar.gz \
    deploy/pero-user-center-linux-amd64.tar.gz.sha256 \
    root@SERVER:/tmp/
scp deploy/pero/compose.yaml root@SERVER:/root/projects/pero/runtime/compose.yaml
```

必须同步本版 Compose：已移除 build 配置，并设置 pull_policy: never，只使用加载的本地镜像，不会在服务器触发编译或访问镜像仓库。不要再从服务器 source 覆盖成旧版含 build 的 Compose；只有 source 同步到本版之后才可复制模板。

## 4. 服务器校验、加载

以下以 root 登录服务器执行：

```bash
cd /tmp
sha256sum -c pero-user-center-linux-amd64.tar.gz.sha256
```

必须看到 OK，然后执行：

```bash
docker load -i /tmp/pero-user-center-linux-amd64.tar.gz
docker image inspect pero-user-center:local --format '{{.Os}}/{{.Architecture}}'
```

应看到 Loaded image: pero-user-center:local，架构为 linux/amd64。使用 docker load，不使用 docker import。镜像已含程序、SQL、静态资源和初始化所需工具，服务器不用拉基础镜像、安装构建依赖。

## 5. 检查现有 runtime

```bash
cd /root/projects/pero/runtime
docker compose config --quiet
ls -l config/default.toml config/production.toml config/bootstrap.toml
ls -l config/keys/private.pem config/keys/public.pem
ss -ltnp 'sport = :8080'
```

确认旧进程已停止、8080 空闲、PostgreSQL 18+ 与 Redis 通过原宿主机 5432/6379 提供服务。Compose 继续使用 Linux host 网络，原域名映射不变。

当前存储容器名为 postgres、redis，可用 docker port postgres、docker port redis 核对宿主机端口发布。host 网络下仍使用 127.0.0.1，不直接改成容器名。初始化连接预检显式向 psql 传入完整 URI；失败时输出已隐藏密码的 PostgreSQL 错误，便于区分端口、密码、库名与 pg_hba 问题。

原先权限若已配置成功，不需要重复修改；需要时执行：

```bash
chown -R root:10001 config
find config -type d -exec chmod 750 {} +
find config -type f -exec chmod 640 {} +
install -d -o 10001 -g 10001 -m 750 logs logs/prd
```

## 6. 首次初始化与启动

如果此次清库后尚未成功初始化，执行一次：

```bash
docker compose run --rm --no-deps --entrypoint python3 pero initialize.py
```

它检查数据库版本、运行新版 migrate.sh，并按原配置创建 Provider、签名 key 和管理员。看到 Initialization complete 后继续。如果此前已经成功初始化，跳过本命令；管理员创建不幂等，不能重复全量 bootstrap。

```bash
docker compose up -d --no-build
docker compose ps
docker compose logs --tail=100 pero
curl -fsS http://127.0.0.1:8080/health
```

生产域名验收（替换为 production.toml 中的域名）：

```bash
AUTH_URL=https://auth.example.com
curl -fsS "$AUTH_URL/health"
curl -fsS "$AUTH_URL/.well-known/openid-configuration"
curl -fsS "$AUTH_URL/api/oauth2/jwks"
curl -fsS "$AUTH_URL/static/index.html" -o /dev/null
```

浏览器登录生产域名 /dashboard，用原管理员验证用户/应用管理、退出重登。/health 只检查进程存活。清库后业务 OAuth client 要重新创建并更新业务端凭证。若原代理 alias 到旧静态目录，改为将 /static 转发到服务的 8080，避免继续读取历史资源。

## 7. 后续更新

本机修改代码后重新运行 build-docker-image.sh，上传镜像和校验文件；服务器验证 SHA256、docker load，再执行：

```bash
cd /root/projects/pero/runtime
docker compose up -d --no-build --force-recreate
docker compose logs --tail=100 pero
```

不重新清库、不重复初始化、不覆盖原生产配置；未来 schema 变更要单独评估升级路径。服务器 source 只作为参考/同步源码保留，运行服务不依赖它，也不执行 docker compose build。

## 8. Git 管理与可选配置打包

通用 Docker 文件、构建/配置打包脚本、部署测试和本指南随代码追踪。local/ 下真实配置、私钥，以及 deploy/*.tar.gz、校验文件、缓存、日志不提交。

scripts/package-production-config.sh 仍可用于首次迁移配置，本机需要 Python 3.11+；当前 runtime 已配置，无需再次打包或上传。旧 scripts/deploy.sh 的 Zig 交叉编译流程独立保留，不用于本 Docker 部署。
