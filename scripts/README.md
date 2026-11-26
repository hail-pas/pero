# Pero 脚本

以下示例在仓库根目录执行。生产构建、上传和上线步骤见 [Docker 部署指南](../deploy/pero/README.md)。

## 生产构建与配置

### [build-docker-image.sh](build-docker-image.sh)

使用 Docker Buildx 构建并加载 Linux amd64 镜像 `pero-user-center:git-<提交短哈希>`。检查镜像架构后，在 `deploy/` 下生成 `pero-user-center-linux-amd64.tar.gz`、对应的 `.sha256` 和 `pero-image.env`。

```bash
bash scripts/build-docker-image.sh
```

需要已启动的 Docker、Buildx、Git、gzip 和 shasum。可用 `PERO_BUILD_JOBS` 调整镜像内的 Cargo 并行数，默认 2。镜像标签取自当前 `HEAD`，构建上下文使用工作区文件，发布前应提交要构建的改动。上线时应使用同一次构建生成的归档、校验文件和标签。

### [package-production-config.sh](package-production-config.sh)

首次部署、清空重部署或重新安装生产配置时使用。默认从 `local/deploy/pero/config/` 读取 `production.toml`、`bootstrap.toml`、`keys/private.pem` 和 `keys/public.pem`。将源码的 `default.toml` 和同步后的生产配置一并归档，生成 `deploy/pero-config.tar.gz` 和对应的 `.sha256`。

```bash
bash scripts/package-production-config.sh
bash scripts/package-production-config.sh --config-dir /path/to/private/config
```

需要 Python 3.11+、tar 和 shasum。默认解释器是 `python3`，可通过 `PERO_PYTHON` 指定。归档包含数据库凭据和私钥，权限为 `0600`，应通过 SSH 传输并保存在受限目录。配置字段见 [user-center 配置指南](../services/user-center/config/README.md)。

### [sync-deploy-config.py](sync-deploy-config.py)

供配置打包脚本调用。按当前 `default.toml` 的字段生成配置，保留仍受支持的生产覆盖项和已知可选字段，补充缺省值并移除已废弃的未知字段。解析并验证生成的 TOML 后，通过临时文件原子写入指定输出，文件权限为 `0600`。

```bash
python3 scripts/sync-deploy-config.py \
  --defaults services/user-center/config/default.toml \
  --previous /path/to/private/production.toml \
  --output /path/to/private/production.next.toml
```

需要 Python 3.11+。单独调用时，可先写到新文件，核对结果后再替换运行配置。

## 本地开发与数据库维护

### [build-frontend.sh](build-frontend.sh)

在 `frontend/` 执行 `pnpm install --frozen-lockfile` 和 `pnpm build`，生成 `frontend/dist/`。供本地开发和 CI 共用。需要项目要求的 Node.js 和 pnpm。

```bash
bash scripts/build-frontend.sh
```

### [dev.sh](dev.sh)

`make dev` 的入口。读取已准备好的本地配置，构建前端，然后以 release 模式启动 `user-center`。脚本设置 `PERO_RUN_MODE=local`，服务仅监听 `127.0.0.1`，静态资源指向 `frontend/dist/`。需要配置文件 `services/user-center/config/local.toml`、可用的 PostgreSQL 和 Redis，以及已完成首次初始化的本地环境。

```bash
make dev
```

### [migrate.sh](migrate.sh)

显式调用 Rust 迁移器，使用 `DATABASE_URL` 指定目标数据库，无位置参数。Docker 镜像中执行同目录的 `migrate` 二进制，源码目录中通过 Cargo 执行。CI 和 Docker 镜像都引用该脚本。常规生产启动及首次 bootstrap 会自动执行版本核对、迁移和结构验收。

```bash
DATABASE_URL='postgres://USER@127.0.0.1:5432/pero_dev' bash scripts/migrate.sh
```

迁移历史和恢复流程见 [数据库迁移指南](../docs/database-migrations.md)。

### [generate-entity.sh](generate-entity.sh)

从指定数据库 schema 生成 SeaORM 实体，写入 `services/<service>/src/db/entity/`。后处理会移动枚举到 `src/db/enums.rs`、修正 PostgreSQL 自定义类型映射，并让生成的实体在序列化时跳过指定的凭据字段。若本机有 `rustfmt`，同时格式化生成的 Rust 文件。

```bash
make entity SERVICE=user-center DATABASE_URL='postgres://USER@127.0.0.1:5432/pero_dev'
./scripts/generate-entity.sh --postprocess-only user-center
```

完整生成需要 `sea-orm-cli` 和 Python 3。仅后处理使用现有实体文件，无需连接数据库。生成后用 `cargo check -p user-center` 验证。

## CI 依赖审计

### [check-advisories.py](check-advisories.py)

读取 `cargo audit --json --deny warnings` 的完整报告，检查漏洞和警告是否符合仓库的精确版本、类型和有效期策略。遇到未处置或豁免已过期的条目时，以非零状态退出。需要 Python 3，并由 CI 生成和上传审计报告。报告含发现时仍应交给策略脚本处理。

```bash
python3 scripts/check-advisories.py audit.json
```

### [check-osv.py](check-osv.py)

读取 `Cargo.lock` 中 registry 来源的精确版本，批量查询 OSV 的 crates.io 公告。保留可见的精确版本豁免记录，对未处置发现、结果数量不符或需要继续分页的响应返回失败。需要 Python 3.11+ 和 OSV 网络访问。

```bash
python3 scripts/check-osv.py
```

两种审计的配置和调用见 [公告处理策略](../.github/security/advisory-policy.json) 和 [CI 工作流](../.github/workflows/check.yml)。
