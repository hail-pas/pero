# 数据库迁移与失败恢复

服务启动、首次初始化（bootstrap）和独立 `migrate` 工具共用 Rust 迁移器。迁移 SQL 和验收规则编译进发布二进制。服务和 bootstrap 使用环境配置中的数据库连接，独立工具通过 `DATABASE_URL` 连接。源码目录可用 `scripts/migrate.sh` 调用当前版本的迁移工具。

## 启动流程

1. 连接数据库后启动事务并获取迁移锁，检查 PostgreSQL 版本是否为 18 或以上。
2. 核对 `schema_migrations`。已应用的文件名必须依次匹配发布版本开头的迁移，且每个文件的 SHA-256 必须一致。
3. 按文件名顺序执行所有未应用迁移，与版本记录一同写入当前事务。
4. 按 `verify.sql` 检查必要表和字段、关键唯一索引、约束、注销和通知触发器、pgcrypto 及种子数据。每次启动均执行验收。
5. 提交成功后，服务启动后台任务并监听 HTTP 端口。`/ready` 检查数据库和 Redis 的运行状态。

锁等待上限为 60 秒，SQL 语句超时为 120 秒。并行启动的副本串行执行检查，后续副本确认历史后跳过已应用迁移。发版验收仍需覆盖业务登录和实际应用接入。

## 初始基线与后续升级

`001_init.sql` 是当前首发基线，用于空库。已有数据库只有迁移历史与校验和均匹配时才能原位升级。运行过其他基线的旧库，包括同名但校验和不同的 `001_init.sql`，需要先备份，再初始化新库、按业务需要显式导入数据并验证后切换。

基线将 `pgcrypto` 和 `citext` 安装在数据库的 `public` schema，应用表位于当前 schema。使用自定义 `search_path` 时，将应用 schema 放在 `public` 之前。

发布后保持已发布迁移文件不变。后续变更使用三位递增编号的迁移文件，并同步更新 [数据库验收规则](../services/user-center/src/db/verify.sql)。构建自动收集 `migrations/*.sql`，发布前在专用测试库验证。迁移文件仅包含可在迁移事务中执行的 SQL，大规模维护或独立事务操作单独安排。

## 验收失败与恢复

### 本地 `make dev` 提示 history/checksum mismatch

如果出现 `Migration history/checksum mismatch at 001_init.sql`，先确认 `local.toml` 指向的数据库及其迁移历史。保留旧数据库，使用新库验证当前版本。

```bash
# 将 pero 替换为 local.toml 中的数据库角色；新库名必须尚未存在。
createdb --owner=pero pero_dev_v2
cp -p services/user-center/config/local.toml services/user-center/config/local.toml.before-baseline
# 编辑 local.toml，仅将 database.url 中的库名改为 pero_dev_v2，保留连接凭据和加密密钥。
# 确认 bootstrap.toml 与 config/keys 已就绪，再初始化这个新库。
make bootstrap
make dev
```

新库的管理员使用 `bootstrap.toml` 中的凭据。旧库用户、OAuth 客户端和业务数据需显式导入。恢复旧环境时，使用备份配置和与旧迁移历史匹配的软件版本。保留 `schema_migrations` 及其校验和。

### 运行环境恢复

SQL、历史核对或验收失败时，当前事务回滚，进程以失败状态退出。执行 `docker compose logs --tail=100 pero` 查看原因。数据库权限、锁冲突或配置问题修复后可重启，迁移器会重新核对并重试。

升级前保存数据库备份及配套镜像和配置。回退时核对目标镜像的迁移历史。如果新版本已提交旧镜像无法识别的迁移，恢复与旧版本匹配的数据库备份后再启动，并处理备份后的业务写入。部署操作见 [Linux Docker 部署指南](../deploy/pero/README.md)。

首次部署在迁移验收后通过 bootstrap 创建本地身份提供方、签名密钥和超级管理员。常规升级由服务启动执行迁移。

## 验证

[迁移测试](../tests/migrations_test.sh) 在专用数据库的隔离 schema 验证首次迁移、并发启动和重复执行，并检查校验和不匹配、未知版本和停用安全触发器时的失败行为。[Rust 迁移回归](../services/user-center/src/db/migrate.rs) 覆盖 SQL 或验收失败后的事务回滚，以及修复后重试。
