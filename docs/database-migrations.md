# 数据库迁移与失败恢复

服务启动、bootstrap、独立 `migrate` 工具使用同一个 Rust 迁移器。SQL 和验收语句编译进二进制，修改部署目录的 SQL 不会改变正在运行的版本。`scripts/migrate.sh` 只负责调用对应迁移工具；源码目录下通过 Cargo 运行。普通启动直接使用配置中的连接，不要求设置 `DATABASE_URL`。

## 启动流程

1. 建立连接并注入数据库加密会话配置，检查 PostgreSQL 18+。
2. 事务内获取迁移锁，核对 `schema_migrations` 是否为当前版本历史的完整前缀，以及各文件的 SHA-256。
3. 按文件名顺序执行所有未应用迁移，与版本记录一同写入当前事务。
4. 验收所有应用表和字段可访问、关键唯一索引有效、恢复凭据配对约束存在、注销和通知触发器启用、pgcrypto 可用、必要种子数据存在。验收在无新迁移时同样执行。
5. 提交成功后才启动后台任务和 HTTP 监听。`/ready` 继续检查数据库、缓存等运行依赖。

锁等待上限 60 秒，单次 SQL 操作上限 120 秒。多副本启动会串行检查，后续副本确认历史后跳过已应用迁移。这里的结构验收是明确列出的关键不变量检查，不是整个数据库与原始 SQL 的完整等价比较，也不替代升级后的业务验证。

## 初始基线与后续升级

当前只保留 `001_init.sql`，包含原 001–011 的最终结构和必要种子数据，删除历史数据回填和升级时会话撤销逻辑。旧数据库的迁移 checksum 不匹配时直接拒绝启动。已有数据先备份，创建新库并初始化，按业务需要显式导入数据；不要删除历史表或修改 checksum 来绕过检查。自动流程不清库、不猜测旧结构。

后续迁移使用三位递增编号，例如 `002_add_feature.sql`；构建时自动收集 `migrations/*.sql`。同步更新 `src/db/verify.sql`，使用专用测试库验证后发布。已发布迁移保持不变；迁移文件只能包含可事务执行的 SQL，不使用 `COMMIT`、`CREATE INDEX CONCURRENTLY` 或客户端元命令。需要更长时间或独立事务的大规模数据维护应单独安排。

## 验收失败与恢复

### 本地 `make dev` 提示 history/checksum mismatch

前端和 Rust 构建成功后出现 `Migration history/checksum mismatch at 001_init.sql`，表示配置指向的数据库使用旧迁移基线。重新构建前端、重复 bootstrap 或重启 PostgreSQL 都不能解决。保留旧库，创建一个独立开发库：

```bash
# 将 pero 替换为 local.toml 中的数据库角色；新库名必须尚未存在。
createdb --owner=pero pero_dev_v2
cp -p services/user-center/config/local.toml services/user-center/config/local.toml.before-baseline
# 编辑 local.toml，仅将 database.url 中的库名改为 pero_dev_v2，保留连接凭据和加密密钥。
# 确认 bootstrap.toml 与 config/keys 已就绪，再初始化这个新库。
make bootstrap
make dev
```

`make dev` 自动执行迁移检查，但不会创建数据库或初始化管理员。新库的管理员使用 `bootstrap.toml` 中的凭据；旧库用户、OAuth 客户端和业务数据不会自动复制。需要恢复旧环境时，将备份配置恢复，并使用与旧迁移历史匹配的代码版本。不要删除 `schema_migrations` 或改写 checksum。

### 运行环境恢复

SQL、历史核对或验收失败都会回滚当前事务，版本记录与结构变更不会部分提交，进程以失败状态退出。Docker 使用现有 restart 策略重试；日志可通过 `docker compose logs --tail=100 pero` 查看。修复权限、锁冲突、配置或缺失结构后重启，迁移器会重新核对并重试。不会自动降级已成功提交的迁移：发布前保留数据库备份，回退镜像必须与数据库历史匹配；旧镜像遇到未知新版本会拒绝启动。

首次 bootstrap 在迁移验收成功后创建 Provider、密钥和管理员。常规升级只需启动服务，不重复 bootstrap。生产镜像内不再依赖 psql、Perl SHA 工具执行迁移。

## 验证

`tests/migrations_test.sh` 在专用数据库的隔离 schema 中验证首次迁移、并发启动、重复执行、checksum 篡改、未知版本和禁用安全触发器的拒绝。Rust 迁移回归验证升级 SQL 失败、验收失败时结构和历史同时回滚，以及修复后重试成功。既有认证、授权、权限和 MFA 测试使用同一迁移器建立测试结构。
