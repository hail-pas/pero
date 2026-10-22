# Pero

Rust 身份认证中心，基于 Axum / SeaORM / Redis，提供 OAuth2 / OpenID Connect 服务。

## 服务

- **user-center** — 核心认证服务（OAuth2 授权、Token 签发、JWKS、用户管理）
- **admin** — OAuth2 登录示例和受保护首页；用户与应用管理位于 user-center `/dashboard`

## 依赖

- Rust 1.95+ (edition 2024)
- PostgreSQL 18+（schema 使用 `uuidv7()`）
- Redis
- 构建部署包需 Python 3（复制该次构建生成的前端字典）

## 快速开始

```bash
# 1. 生成 RSA 密钥
make gen-keys

# 2. 复制并编辑配置
cp services/user-center/config/local.toml.example services/user-center/config/local.toml
cp services/user-center/config/bootstrap.toml.example services/user-center/config/bootstrap.toml

# 3. 初始化 schema（需 psql；DATABASE_URL 指向步骤 2 配置的数据库）
export DATABASE_URL=postgres://pero:CHANGE_ME@127.0.0.1:5432/pero
./scripts/migrate.sh
make bootstrap

# 4. 启动
(cd services/user-center && cargo run --bin user-center -- --config-dir config)
# 先注册对应 OAuth client，再配置 admin 的 local.toml
cp services/admin/config/local.toml.example services/admin/config/local.toml
(cd services/admin && cargo run --bin admin -- --config-dir config)
```

## 初始化与配置

Linux Docker 部署见 [deploy/pero/README.md](deploy/pero/README.md)。本机通过 `scripts/build-docker-image.sh` 构建 Linux amd64 镜像并导出，服务器加载后在 `/root/projects/pero/runtime` 启动，无需服务器编译或本机 Rust/Zig。现有 `/root/projects/pero/source` 可保留；`scripts/package-production-config.sh` 仅在需要迁移配置时使用，私有包不提交 Git。

项目以首次部署为基线，仅提供 `001_init.sql`，适用于空数据库。`scripts/migrate.sh` 在事务内初始化并记录 checksum，重复执行会校验并跳过已应用的 SQL。标准 `scripts/deploy.sh` 部署包包含配置默认值、示例、初始化 SQL 和迁移脚本；不包含真实配置或私钥。目标环境需独立提供密钥。

配置 `notification.endpoint` 和 `notification.bearer_token` 后，服务将通知加密入库并由后台任务投递；数据库连接使用的 `app.encrypt_key` 必须保持一致。没有配置通知网关时，联系方式验证和密码恢复不会报告已发送。

密码恢复仅向已有本地密码的账号发送重置链接。仅使用第三方登录的账号可先登录，再在 `/account/change-password` 设置本地密码；找回密码页面始终使用统一提示，不暴露账号是否具备恢复资格。

静态资源只保留当前版本。前端字典由 `ui/locales/*.toml` 构建成 `i18n.js`，服务直接提供该字典，部署打包时复制同一次构建的输出，供反向代理托管。

## 验证

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
node tests/forms_test.cjs
bash tests/generate_entity_postprocess_test.sh

# 专用 PostgreSQL 18 测试库，先执行 scripts/migrate.sh；禁止指向业务库。
# 每个场景创建独立 schema，可重复执行。
PERO_TEST_DATABASE_URL=postgres://USER@127.0.0.1:PORT/pero_security_test \
PERO_TEST_REDIS_URL=redis://127.0.0.1:6379 \
  cargo test -p user-center --locked -- --ignored
```

真实 Redis 测试会短暂暂停专用 Redis 实例，不能指向业务 Redis：

```bash
PERO_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p pero-cache-redis --locked --test live_redis -- --ignored
PERO_TEST_DATABASE_URL=postgres://USER@127.0.0.1:PORT/pero_security_test bash tests/migrations_test.sh
python3 tests/check_advisories_test.py
cargo audit --json --deny warnings > audit.json
python3 scripts/check-advisories.py audit.json
```

依赖审计保留完整报告；当前没有接受中的告警，见 `.github/security/advisory-policy.json`。未评估告警、撤包或接受期到期均令 CI 失败，不使用全局 ignore。Askama 关闭配置文件功能，使用各服务默认的 `templates/` 目录，避免引入停维护的 `basic-toml`。

`sso.session_touch_interval_seconds` 默认 `0`，保持每次请求刷新 idle 时间；可显式设置不超过 `30` 秒且不超过 idle TTL 的 `1%`，减少高频请求的数据库写入。代价是空闲到期时间最多提前该间隔，每次请求仍查询数据库撤销状态。清理任务每轮每类最多 20 批、每批 500 条，积压会在后续轮次继续处理。

刷新令牌支持可选 `scope` 子集；未传时保持原授权范围，扩大范围返回 `invalid_scope`，不会消耗令牌。新的刷新令牌保留原授权范围，降权仅作用于此次 access token。尚无账户选择界面，`prompt=select_account` 明确返回 `invalid_request`。数据库/Redis 临时故障不会当作用户凭证失效；UserInfo 返回 503 时 admin 保留登录 Cookie。

部署包可直接执行 `DATABASE_URL=... bash ./migrate.sh`，也可通过参数或 `MIGRATIONS_DIR` 指定目录。checksum 不一致会报错回滚。

## 注销与上游密钥缓存

注销支持 GET query 和标准表单 POST。hint 无法关联当前用户及会话时，通过带 CSRF 保护的页面确认。过期 hint 仅用于注销，普通认证令牌仍严格校验有效期。Access Token 使用 `typ=at+jwt`，ID Token 使用 `typ=JWT`。OAuth scope 按大小写精确匹配，手机号登录与找回密码使用数据库中存储的完整号码。

`oauth2.upstream_jwks_cache_ttl_seconds` 默认 `0`，保持每次上游登录重新获取 JWKS；可显式设置为 `1–300` 秒以减少网络请求。启用后，已缓存 key 的撤销最多延迟该 TTL；过期缓存刷新失败不会继续接受旧 key。Provider 配置变更隔离缓存，未知 kid 刷新有 5 秒冷却。没有改变本地签名 key 的数据库启用状态检查。

浏览器回归使用专用测试库和 Redis，真实 Chromium 覆盖登录、切换用户、取消/确认退出和过期 hint：

```bash
npm ci --prefix tests/browser --ignore-scripts
npx --prefix tests/browser playwright install chromium
# 同上设置 PERO_TEST_DATABASE_URL 与 PERO_TEST_REDIS_URL 后运行
PERO_BROWSER_TEST=1 cargo test -p user-center --locked --test logout -- --ignored
```

## License

MIT OR Apache-2.0
