# Pero

Rust 身份认证中心，基于 Axum / SeaORM / Redis，提供 OAuth2 / OpenID Connect 服务。

## 服务

- **user-center** — 核心认证服务（OAuth2 授权、Token 签发、JWKS、用户管理）
- **admin** — OAuth2 登录示例和受保护首页；用户与应用管理位于 user-center `/dashboard`

## 依赖

- Rust 1.95+ (edition 2024)
- PostgreSQL 18+（schema 使用 `uuidv7()`）
- Redis
- Node.js 24.11+ / pnpm 11.25（构建 React 前端）；部署初始化需 Python 3

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

# 4. 构建前端（同时复制到两个 Rust 服务的静态资源目录）
npm install --global pnpm@11.25.0 # 或使用 corepack
bash scripts/build-frontend.sh

# 5. 启动
(cd services/user-center && cargo run --bin user-center -- --config-dir config)
# 先注册对应 OAuth client，再配置 admin 的 local.toml
cp services/admin/config/local.toml.example services/admin/config/local.toml
(cd services/admin && cargo run --bin admin -- --config-dir config)
```

## 初始化与配置

Linux Docker 部署见 [deploy/pero/README.md](deploy/pero/README.md)。本机通过 `scripts/build-docker-image.sh` 构建 Linux amd64 镜像并导出，服务器加载后在 `/root/projects/pero/runtime` 启动，无需服务器编译或本机 Rust/Zig。现有 `/root/projects/pero/source` 可保留；`scripts/package-production-config.sh` 仅在需要迁移配置时使用，私有包不提交 Git。

项目以首次部署为基线，仅提供 `001_init.sql`，适用于空数据库。`scripts/migrate.sh` 在事务内初始化并记录 checksum，重复执行会校验并跳过已应用的 SQL。标准 `scripts/deploy.sh` 部署包包含配置默认值、示例、初始化 SQL 和迁移脚本；不包含真实配置或私钥。目标环境需独立提供密钥。

配置 `notification.endpoint` 和 `notification.bearer_token` 后，服务将通知加密入库并由后台任务投递；数据库连接使用的 `app.encrypt_key` 必须保持一致。没有配置通知网关时，联系方式验证和密码恢复不会报告已发送。

OAuth 客户端密钥统一使用 Argon2id 哈希。已有 bcrypt 客户端密钥需重新设置或重置。

密码恢复仅向已有本地密码的账号的已验证邮箱或手机号发送重置链接；注册填写的联系方式需先登录并完成验证，才能用于找回密码。重置密码会取消待处理的联系方式变更及其通知，并撤销所有登录会话。仅使用第三方登录的账号可先登录，再在 `/account/change-password` 设置本地密码；找回密码页面始终使用统一提示，不暴露账号是否具备恢复资格。恢复请求同时按来源 IP（每小时 20 次）和目标联系方式（每小时 3 次）限流，Redis 不可用时返回 503。纯第三方账号遇到相同邮箱的关联流程时，页面会引导使用原登录方式设置本地密码，再重新发起关联。

前端位于 `frontend/`，使用 React + TypeScript + Vite、[Minimal Free](https://github.com/minimal-ui-kit/material-kit-react) MIT 主题和 MUI。首页、个人中心、Dash 管理、认证/授权/退出及 admin 示例均由同一个前端实现。Minimal 许可保留于 `frontend/LICENSE.minimal.md`。首页、认证页和工作空间顶部提供中英文切换，默认跟随浏览器，选择后会记住语言；切换时保留当前页面与未提交表单。

开发时先启动 Rust 服务，再执行 `cd frontend && pnpm dev`，访问 `http://127.0.0.1:3039`；默认代理到 `http://127.0.0.1:8080`，可通过 `PERO_API_ORIGIN` 指定后端。生产构建使用 `bash scripts/build-frontend.sh`；Docker 自动构建前端并复制产物。配置节由 `[askama]` 改为 `[frontend]`，删除旧的页面字典 `[i18n]` 配置节；`static_dir` 指向构建产物，默认 `ui/static`，资源前缀固定为 `/static`，不再提供 `static_url_prefix` 配置项。日志格式统一使用 `[log].format`，移除旧的 `log.json` 开关和未使用的 `server.docs_servers` 配置。

管理列表保留服务端创建时间顺序与分页，不提供仅排序当前页的名称排序。

页面 URL 对 `Accept: application/json` 返回 `{ view, data }`；浏览器导航返回 Vite 应用。写操作沿用服务端表单接口与 CSRF 校验，布尔值统一为 `true/false`，页面 DTO 时间统一为 RFC3339、枚举使用协议字符串；JSON 请求中的跳转以 `{ redirect }` 返回，由前端执行，避免 OAuth 跨域 fetch。Rust 保留认证、授权、业务校验和数据库操作，已移除 Askama 及旧页面资源。

授权确认页携带绑定用户、SSO 会话和授权请求的签名 token；多标签页分别提交各自展示的请求，互不覆盖。授权码重放只有在客户端、回调地址和 PKCE 校验通过后才触发撤销，撤销范围与刷新令牌重放一致：对应 SSO 会话及该会话下所有客户端的刷新令牌，在线 UserInfo 随即拒绝该会话的访问令牌。

Access Token 必须携带客户端策略版本和用户应用授权版本。客户端安全配置变更、重置密钥或切换状态，以及撤销应用权限或停用应用，会在事务内推进相应版本；UserInfo 拒绝旧版本令牌，恢复权限或重新启用也不会让旧令牌恢复有效。签发授权码令牌和刷新令牌时均绑定当前版本，不影响其他客户端的策略版本或整个 SSO 会话。初始化 schema 的 `oauth_clients` 和 `user_app_access` 均新增 `token_version` 字段，继续采用空库初始化基线，不提供旧 schema/旧令牌兼容。

浏览器首次打开纯页面路由时直接返回前端入口，React 再获取 JSON 数据；认证、管理权限和业务校验在数据请求中执行。OAuth 授权、第三方回调和协议注销继续执行服务端流程。匿名 OAuth 授权和第三方登录入口共用按来源 IP 计数的限流，每分钟最多 60 次，超限返回 429，Redis 不可用时返回 503。

`view` 使用显式协议名称，不依赖 Rust 结构体名称。管理接口的数据库或凭据处理依赖不可用时返回 HTTP 503，不展示为空列表或报告保存成功。OAuth Client ID 创建后不可修改。Provider 已配置的 issuer、client_id，以及 OAuth2/微信的 userinfo_endpoint 不可更换，切换身份源需新建 Provider；未填写的草稿字段仍可补齐。本地密钥管理仅支持 RS256 签名密钥。Token 有效期由各 OAuth 客户端配置，移除未生效的 oauth2.default_access_token_ttl_seconds、default_refresh_token_ttl_days、default_id_token_ttl_seconds 全局配置。账户登录页的第三方登录会将站内返回地址保存在服务端登录状态中，在回调及账号关联完成后恢复。

## 验证

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
pnpm --dir frontend test
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
python3 scripts/check-osv.py # Python 3.11+
pnpm --dir frontend audit
```

依赖审计保留完整报告；当前没有接受中的告警，见 `.github/security/advisory-policy.json`。未评估告警、撤包或接受期到期均令 CI 失败，不使用全局 ignore。前端主题源码保留 Minimal MIT 许可，构建锁定依赖版本。

`sso.session_touch_interval_seconds` 默认 `0`，保持每次请求刷新 idle 时间；可显式设置不超过 `30` 秒且不超过 idle TTL 的 `1%`，减少高频请求的数据库写入。代价是空闲到期时间最多提前该间隔，每次请求仍查询数据库撤销状态。清理任务每轮每类最多 20 批、每批 500 条，积压会在后续轮次继续处理。

刷新令牌支持可选 `scope` 子集；未传时保持原授权范围，扩大范围返回 `invalid_scope`，不会消耗令牌。新的刷新令牌保留原授权范围，降权仅作用于此次 access token。尚无账户选择界面，`prompt=select_account` 明确返回 `invalid_request`。数据库/Redis 临时故障不会当作用户凭证失效；UserInfo 返回 503 时 admin 保留登录 Cookie。

部署包可直接执行 `DATABASE_URL=... bash ./migrate.sh`，也可通过参数或 `MIGRATIONS_DIR` 指定目录。checksum 不一致会报错回滚。

## 注销与上游密钥缓存

注销支持 GET query 和标准表单 POST。hint 无法关联当前用户及会话时，通过带 CSRF 保护的页面确认。过期 hint 仅用于注销，普通认证令牌仍严格校验有效期。Access Token 使用 `typ=at+jwt`，ID Token 使用 `typ=JWT`。OAuth scope 按大小写精确匹配，手机号登录与找回密码使用数据库中存储的完整号码。

浏览器表单 POST 需要注销确认时，通过 303 保留协议参数并转入 GET 确认页；没有退出回调地址时，确认完成同样转入 GET 结果页。JSON 请求继续直接返回页面数据或跳转目标。

`oauth2.upstream_jwks_cache_ttl_seconds` 默认 `0`，保持每次上游登录重新获取 JWKS；可显式设置为 `1–300` 秒以减少网络请求。启用后，已缓存 key 的撤销最多延迟该 TTL；过期缓存刷新失败不会继续接受旧 key。Provider 配置变更隔离缓存，未知 kid 刷新有 5 秒冷却。没有改变本地签名 key 的数据库启用状态检查。

浏览器回归使用专用测试库和 Redis，真实 Chromium 覆盖登录、切换用户、取消/确认退出和过期 hint：

```bash
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend exec playwright install chromium
# 同上设置 PERO_TEST_DATABASE_URL 与 PERO_TEST_REDIS_URL 后运行
PERO_BROWSER_TEST=1 cargo test -p user-center --locked --test logout -- --ignored
```

授权入口会在创建请求前检查客户端是否允许 `authorization_code`，不允许时向已验证的回调地址返回 `unauthorized_client`。密码重置的数据库等依赖故障返回 HTTP 503，输入和令牌校验错误保留原有页面提示。

刷新令牌重放的回滚或会话撤销失败返回 `temporarily_unavailable`（HTTP 503）；调用方应在依赖恢复后重试原刷新令牌请求，服务端重试会再次执行会话及其刷新令牌的撤销。返回 503 不代表撤销已完成；依赖故障持续期间不保证撤销已生效。

## License

MIT OR Apache-2.0
