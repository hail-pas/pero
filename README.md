# Pero

Rust 身份认证中心，基于 Axum / SeaORM / Redis，提供 OAuth2 / OpenID Connect 服务。

## 服务

- **user-center** — 核心认证服务（OAuth2 授权、Token 签发、JWKS、用户管理）

## 依赖

- Rust 1.100+ (edition 2024)
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

# 3. 首次初始化（自动执行迁移）
make bootstrap

# 4. 构建前端（Rust 服务直接读取 frontend/dist）
npm install --global pnpm@11.25.0 # 或使用 corepack
bash scripts/build-frontend.sh

# 5. 启动
(cd services/user-center && cargo run --bin user-center -- --config-dir config)
```

UI 源码与公共资源位于 `frontend/`。本地配置示例让 Rust 服务直接读取 `../../frontend/dist`（相对于服务工作目录），`make dev` 自动设置绝对路径。Docker 镜像将构建产物放在 `/opt/pero/prd/ui/static`。

## 初始化与配置

已有本地数据库、Redis、密钥及 `services/user-center/config/local.toml` 配置并完成迁移和 bootstrap 后，可在仓库根目录执行 `make dev`。命令构建前端并启动 user-center，默认通过 `http://127.0.0.1:8080` 查看，按 Ctrl+C 停止；数据库和 Redis 使用本地配置中的地址。此命令只监听本机回环地址，不重复初始化数据。

本机通过 `scripts/build-docker-image.sh` 构建并导出 Linux amd64 镜像。服务器加载镜像后，在 `/root/projects/pero/runtime` 运行 Docker Compose。首次部署、更新与回退见 [Linux Docker 部署指南](deploy/pero/README.md)。

本地开发、发布和 CI 的脚本清单见 [脚本说明](scripts/README.md)。

数据库以 `001_init.sql` 为空库初始化基线。服务启动、bootstrap 和独立迁移工具共用迁移器。服务在监听端口前核对迁移历史与校验和，执行待应用迁移并完成结构验收。已部署数据库需要历史和校验和均匹配才能原位升级。旧基线处理、迁移失败和回退步骤见 [数据库迁移与失败恢复](docs/database-migrations.md)。

配置 `notification.smtp`、`notification.sms`（Twilio）或 HTTPS 网关后，服务将通知加密入库，由后台任务投递。数据库连接使用的 `app.encrypt_key` 必须保持一致。渠道配置、失败处理和重试规则见 [应用接入与运维](docs/application-portal-and-delivery.md)。

OAuth 客户端密钥统一使用 Argon2id 哈希。已有 bcrypt 客户端密钥需重新设置或重置。

密码恢复向账号的已验证邮箱或手机号发送设置/重置本地密码链接，仅使用第三方登录且尚无本地密码的账号也可以通过已验证联系方式设置第一个本地密码；新注册邮箱在创建账户前完成验证；既有账户的未验证联系方式需在个人中心完成验证后，才能用于找回密码。重置密码会取消待处理的联系方式变更及其通知，并撤销所有登录会话。仅使用第三方登录的账号也可先登录，再在 `/account/change-password` 设置本地密码；找回密码页面始终使用统一提示，不暴露账号是否具备恢复资格。恢复请求同时按来源 IP（每小时 20 次）和目标联系方式（每小时 3 次）限流，Redis 不可用时返回 503。纯第三方账号遇到相同邮箱的关联流程时，页面会引导使用原登录方式设置本地密码，再重新发起关联。

前端位于 `frontend/`，使用 React + TypeScript + Vite、[Minimal Free](https://github.com/minimal-ui-kit/material-kit-react) MIT 主题和 MUI。首页、个人中心、Dash 管理、认证/授权/退出均由同一个前端实现。Minimal 许可保留于 `frontend/LICENSE.minimal.md`。首页、认证页和工作空间顶部提供中英文切换，默认跟随浏览器，选择后会记住语言；切换时保留当前页面与未提交表单。

开发时先启动 Rust 服务，再执行 `cd frontend && pnpm dev`，访问 `http://127.0.0.1:3039`；默认代理到 `http://127.0.0.1:8080`，可通过 `PERO_API_ORIGIN` 指定后端。生产构建使用 `bash scripts/build-frontend.sh`；Docker 自动构建前端并复制产物。`[frontend].static_dir` 指向构建产物，默认 `ui/static`，资源前缀固定为 `/static`。配置按 `default.toml` → 运行环境配置（`local.toml` 或 `production.toml`）→ `PERO__` 环境变量顺序覆盖；公开默认文件包含通用参数，环境配置只填写必要的地址、凭据和覆盖项，`bootstrap.toml` 仅用于首次初始化。日志格式使用 `[log].format`。

管理列表保留服务端创建时间顺序与分页，不提供仅排序当前页的名称排序。

首页、个人中心和后台共用 `can_access_dashboard` 导航字段。超级管理员和普通管理员均需完成 MFA 才能访问后台。后台根据当前授权决定可见菜单、可读数据和可执行操作。

页面 URL 对 `Accept: application/json` 返回 `{ view, data }`；浏览器导航返回 Vite 应用。写操作沿用服务端表单接口与 CSRF 校验，布尔值统一为 `true/false`，页面 DTO 时间统一为 RFC3339、枚举使用协议字符串；JSON 请求中的跳转以 `{ redirect }` 返回，由前端执行，避免 OAuth 跨域 fetch。Rust 保留认证、授权、业务校验和数据库操作，已移除 Askama 及旧页面资源。

授权确认页携带绑定用户、SSO 会话和授权请求的签名令牌，各标签页提交各自展示的请求。签发授权码时在事务内锁定并重新校验会话。已使用且仍在有效期内的授权码，在客户端、回调地址、PKCE 和当前租户准入校验通过后被重放时，会撤销对应的 RP 会话。轮换后的 Refresh Token 在有效期内被重放时也会撤销对应的 RP 会话。

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
  cargo test -p user-center --locked -- --ignored --test-threads=1
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

依赖审计保留完整报告；已核实的误报按公告、包名和确切版本记录于 `.github/security/advisory-policy.json`，检查时仍输出记录。当前仅跟踪 `block-buffer 0.10.4` 的 `GHSA-qwgh-2vcv-g2f7` 误报：维护者确认受影响范围为 `>=0.11.0,<0.12.1`，聚合数据库范围过宽。未评估告警、撤包或接受期到期均令 CI 失败，不使用全局 ignore；OSV 返回未完成的分页结果也会令检查失败。前端主题源码保留 Minimal MIT 许可，构建锁定依赖版本。

`sso.session_touch_interval_seconds` 在默认配置文件中设为 `10` 秒，减少高频请求刷新会话空闲时间产生的数据库写入。空闲到期时间最多提前该间隔，每次请求仍查询数据库撤销状态。该值不能超过 `30` 秒或空闲超时的 `1%`。将 `sso.session_idle_ttl_seconds` 设为低于 `1000` 秒时，需同时调低刷新间隔。设为 `0` 可按每次请求刷新。

清理任务每个清理条件每轮最多 20 批、每批 500 条，积压会在后续轮次继续处理。已解绑的第三方身份在 `retention.login_event_days` 保留期届满且不再被登录记录或 SSO 会话引用后清理；该配置为 `0` 时不自动删除解绑身份。

刷新令牌支持可选 `scope` 子集；未传时保持原授权范围，扩大范围返回 `invalid_scope`，不会消耗令牌。新的刷新令牌保留原授权范围，降权仅作用于此次 access token。`prompt=select_account` 提供当前账号与切换登录选择。数据库/Redis 临时故障不会当作用户凭证失效；在线校验返回 503 时 admin 保留登录 Cookie。

Docker 镜像内的独立迁移入口为 `/opt/pero/prd/migrate.sh`。它通过 `DATABASE_URL` 连接目标数据库，执行随镜像编译的迁移和验收规则。

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

处理 Refresh Token 重放时，如果 RP 会话撤销或事务提交失败，接口返回 `temporarily_unavailable`（HTTP 503）。调用方可在依赖恢复后重新提交原请求。

## License

MIT OR Apache-2.0

## 账户安全与操作审计

个人中心新增 `/account/sessions`、`/account/activity`、`/account/authorizations`、`/account/identities`。会话列表只展示当前用户的有效会话，可退出指定、其他或全部设备，并同步撤销关联刷新令牌。新登录会记录有长度限制的 User-Agent，历史记录缺失的设备信息显示为未知。

用户在个人中心撤销应用授权时，会移除该应用所有客户端的授权同意，撤销相关刷新令牌和未使用的授权码，并推进用户的应用令牌版本。应用访问资格与其他应用的授权继续有效。撤销后使用旧令牌会返回 `invalid_grant`。

关联账号通过带 CSRF 的 POST 发起，第三方登录 state 绑定当前用户与当前会话；回调必须保留同一会话，不根据相同邮箱自动合并。解绑只针对自己的第三方身份，禁止移除最后一种可用登录方式，并撤销使用该身份建立的会话。原有登录时账号冲突关联流程继续保留。

管理控制台新增 `/dashboard/events` 和 `/dashboard/audit`，支持分页及事件类型/结果筛选；用户详情可直接查看该用户登录记录。所有通过后台门禁的 POST 在执行业务前持久化 pending 审计，响应后记录成功/失败和 HTTP 状态。初始审计写入失败时返回 503 并阻止执行；结果写入失败时保留 pending 记录并记录错误，继续返回原业务响应，避免丢失已生成的一次性密钥。审计仅存操作者、操作路由、目标路径、来源与请求编号，不存表单、响应正文、密码或密钥，也不提供修改/删除接口。


## MFA、再认证与管理员角色

角色和 MFA 结构已包含在初始迁移中。bootstrap 创建超级管理员；此后系统应用访问资格不再自动授予管理员身份。

`/account/security` 提供 TOTP 设置、二维码/手动密钥、一次性恢复码生成及停用；`/sso/mfa` 完成登录验证。TOTP 六位、30 秒、允许相邻时间步，同一成功时间步不可重放。恢复码每个含 128 位随机性，数据库只存 SHA-256 哈希，使用后立即作废。管理后台仅允许管理员访问，并始终要求设置和验证 MFA。普通应用默认不要求 MFA；用户可在个人中心“我的应用”为自己逐个开启或关闭 MFA，不影响其他用户。即使账号是管理员或已设置验证器，登录未开启此开关的普通应用也无需 MFA；开启后在授权、令牌刷新及 UserInfo 中均校验 MFA。更改个人应用 MFA 设置需要近期认证，并撤销本人在该应用已有的授权。开启前需先设置验证器。恢复中的会话仍不能访问任何应用。

丢失验证器时，先使用原登录方式验证主身份，再输入恢复码。恢复会撤销其他会话，并限制当前会话只能重新设置验证器；设置新验证器使用独立草稿，确认前保留原认证器及未使用的恢复码；页面中断后可用剩余恢复码重新开始，设置完成才替换全部恢复码。不提供管理员直接清除 MFA 的接口，密码重置不会清除 MFA。验证器与恢复码均丢失时，可由另一位超级管理员在用户安全页面核验身份后签发短时恢复码，仍需主身份验证和重新绑定验证器。

敏感账户变更与所有管理写操作需要 15 分钟内的近期认证。`/account/reauth` 支持本地密码或已绑定 OIDC 身份的强制再认证。账号已启用 MFA 时，还需验证 TOTP。仅使用普通 OAuth2 或微信登录的账号，可在仍有近期认证时设置本地密码或绑定 OIDC。再认证后回到原页面重新提交操作。

`/dashboard/admins` 由超级管理员管理后台角色和普通管理员权限。普通管理员默认没有业务操作权限，授权可以覆盖全局模块或指定的非系统应用。

| 授权范围 | 可分配能力 |
| --- | --- |
| 全局 | 普通用户查询、邀请、资料及联系方式管理、启停和密码重置，身份提供方摘要，全局登录记录、操作审计，以及普通通知的查询和重试。完整联系方式需要独立权限。 |
| 指定应用 | 应用查询与管理、OAuth 客户端查询与管理、客户端密钥轮换，以及应用成员查询与访问资格管理。每项授权绑定具体应用，且各应用独立满足权限依赖。 |

管理员身份及授权分配、新建应用、系统应用管理、注册策略及审批、租户平台管理、身份提供方和签名密钥管理、账户同步配置、接入诊断和管理员会话处置由超级管理员负责。普通管理员只能通过后台管理普通用户，应用成员权限仅覆盖该应用的访问资格。服务端校验功能权限、资源范围和可操作字段。

角色或权限变更会撤销目标管理员的登录状态。权限保存校验授权版本，拒绝覆盖他人已保存的变更，并在同一事务记录授权差异。系统保护最后一个有效超级管理员，禁止移除、降级或停用。

角色变更、MFA 设置、恢复及再认证成功会写入操作审计。MFA 通知通过可用渠道发送到已验证联系方式，消息类型为 `mfa_enabled`、`mfa_changed` 和 `mfa_recovery`。

## 通知投递运维

后台 `/dashboard/notifications` 提供状态筛选、分页、脱敏收件人、尝试次数、最近失败类别及 HTTP 状态。普通通知的查看和重试分别需要 `notifications.read` 和 `notifications.retry`。账户同步与应用注销的投递记录和重试仅对超级管理员开放。重试需要通过 CSRF 校验和 15 分钟内的近期认证，并写入管理审计。

通知可通过 SMTP、Twilio 短信或 HTTPS 网关投递，复用数据库队列。队列和脱敏记录原子写入，投递成功后删除含凭据的加密载荷，只保留结果元数据。投递状态包括待投递、重试中、网关已接收、过期和取消；“网关已接收”仅表示网关返回 2xx，不代表邮件/短信最终送达。

“立即重试”仅将尚未过期、至少尝试过一次、正在等待重试且没有有效投递租约的原消息提前排队，后台下一轮执行；不生成新验证码、不延长有效期，始终使用原通知 ID 作为 `Idempotency-Key`。网关必须按此键去重。已成功、取消或过期的消息不能重试；联系方式修改、密码恢复等原有撤销流程会同步标记取消。网关已经接收的在途请求无法撤回。

失败记录保存受控错误类别，例如 `http_error`、`transport_error` 或 `timeout`。自动重试按 30 秒递增，间隔最多 300 秒，通知到期后停止。终态元数据保留 30 天后分批删除。

页面显示待投递总数、超过调度时间 5 分钟的积压及多次失败数量。通知后台任务每 60 秒独立检查一次，发现积压或至少 3 次失败时输出 `Notification backlog requires attention` 警告，可接入现有日志告警；检查不受清理周期、慢网关请求或网关是否配置影响。排查时先确认网关配置、连接和认证，再依据 HTTP 状态检查网关；修复后可提前调度有效通知。网关测试可通过测试账号发起联系方式验证，再在此页面检查结果。

## 注册、邀请与应用准入

平台默认仅限邀请注册。超级管理员在「注册策略与邀请」配置注册模式、邮箱域名和平台开户审批。普通应用可以继承平台策略或配置覆盖规则。应用处于自助注册模式时，由生效的审批开关决定已有账号申请访问后立即开通还是进入待审队列。紧急停止暂停注册、邀请接受和普通应用新资格开通，已有访问仍受应用启停和撤权控制。

普通应用可在「我的应用」或交互式 OAuth 权限恢复页申请访问。系统按账号和应用判断，立即开通或进入后台待审。批准时直接生效，进度在站内查看。指定应用的开户邀请会在开户时授予目标应用，已有账号由管理员在应用成员页直接授予。关闭自助后仍可由管理员授予资格。系统应用由超管显式授予 OAuth 资格，后台依管理员角色和 MFA 授权。

开户邀请有效期 72 小时，自助注册办理凭据有效期 24 小时。应用访问按账号和应用保存一条当前申请，可在待审期间撤回，审核或资格条件失效后结案，历史操作保存在审计记录。密码注册和第三方首次注册沿用联系方式验证；平台注册完成后可以登录，但不会自动分配业务应用。

`/account/applications` 提供申请、退出应用及注销账户。退出应用撤销该应用资格、授权同意和令牌。注销需在 15 分钟内完成近期认证并输入用户名确认，随后清除个人资料和认证凭据，撤销全部会话。管理员须先移除管理员身份。注销后的业务数据由接入应用按自身规则处理。

注册申请与组织邀请到期 30 天后分批清理。`retention.login_event_days` 与 `retention.audit_event_days` 分别控制登录与管理员审计记录保留期，默认 90 天和 365 天，设为 `0` 时停用相应清理。租户和成员对账历史单独保留。

应用可在 OIDC 授权请求中使用 `prompt=create` 进入注册；需配置客户端 `login_uri`，以便跨设备或超时后重新发起授权。组织邀请支持新用户注册及既有用户独立登录后加入；应用发出的邀请自动关联来源客户端。应用登录入口处理 `enrollment_status=cancelled` 和 `enrollment_status=expired`，由用户选择重新发起。

注册、邀请、进度恢复和 OAuth 回跳见 [注册与邀请接入](docs/registration-invitation-design.md)。

## 审批、申请进度与应用成员

`/dashboard/registration` 的申请工作台支持分页、邮箱/应用名称搜索和状态筛选，默认优先显示待审批项；平台入口默认汇总全部应用，应用入口默认限定本应用，可用 `all_apps=true/false` 切换查询范围，待审批计数遵循当前应用及搜索范围。应用详情保留独立准入策略入口。拒绝时可填写原因，工作台支持批准、拒绝、重发及撤销。

`/account/applications` 的“我的申请与邀请”显示由当前账户发起、已归属于当前账户，或匹配该账户已验证联系方式的申请。有效的申请可继续办理、重发或撤回。已经开始办理的浏览器可以在链接轮换后继续查看进度，实际操作仍需当前办理凭据及相应的账号验证。

`/dashboard/apps/{id}/members` 支持按用户名、昵称和访问状态分页查询。具备应用成员管理权限的管理员也可查看应用待审队列、批准或拒绝申请，并显式授予、撤销或恢复资格。普通管理员需具备目标应用的成员查询或管理权限，且操作对象限普通用户。撤销资格会使该用户在目标应用的既有授权凭据失效。恢复资格由有权管理员显式操作。

## 业务应用在线校验与令牌撤销

`POST /api/oauth2/introspect` 和 `POST /api/oauth2/revoke` 通过 Discovery 公布。请求使用表单字段 `token`，可选 `token_type_hint`。Confidential 客户端可通过 `client_secret_basic` 或 `client_secret_post` 认证。Introspection 允许 confidential 客户端查询本客户端的 Access Token 和 Refresh Token，以及同一应用中 public 客户端的 Access Token。响应中的 `client_id` 和 `aud` 对应令牌原始客户端。令牌无效、越权或已撤销时返回 `{"active":false}`，依赖不可用时返回 HTTP 503。状态响应禁止缓存，在线校验与令牌签发使用独立的来源配额。

Revocation 接受本客户端的 Access Token 或 Refresh Token，撤销令牌对应的 RP 会话、关联刷新令牌，以及同一客户端、SSO 会话和租户下的待用授权码。应用访问资格、SSO 会话和其他 RP 会话继续有效。未知、已撤销或属于其他客户端的令牌通常统一返回 HTTP 200。仍处于有效会话中的轮换旧令牌也可用于发起主动撤销。

有效 Access Token 的 introspection 响应返回两个布尔值。`is_superadmin` 表示用户当前持有 `super_admin` 平台角色，`mfa_verified` 表示当前 SSO 会话已完成 MFA。业务端可根据 `is_superadmin` 映射本系统角色，撤销中心角色后下一次在线校验即生效。此前只检查 `is_superadmin` 来授权超级管理员操作的业务端，需要同时检查 `mfa_verified`，以保留原有的 MFA 门禁。用户资料声明复用 scope 策略，`profile` 才返回 `preferred_username`、`name`、`picture`。旧令牌没有 `profile` 时需重新授权才能取得用户名和头像。

业务应用应在每次受保护请求时调用 introspection，检查 `active`、`sub`、`aud` / `client_id` 与本地会话绑定是否一致；`active=false` 时清除本地登录态，503 时返回暂不可用并保留 Cookie。长连接应用应在敏感操作或定期续期时再次校验。中心撤销不主动清理其他域名的 Cookie。仅在登录时离线验签无法获得即时撤销效果。

协议依据：[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)、[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)。

## 日志检索、审计详情与凭据轮换

登录记录新增用户名、IP、身份源及 RFC3339 时间范围筛选；用户端查询始终限定当前用户。审计新增操作者、操作路由、目标、请求编号、IP、时间范围检索；`/dashboard/audit/{id}` 展示完整元数据及允许记录的配置字段差异。应用、客户端、用户和审批状态的前后快照只选择明确允许的字段，不采集请求正文、密码、密钥哈希、令牌或联系方式。

客户端详情提供“平滑轮换密钥”：新密钥仅在成功响应中显示一次，原密钥在所选的 1 小时、24 小时或 7 天窗口内继续可用；使用新密钥完成部署后可“停用旧密钥”。每个客户端最多保留一把旧密钥，重叠期结束或提前停用后才能再次轮换。轮换和停用旧密钥不撤销用户授权；“紧急重置密钥”及编辑密钥仍立即替换凭据并使既有授权失效。过期旧密钥不再参与认证，由现有后台清理任务分批删除哈希。

## 账号选择与安全提醒

`prompt=select_account` 进入账号选择页，可继续使用当前账号或重新登录其他账号，保留原 OAuth state、nonce、PKCE、scope 和回调。选择操作绑定授权请求和当时的会话，并要求 CSRF；不会把授权请求 ID 当成登录凭据。个人菜单也提供“切换账号”。切换时撤销当前浏览器的 SSO 会话及关联刷新令牌，不影响其他设备。

安全通知包括 `password_changed`、`password_reset_completed`、`admin_password_reset`、`contact_changed`、`identity_linked` 和 `identity_unlinked`。使用 HTTPS 网关时，网关需识别这些消息类型。登录成功写入登录审计。联系方式变更通知发送到原已验证渠道及本次验证的新渠道，管理员修改联系方式时只通知原已验证渠道。通知与对应变更在同一事务内入队。

上述结构均包含在初始迁移，服务启动自动核对并验收。


## 账户恢复、管理员会话处置与接入诊断

辅助恢复与诊断请求结构均包含在初始迁移。`/account/security` 展示再认证方式、已验证恢复联系方式和剩余恢复码检查。仅有 OAuth2/微信身份而无法完成再认证时，可直接通过 `/sso/forgot-password` 使用已验证邮箱或手机号设置本地密码并重新登录。未验证联系方式不能用于恢复；恢复接口保持统一提示和原有限流，密码设置/重置不会清除 MFA，且撤销全部会话和待处理联系方式变更。

超级管理员从用户详情进入 `/dashboard/users/{id}/security`，查看有效会话、设备/IP、时间及 MFA 待完成状态，可撤销指定或全部会话、解除密码失败引起的临时锁定。所有处置要求 CSRF、15 分钟内近期认证、必填原因（最多 500 字）并记录审计。解除锁定仅清除该用户密码失败计数，不改变账号启停状态、不清除来源 IP 或账号请求频率配额。会话撤销同步撤销关联刷新令牌；通知新增 `sessions_revoked` 消息 kind。

验证器和恢复码均丢失时，管理员应先通过独立渠道核验本人身份，填写工单号/原因，再在同一页面点击“生成临时恢复码并退出全部会话”。恢复码含 128 位随机性，只在成功响应中显示一次、数据库只存哈希、15 分钟内单次有效；重新签发会替换旧临时码、使原恢复码失效并撤销全部登录状态。不要将恢复码写入原因、工单、日志或群聊，核验后私下交付本人。用户先以原登录方式或找回密码验证主身份，再在 MFA 页使用临时恢复码进入受限会话，重新绑定验证器后才恢复访问。不会直接关闭 MFA，也不支持管理员恢复自己；应保留至少两位能独立登录的超级管理员，以便管理员账号互助恢复。全部管理员都无法登录时，此页面流程不能自行解除锁定。恢复沿用 `mfa_recovery` 安全通知，不包含恢复码。

应用详情中的 `/dashboard/apps/{id}/integration` 提供服务端 Web（confidential）与浏览器 SPA（public）的配置向导，复用已有客户端创建与一次性密钥展示；两种模板均要求授权码与 S256 PKCE。页面提供 Discovery/接入配置、应用/客户端状态、签名密钥、scope、grant、回调格式及测试账号成员资格检查。Token、introspection、revoke 均支持 `client_secret_basic` 与 `client_secret_post`；不得同时提交 Basic 和表单密钥，public 客户端不发送密钥，introspection 仍仅允许 confidential 客户端。

运行真实授权诊断前，将页面给出的 `/oauth2/diagnostic/callback` 额外登记到所选客户端的回调列表，并授予当前测试账号应用访问资格。开始测试会生成绑定账号、当前会话和客户端的 state、nonce、PKCE；同意授权后，回调移除地址栏中的授权码，诊断状态在 Redis 保留 10 分钟。confidential 客户端需在页面输入密钥完成兑换，密钥不保存；public 客户端无需密钥。服务端验证 ID Token 签名、issuer/audience、nonce、sid、token/code hash 和访问令牌在线状态，只返回检查结果，不返回令牌，立即撤销本次测试刷新令牌；其他应用授权不受影响。诊断成功并不证明业务应用的实际回调、Cookie、退出及在线撤销处理正确，仍需接入方验收。诊断完成后可移除额外回调地址。


诊断请求由服务端内部入口创建，在数据库授权请求中记录不可由公开接口设置的 `diagnostic_session_id`，并绑定初始会话；公开 OAuth `state` 始终作为客户端不透明值原样处理，不保留内部前缀，也不通过 Redis 判断请求类型。批准或取消诊断均不修改已有业务 consent。票据过期、已使用或会话变化时显示可重新开始的页面；回调会话失效则回应用列表重新发起，不把旧诊断绑定转移到新会话。

解除登录锁定采用先提交审计意图、再操作 Redis、最后记录结果的流程。意图写入失败时不解锁；Redis 失败或超时保留 pending（可能需要人工确认实际状态）；解锁已确认成功但结果写入失败时返回成功并保留带原因的 pending 记录，避免将数据库回滚误当作 Redis 回滚。重试解除锁定是幂等操作。

应用设备会话上限、签名密钥轮换和 Back-channel Logout 见 [应用接入与运维](docs/application-portal-and-delivery.md)。


## 应用侧账户生命周期同步

超级管理员为 confidential 客户端开启查询授权后，应用后端可凭客户端凭据调用 `POST /api/accounts/sync` 查询本应用成员的当前状态，资料字段按客户端 scope 过滤。可选的账户同步 HTTPS 回调用于推送用户资料、账户状态、成员资格及账户注销的签名事件。启用或更换地址会同步现有成员，投递失败自动重试，后台通知页可查看和重试。详见[账户生命周期同步与接收端示例](docs/account-lifecycle-sync.md)。


## 多租户

- 用户创建组织资格与现有组织成员治理独立；组织可设置独立成员上限（默认 100，平台配置），支持显式停用、恢复及解散墓碑。
- 平台超级管理员可以在 `/dashboard/tenants` 搜索组织、维护成员额度、提升现有成员为 Owner、管理租户应用准入。
- 应用支持 `organization_access=open|restricted`，并在组织详情维护显式准入关系；业务 ACL 仍在应用侧。
- 应用可经 `tenant.manage` OAuth scope 调用受用户授权的租户管理 JSON API，也可用 confidential 客户端凭据分页查询本应用的账户、租户和成员关系。
- 接入契约及具体 API 见 [租户接入说明](docs/tenant-integration.md)。


## 可运行的租户业务应用接入模板

查看 [examples/tenant-app](examples/tenant-app/README.md)，包含 OIDC BFF 登录、租户切换、Token 在线撤销、SSO 退出、账户及成员同步和全量对账。
