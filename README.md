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

# 4. 构建前端（两个 Rust 服务直接读取 frontend/dist）
npm install --global pnpm@11.25.0 # 或使用 corepack
bash scripts/build-frontend.sh

# 5. 启动
(cd services/user-center && cargo run --bin user-center -- --config-dir config)
# 先注册对应 OAuth client，再配置 admin 的 local.toml
cp services/admin/config/local.toml.example services/admin/config/local.toml
(cd services/admin && cargo run --bin admin -- --config-dir config)
```

UI 源码与公共资源只维护在 `frontend/`，本地配置示例让两个服务直接读取 `../../frontend/dist`（相对于各服务工作目录）；`make dev` 自动设置绝对路径。`services/` 下不保存 UI 文件或软链接。独立部署包仍包含构建产物，并使用部署目录中的 `ui/static`。

## 初始化与配置

已有本地数据库、Redis、密钥及 `services/user-center/config/local.toml` 配置并完成迁移和 bootstrap 后，可在仓库根目录执行 `make dev`。命令构建前端并启动 user-center，默认通过 `http://127.0.0.1:8080` 查看，按 Ctrl+C 停止；数据库和 Redis 使用本地配置中的地址。此命令只监听本机回环地址，不重复初始化数据。

Linux Docker 部署见 [deploy/pero/README.md](deploy/pero/README.md)。本机通过 `scripts/build-docker-image.sh` 构建 Linux amd64 镜像并导出，服务器加载后在 `/root/projects/pero/runtime` 启动，无需服务器编译或本机 Rust/Zig。现有 `/root/projects/pero/source` 可保留；`scripts/package-production-config.sh` 仅在需要迁移配置时使用，私有包不提交 Git。

`001_init.sql` 用于空数据库初始化，后续变更通过增量 SQL 迁移。`scripts/migrate.sh` 按文件顺序在事务内应用迁移并记录 checksum，重复执行会校验并跳过已应用的 SQL。本次新增 `002_audit_events.sql`，已有部署需先运行迁移，再启动新版服务。标准 `scripts/deploy.sh` 部署包包含配置默认值、示例、初始化 SQL 和迁移脚本；不包含真实配置或私钥。目标环境需独立提供密钥。

配置 `notification.endpoint` 和 `notification.bearer_token` 后，服务将通知加密入库并由后台任务投递；数据库连接使用的 `app.encrypt_key` 必须保持一致。没有配置通知网关时，联系方式验证和密码恢复不会报告已发送。

OAuth 客户端密钥统一使用 Argon2id 哈希。已有 bcrypt 客户端密钥需重新设置或重置。

密码恢复仅向已有本地密码的账号的已验证邮箱或手机号发送重置链接；新注册邮箱在创建账户前完成验证；既有账户的未验证联系方式需在个人中心完成验证后，才能用于找回密码。重置密码会取消待处理的联系方式变更及其通知，并撤销所有登录会话。仅使用第三方登录的账号可先登录，再在 `/account/change-password` 设置本地密码；找回密码页面始终使用统一提示，不暴露账号是否具备恢复资格。恢复请求同时按来源 IP（每小时 20 次）和目标联系方式（每小时 3 次）限流，Redis 不可用时返回 503。纯第三方账号遇到相同邮箱的关联流程时，页面会引导使用原登录方式设置本地密码，再重新发起关联。

前端位于 `frontend/`，使用 React + TypeScript + Vite、[Minimal Free](https://github.com/minimal-ui-kit/material-kit-react) MIT 主题和 MUI。首页、个人中心、Dash 管理、认证/授权/退出及 admin 示例均由同一个前端实现。Minimal 许可保留于 `frontend/LICENSE.minimal.md`。首页、认证页和工作空间顶部提供中英文切换，默认跟随浏览器，选择后会记住语言；切换时保留当前页面与未提交表单。

开发时先启动 Rust 服务，再执行 `cd frontend && pnpm dev`，访问 `http://127.0.0.1:3039`；默认代理到 `http://127.0.0.1:8080`，可通过 `PERO_API_ORIGIN` 指定后端。生产构建使用 `bash scripts/build-frontend.sh`；Docker 自动构建前端并复制产物。配置节由 `[askama]` 改为 `[frontend]`，删除旧的页面字典 `[i18n]` 配置节；`static_dir` 指向构建产物，默认 `ui/static`，资源前缀固定为 `/static`，不再提供 `static_url_prefix` 配置项。日志格式统一使用 `[log].format`，移除旧的 `log.json` 开关和未使用的 `server.docs_servers` 配置。

管理列表保留服务端创建时间顺序与分页，不提供仅排序当前页的名称排序。

页面 URL 对 `Accept: application/json` 返回 `{ view, data }`；浏览器导航返回 Vite 应用。写操作沿用服务端表单接口与 CSRF 校验，布尔值统一为 `true/false`，页面 DTO 时间统一为 RFC3339、枚举使用协议字符串；JSON 请求中的跳转以 `{ redirect }` 返回，由前端执行，避免 OAuth 跨域 fetch。Rust 保留认证、授权、业务校验和数据库操作，已移除 Askama 及旧页面资源。

授权确认页携带绑定用户、SSO 会话和授权请求的签名 token；多标签页分别提交各自展示的请求，互不覆盖。签发授权码时在事务内重新校验并锁定有效会话，避免已撤销会话写入授权码或同意记录。授权码重放只有在客户端、回调地址和 PKCE 校验通过后才触发撤销，撤销范围与刷新令牌重放一致：对应 SSO 会话及该会话下所有客户端的刷新令牌，在线 UserInfo 随即拒绝该会话的访问令牌。

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

依赖审计保留完整报告；已核实的误报按公告、包名和确切版本记录于 `.github/security/advisory-policy.json`，检查时仍输出记录。当前仅跟踪 `block-buffer 0.10.4` 的 `GHSA-qwgh-2vcv-g2f7` 误报：维护者确认受影响范围为 `>=0.11.0,<0.12.1`，聚合数据库范围过宽。未评估告警、撤包或接受期到期均令 CI 失败，不使用全局 ignore；OSV 返回未完成的分页结果也会令检查失败。前端主题源码保留 Minimal MIT 许可，构建锁定依赖版本。

`sso.session_touch_interval_seconds` 默认 `0`，保持每次请求刷新 idle 时间；可显式设置不超过 `30` 秒且不超过 idle TTL 的 `1%`，减少高频请求的数据库写入。代价是空闲到期时间最多提前该间隔，每次请求仍查询数据库撤销状态。清理任务每轮每类最多 20 批、每批 500 条，积压会在后续轮次继续处理。

刷新令牌支持可选 `scope` 子集；未传时保持原授权范围，扩大范围返回 `invalid_scope`，不会消耗令牌。新的刷新令牌保留原授权范围，降权仅作用于此次 access token。`prompt=select_account` 提供当前账号与切换登录选择。数据库/Redis 临时故障不会当作用户凭证失效；在线校验返回 503 时 admin 保留登录 Cookie。

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

## 账户安全与操作审计

个人中心新增 `/account/sessions`、`/account/activity`、`/account/authorizations`、`/account/identities`。会话列表只展示当前用户的有效会话，可退出指定、其他或全部设备，并同步撤销关联刷新令牌。新登录会记录有长度限制的 User-Agent，历史记录缺失的设备信息显示为未知。

用户撤销应用授权会移除该应用所有客户端的 consent，撤销关联刷新令牌和未使用授权码，并推进当前用户的应用令牌版本；保留管理员分配的应用访问资格，其他应用不受影响。主动撤销覆盖刷新令牌的轮换历史，此后使用旧令牌只返回 invalid_grant，不触发整个 SSO 会话退出；有效授权中的轮换令牌重放仍会撤销关联会话。重新授权不会恢复旧令牌。离线验签的接入应用仍需自行处理撤销感知。

关联账号通过带 CSRF 的 POST 发起，第三方登录 state 绑定当前用户与当前会话；回调必须保留同一会话，不根据相同邮箱自动合并。解绑只针对自己的第三方身份，禁止移除最后一种可用登录方式，并撤销使用该身份建立的会话。原有登录时账号冲突关联流程继续保留。

管理控制台新增 `/dashboard/events` 和 `/dashboard/audit`，支持分页及事件类型/结果筛选；用户详情可直接查看该用户登录记录。所有通过后台门禁的 POST 在执行业务前持久化 pending 审计，响应后记录成功/失败和 HTTP 状态。初始审计写入失败时返回 503 并阻止执行；结果写入失败时保留 pending 记录并记录错误，继续返回原业务响应，避免丢失已生成的一次性密钥。审计仅存操作者、操作路由、目标路径、来源与请求编号，不存表单、响应正文、密码或密钥，也不提供修改/删除接口。


## MFA、再认证与管理员角色

升级需先执行增量迁移 `003_mfa_admin_roles.sql`。迁移将现有系统应用管理员转换为超级管理员，并撤销升级前的会话和刷新令牌，所有用户需要重新登录。bootstrap 创建超级管理员；此后系统应用访问资格不再自动授予管理员身份。

`/account/security` 提供 TOTP 设置、二维码/手动密钥、一次性恢复码生成及停用；`/sso/mfa` 完成登录验证。TOTP 六位、30 秒、允许相邻时间步，同一成功时间步不可重放。恢复码每个含 128 位随机性，数据库只存 SHA-256 哈希，使用后立即作废。管理员必须启用 MFA，普通用户自愿。管理员首次登录只能先完成设置；待验证和恢复中的会话不能用于 OAuth 授权、刷新及 UserInfo。

丢失验证器时，先使用原登录方式验证主身份，再输入恢复码。恢复会撤销其他会话，并限制当前会话只能重新设置验证器；设置新验证器使用独立草稿，确认前保留原认证器及未使用的恢复码；页面中断后可用剩余恢复码重新开始，设置完成才替换全部恢复码。不提供管理员直接清除 MFA 的接口，密码重置不会清除 MFA。认证器与恢复码都丢失时，当前不支持在线恢复。

敏感账户变更与所有管理写操作需要五分钟内的近期认证。`/account/reauth` 支持本地密码（已启用 MFA 时同时要求 TOTP），或已绑定 OIDC 身份强制再认证后验证 TOTP。普通 OAuth2/微信没有通用的强制再认证语义，不作为再认证证明；此类账号应在仍有近期登录证明时设置本地密码或绑定 OIDC，以便后续安全管理。再认证后回原安全页面重新提交操作，不保存或自动重放密码等表单内容。

`/dashboard/admins` 设置超级管理员、普通管理员或移除管理员。超级管理员拥有所有后台权限；普通管理员的权限体系后续设计，当前默认拒绝后台访问。角色变更撤销目标用户的所有会话；禁止移除、降级或停用最后一个有效超级管理员。角色变更、MFA 设置、恢复及再认证成功写入操作审计。安全通知通过现有通知网关向已验证联系方式投递，消息 kind 为 `mfa_enabled`、`mfa_changed`、`mfa_recovery`，不包含密钥或恢复码。

## 通知投递运维

升级先执行 `004_notification_deliveries.sql`（通过现有 `scripts/migrate.sh`），再启动新版服务。后台 `/dashboard/notifications` 提供状态筛选、分页、脱敏收件人、尝试次数、最近失败类别及 HTTP 状态；沿用超级管理员门禁。重试操作复用 CSRF、五分钟近期认证和管理审计。

通知仍通过现有 HTTPS 网关投递，不增加消息队列或独立服务。队列和脱敏记录原子写入，投递成功后删除含凭据的加密载荷，只保留结果元数据。投递状态包括待投递、重试中、网关已接收、过期和取消；“网关已接收”仅表示网关返回 2xx，不代表邮件/短信最终送达。历史队列迁移时不解密收件信息，显示为 `unknown / ***`；升级前已删除的消息不能追溯。

“立即重试”仅将尚未过期、至少尝试过一次、正在等待重试且没有有效投递租约的原消息提前排队，后台下一轮执行；不生成新验证码、不延长有效期，始终使用原通知 ID 作为 `Idempotency-Key`。网关必须按此键去重。已成功、取消或过期的消息不能重试；联系方式修改、密码恢复等原有撤销流程会同步标记取消。网关已经接收的在途请求无法撤回。

失败记录只保存 `http_error`、`transport_error` 或 `timeout`，不保存网关响应正文、完整地址、验证码或链接。自动重试沿用原有间隔（30 秒递增，最多 300 秒），到期即停止；过期清理由现有清理任务执行，即使网关未配置也会清理。终态元数据保留 30 天后分批删除。

页面显示待投递总数、超过调度时间 5 分钟的积压及多次失败数量。通知后台任务每 60 秒独立检查一次，发现积压或至少 3 次失败时输出 `Notification backlog requires attention` 警告，可接入现有日志告警；检查不受清理周期、慢网关请求或网关是否配置影响。排查时先确认网关配置、连接和认证，再依据 HTTP 状态检查网关；修复后可提前调度有效通知。网关测试可通过测试账号发起联系方式验证，再在此页面检查结果。

## 注册、邀请与应用准入

执行增量迁移 `005_enrollment.sql` 后，平台默认仅限邀请注册。超级管理员在 `/dashboard/registration` 配置平台默认模式（关闭、仅邀请、自助注册）、邮箱域名和审批要求；应用详情中的“注册策略与邀请”可以为该应用独立配置，也可继承平台默认值。全局紧急停止覆盖所有应用，停止注册完成和邀请接受，既有账户仍可登录。

原 `auto_access` 开关已移除。应用准入流程完成后只授予目标应用的访问资格；平台注册不分配应用。密码注册与第三方首次登录统一经过邮箱验证，待审批阶段不创建账户。第三方提供方还须勾选“允许此身份源参与注册”；已有身份登录不受此开关影响。所有来源均在本站验证邮箱，不信任通用 OAuth2 返回的邮箱验证标记。

邀请绑定固定邮箱及可选的单个应用，有效期 72 小时；自助申请有效期 24 小时。管理员可重发、撤销和审批，重发轮换链接而不延长到期时间。既有邮箱的账户必须独立登录后接受邀请；不自动合并账户或恢复已停用的应用资格。后台新建用户改为发送邀请，不再代设初始密码。邮件通过现有加密通知 outbox 投递，需要配置通知网关；`enrollment` 和 `enrollment_rejected` 是新增消息 kind。

`/account/applications` 提供应用加入申请、退出应用及注销账户。退出应用撤销该应用资格、consent 和令牌；注销账户需五分钟内的近期认证、准确输入用户名确认，移除个人资料和认证凭据并撤销全部会话。管理员必须先移除管理员身份。普通退出登录仍使用原流程。历史审计与已完成申请按各自保留期限清理；注销不自动删除业务应用中的数据。

数据模型及流程说明见 [注册与邀请设计](docs/registration-invitation-design.md)。

## 审批、申请进度与应用成员

`/dashboard/registration` 的申请工作台支持分页、邮箱/应用名称搜索和状态筛选，默认优先显示待审批项；平台入口默认汇总全部应用，应用入口默认限定本应用，可用 `all_apps=true/false` 切换查询范围，待审批计数遵循当前应用及搜索范围。应用详情保留独立准入策略入口。拒绝时可填写原因，工作台支持批准、拒绝、重发及撤销。

`/account/applications` 增加“我的申请与邀请”，显示状态、原因和有效期，支持继续办理、重发邮件及撤回。只展示已完成归属于当前用户，或发给当前已验证邮箱的记录；联系方式尚未验证时不展示发给该地址的邀请。继续办理沿用现有注册页及确认流程，通过 HttpOnly Cookie 传递新令牌；列表不返回令牌。尚未创建账户的申请人可从邮件链接查看本次申请进度及拒绝原因；终态链接只读，不能继续接受邀请或创建账户。继续办理和重发都会轮换旧链接，保持原到期时间；重发至少间隔一分钟。

`/dashboard/apps/{id}/members` 支持按用户名/昵称、访问状态分页查询，并按完整用户名授予资格、撤销或恢复成员资格。沿用现有 CSRF、近期认证、超级管理员门禁和审计；撤销会推进用户应用令牌版本并撤销相关授权凭据。系统应用不通过此入口修改成员。

## 业务应用在线校验与令牌撤销

新增 `POST /api/oauth2/introspect` 和 `POST /api/oauth2/revoke`，Discovery 同步公布地址。接口使用表单参数 `token`、`client_id`、`client_secret`，`token_type_hint` 可选；沿用 `client_secret_post` 认证。Introspection 仅允许 confidential 客户端查询自己的令牌，支持 access token 和 refresh token，无效、不属于本客户端或已撤销时只返回 `{"active":false}`。依赖不可用返回 503，不能当作令牌无效。状态响应禁止缓存；协议管理接口与 Token 签发使用独立的来源配额。

Revocation 接受本客户端的 access token 或 refresh token；采用应用授权级撤销，使该用户在目标应用的既有令牌及未使用授权码失效，保留应用访问资格、SSO 会话和其他应用授权。未知、已撤销或其他客户端的令牌统一返回 200。旧刷新令牌的主动撤销不会触发刷新重放导致的 SSO 全局退出。

业务应用应在每次受保护请求时调用 introspection，检查 `active`、`sub`、`aud` / `client_id` 与本地会话绑定是否一致；`active=false` 时清除本地登录态，503 时返回暂不可用并保留 Cookie。长连接应用应在敏感操作或定期续期时再次校验。中心撤销不主动清理其他域名的 Cookie；本项目 admin 示例已采用每次请求在线 introspection。仅在登录时离线验签无法获得即时撤销效果。

协议依据：[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)、[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)。

## 日志检索、审计详情与凭据轮换

登录记录新增用户名、IP、身份源及 RFC3339 时间范围筛选；用户端查询始终限定当前用户。审计新增操作者、操作路由、目标、请求编号、IP、时间范围检索；`/dashboard/audit/{id}` 展示完整元数据及允许记录的配置字段差异。应用、客户端、用户和审批状态的前后快照只选择明确允许的字段，不采集请求正文、密码、密钥哈希、令牌或联系方式。

客户端详情提供“平滑轮换密钥”：新密钥仅在成功响应中显示一次，原密钥在所选的 1 小时、24 小时或 7 天窗口内继续可用；使用新密钥完成部署后可“停用旧密钥”。每个客户端最多保留一把旧密钥，重叠期结束或提前停用后才能再次轮换。轮换和停用旧密钥不撤销用户授权；“紧急重置密钥”及编辑密钥仍立即替换凭据并使既有授权失效。过期旧密钥不再参与认证，由现有后台清理任务分批删除哈希。

## 账号选择与安全提醒

`prompt=select_account` 进入账号选择页，可继续使用当前账号或重新登录其他账号，保留原 OAuth state、nonce、PKCE、scope 和回调。选择操作绑定授权请求和当时的会话，并要求 CSRF；不会把授权请求 ID 当成登录凭据。个人菜单也提供“切换账号”。切换时撤销当前浏览器的 SSO 会话及关联刷新令牌，不影响其他设备。

通知 outbox 新增安全消息 kind：`new_login`、`password_changed`、`password_reset_completed`、`admin_password_reset`、`contact_changed`、`identity_linked`、`identity_unlinked`。通知网关需识别这些 kind。登录提醒仅在完成主认证且无需 MFA，或 MFA 验证成功后生成；再认证不重复发送登录提醒。联系方式变更通知发送到原已验证渠道及本次验证的新渠道；管理员修改联系方式只通知原已验证渠道。所有提醒与对应变更同事务入队，复用已有投递、重试、脱敏及保留策略，不包含密码、验证码、密钥或恢复码。

上述变更新增 `006_management_workflows.sql`、`007_client_secret_rotation.sql`，启动新版前执行 `scripts/migrate.sh`。
