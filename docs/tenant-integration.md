# 租户接入

## 职责与权限边界

Pero 管理用户身份、登录会话、个人空间与组织空间，以及 `owner`、`admin` 和 `member` 三种组织治理角色。业务应用负责资源、业务角色和数据访问控制。

业务应用应按非空 `tenant_id` 隔离业务数据，并要求请求及目标资源的租户与已验证的 Access Token 一致。校验 Access Token 的签名、`typ=at+jwt`、`iss`、`aud` 和 `exp`。需要即时判断撤销时，调用 `POST /api/oauth2/introspect`。

SSO 会话只关联用户；切换空间必须重新授权，Refresh Token 不能切换租户。个人空间随用户创建，无组织治理能力。非系统应用按照 `tenant_mode` 选择个人/组织/两者。

## 组织创建资格与成员上限

平台超级管理员在用户详情管理是否允许创建组织、用户最多可创建多少个组织。配额只约束**新组织创建**，仅计算该用户已创建且未注销的组织；转让 Owner 或降低创建额度，均不影响已有组织的邀请、成员与应用接入。

每个组织有独立成员上限 `max_members`（初始值 100，平台超级管理员可设置 1–100000）。包含 Owner/Admin/Member 的**有效成员**；不把已移除成员计入。组织状态为 active 且有效成员数小于上限时才能邀请；接受邀请时在组织锁下再次校验，防止并发超额。降低上限不会删除或降级已有成员；超过上限只阻止新增成员，保留已有成员操作。已发送但未接受的邀请在名额用尽后不能使用，需释放名额或增加上限。成员上限变更会触发 `tenant.membership.changed` 同步提示，下游可重新读取 `/api/tenants/sync` 获取最新 `max_members`，但不会因此使现有登录令牌失效。

管理员邀请仅由 Owner 创建、替换和撤销；Admin 可以管理普通成员邀请，但不能通过重新邀请覆盖尚有效的管理员邀请。

## 组织生命周期

- **active**：Owner 和 Admin 按其治理角色管理成员。Owner 可改名或停用组织。
- **disabled**：保留组织及成员，拒绝新邀请、接受邀请和业务授权；Owner 可恢复自行停用的组织；平台超级管理员停用的组织只能由平台超级管理员恢复，旧租户授权不会恢复。停用会终止已绑定该组织的未完成 OAuth 授权请求。停用/恢复采用明确目标状态，允许安全重试。
- **deleted**：只允许 Owner 通过组织标识确认主动解散，且组织已没有其他有效成员、未被平台停用。平台停用期间不得自行解散，须先由平台超级管理员解除停用。解散后不可恢复；保留租户 ID、成员历史与审计记录以供下游对账，释放 slug；撤销租户令牌、待用授权码和未接受邀请，并发送状态变更事件。业务系统仍自行决定业务数据保留与清理。
- 平台后台 `/dashboard/tenants` 提供分页搜索、状态过滤、成员检索、组织成员上限配置、所有者应急提升、组织应用准入和停用/恢复。平台管理员不因这些操作自动获得业务数据访问权。

## 组织成员自动开通应用资格

应用管理员可选启用 `organization_auto_access`。符合当前组织成员身份及该组织应用准入策略的用户，首次 OAuth 登录可自动建立应用访问资格；已有显式停用的用户应用资格不被自动恢复。自动开通的用户应用资格标记 `admission_origin=organization`：只允许组织空间，不允许个人空间；离开或停用组织后，相应 Token 立即无法通过在线验证。显式管理员授权会将标记改为 `explicit`。

## 应用与组织准入

`apps.tenant_mode` 表示应用接受 personal、organization 或 both。`apps.organization_access` 表示组织准入方式：

- `open`（默认）：满足应用准入资格的组织成员均可授权进入。
- `restricted`：必须由平台超级管理员在组织详情显式授予应用准入；组织被移出准入列表时无法再通过该组织登录应用。
- 个人空间不受 `organization_access` 限制，但仍需应用本身允许 personal 模式及用户具备应用访问资格。

准入关系仅回答“这个组织是否允许进入应用”，不授予具体业务权限。修改应用全局准入策略会撤销该应用原有授权；将应用设为 `open` 或仅个人模式时会清理旧显式组织准入，后续重新转为 `restricted` 需要重新审批，避免隐式恢复访问；修改单个组织的应用准入，推进该组织的认证版本并撤销该组织在目标应用中的未失效刷新令牌，确保撤销后重授不能让旧 JWT 恢复；这也会使该组织的其他应用的旧租户版本失效，需要重新授权。

## 面向业务系统的管理 API

业务应用显式申请 `tenant.manage` scope，用户同意后持 Access Token 调用以下 JSON API（路径前缀 `/api`）：

| 方法 | 地址 | 操作 |
| --- | --- | --- |
| GET | `/tenants` | 列出自己的空间，返回 `{rows}` |
| POST | `/tenants` | 提交 `{name, slug}` 创建组织，成功返回 HTTP 201 和 `{"id":"<tenant-uuid>"}` |
| GET | `/tenants/{id}` | 获取当前组织信息 |
| GET | `/tenants/{id}/members` | 列出成员 |
| GET / POST | `/tenants/{id}/invitations` | 查看最近 100 条邀请 / 邀请成员：`{email,role}` |
| POST | `/tenants/{id}/invitations/{invitation}/revoke` | 撤销待接受邀请 |
| POST | `/tenants/{id}/members/{user}` | 提交 `{action}` 改变角色或移除成员，值为 `owner`、`admin`、`member` 或 `remove`，仍受操作者的治理权限限制 |
| POST | `/tenants/{id}/rename` | 修改组织名称：`{name}` |
| POST | `/tenants/{id}/leave` | 退出组织 |
| POST | `/tenants/{id}/status` | 设置组织状态：`{status:"active"|"disabled"}`；相同状态重复提交无副作用 |

所有操作从**已验证的 Access Token** 获取操作者；除列出及创建外，Token 的 `tenant_id` 必须与路径中的组织 ID 完全一致。**唯一例外**：组织已停用且无法再为该组织签发 Token 时，其当前 Owner 可使用具有 `tenant.manage` 的**个人空间** Access Token 调用 `POST /tenants/{id}/status` 并提交 `{status:"active"}` 以恢复自行停用的组织。该例外只允许恢复已停用且未被平台锁定的组织，不能用个人空间 Token 停用别的活动组织或执行其他跨租户管理。进一步复用现有 Owner/Admin 规则和安全校验，不接受客户端伪造的 actor。

组织解散是不可逆高风险操作，**不通过业务 API 委托**。Owner 必须在 Pero 的 `/account/tenants/{id}` 页面完成近期再认证后输入组织 slug 解散。

UserInfo 与 Access Token introspection 返回当前 `tenant_id`、`tenant_kind` 和实时 `membership_role`；后者只代表组织治理身份，不替代业务系统 ACL。

## 同步与全量对账

由超级管理员开启查询授权后，非系统应用可用有效的 confidential 客户端凭据查询本应用的账户、租户和成员。同步回调可选，用于 Pero 推送事件。以下接口使用 `POST` 和 `application/x-www-form-urlencoded`，通过 `client_secret_basic` 或 `client_secret_post` 认证。

| 路径 | 请求字段 | 响应 |
| --- | --- | --- |
| `/api/accounts/sync` | `sub` 或 `username` | 本应用成员的当前账户投影 |
| `/api/tenants/sync` | `tenant_id` | 租户目录快照，包括名称、类型、`slug`、状态、成员数和上限、`app_allowed`、`active` |
| `/api/tenants/membership/sync` | `sub`、`tenant_id` | 成员快照，包括角色、租户及成员状态和版本、`app_allowed`、`app_access_active`、`active` |
| `/api/accounts/sync/list` | 可选 `after_user_id`、`search`、`active`、`limit` | 账户投影分页，`next` 为用户 UUID |
| `/api/tenants/list` | 可选 `after_tenant_id` | 租户目录分页，`next` 为租户 UUID |
| `/api/tenants/membership/list` | 续页同时传 `after_tenant_id`、`after_user_id` | 成员快照分页，`next` 为 `{tenant_id,user_id}`，条目中的用户标识为 `sub` |

分页响应为 `{rows,next}`，每页最多 100 条，`next=null` 表示结束。初次查询省略游标，续页使用对应的 `next` 值。点查超出应用可见范围时返回 HTTP 404。所有响应禁止缓存。

完整用户名查询和前缀搜索用于应用侧选人，参数和 `profile` scope 要求见 [按用户名查找和下拉搜索](account-lifecycle-sync.md#按用户名查找和下拉搜索)。

账户投影包含本应用已有的成员关系。租户和成员投影以本应用历史准入关系为边界，保留退出、解散或准入被撤销后的快照。成员快照中，`app_allowed` 反映应用状态、租户模式与组织准入，`app_access_active` 反映该账户的应用访问资格，`active` 还要求用户、租户与成员关系均有效。应用停用后，仍可用有效客户端凭据读取历史投影以完成撤权对账。

### 组织元数据与治理角色同步

组织改名会触发 `tenant.membership.changed`，但**不会**撤销既有 Access Token（组织名称不是权限判断条件）。成员角色变更同样触发该事件。增量查询和全量成员对账均返回 `tenant_name` 与 `membership_role`，业务系统可用于组织名称显示及基础治理信息同步，但业务资源授权仍以业务系统自身的规则为准。

## 业务系统租户切换协议（OAuth2 / OIDC）

业务系统只应使用 OAuth2 授权码模式（建议 PKCE），**不需要申请 `tenant.manage` 来实现租户切换**。该高权限 scope 仅用于用户明确委托业务应用进行组织管理。

1. 初次登录导航到 `GET /oauth2/authorize`，正常提交 `client_id`、`redirect_uri`、`response_type=code`、`scope`、`state` 和 PKCE 参数。没有 `tenant_id` 时，只有一个可用空间会直接选中，多个/零个会进入 Pero 空间选择页。
2. 已登录业务应用可用当前 **Access Token** 调用 `GET /api/tenants/choices`（`Authorization: Bearer <access_token>`），获取当前应用及该用户可进入的 `{rows:[{id,kind,name,role}]}` 空间列表；此接口不需要 `tenant.manage`，也不会提供其他用户的组织列表。切换到某个已知租户时，重新发起完整的授权码流程，额外提交 `tenant_id=<uuid>`。Pero 会验证该用户属于该租户、该租户可用、应用模式符合且受应用组织准入策略允许。不可用的请求被拒绝，应用不得按用户输入的 UUID 自行授权。
3. 应用服务端验证 OAuth 回调 `state`，交换 code 获取新的 Access Token / Refresh Token。**新登录上下文以已验证 Access Token 的 `tenant_id` 为准**，不要以客户端提交的 `tenant_id` 为准。旧 Refresh Token 只能刷新原租户，不能拿它更换上下文。
4. 每次业务请求严格校验 JWT 的签名、`typ=at+jwt`、`iss`、`aud`、`exp`，并强制访问的业务资源 `tenant_id` 与 Token 一致。业务应用中的角色权限、数据隔离与资源 ACL 由应用自身实现，不由 Pero 组织的 owner/admin/member 自动映射；本地登录会话和缓存建议以 `(sub,tenant_id)` 为隔离维度。
5. 当需要实时判断撤销时，调用 `POST /api/oauth2/introspect`。组织停用、成员移除、应用准入撤销后，在线校验可立即判定失效；离线 JWT 校验仍可能接受未过期旧 Token，因此短 TTL + 必要时 introspection 更适合高风险操作。
6. 可选的 `prompt=none` 仅适合已有 SSO 会话且已满足授权条件的无交互续登；收到 `interaction_required` 等错误后，应正常进入交互式授权流程。

## 首次接入、增量同步与全量恢复

- **首次接入**。分别遍历账户、租户目录和租户成员的列表接口，建立本地投影。
- **日常更新**。应用可随时查询当前状态。已配置回调时，验证 `tenant.membership.changed` 事件后，用 `sub` 和 `tenant_id` 查询最新成员状态，按需刷新租户目录。账户事件通过 `/api/accounts/sync` 获取当前账户投影。使用 `jti` 去重，按当前查询结果更新。验签和投递流程见 [账户生命周期同步](account-lifecycle-sync.md#接收签名事件)。
- **断线恢复**。重新遍历三个列表。已配置回调的应用继续处理对账期间收到的增量事件。每页独立读取，需要时再核对一轮。以 `active` 控制访问，单页缺行时保留业务历史。

## 组织应用申请

Owner 可在 `/account/tenants/{id}` 查看组织适用的应用，对 `organization_access=restricted` 的应用申请准入或撤回待审申请。平台超级管理员在 `/dashboard/tenants/{id}` 批准或拒绝申请，批准与组织应用准入变更在同一事务内完成；仍保留原有平台直接授权入口。每个组织/应用保留一条当前申请记录，拒绝后可以再次申请。停用组织、禁用应用或已开通应用均不允许再提交新申请。

当用户依据注册策略取得应用的个人准入后，原先来自组织自动准入的用户应用资格将升级为显式准入；此后可以按应用租户模式进入个人空间。被管理员明确撤销的准入不会经此流程被隐式恢复。

自动准入开关变更与成员准入来源从组织变为显式准入时，会复用现有账户同步及租户成员变更事件，促使业务端重新拉取最新状态，而不是依靠旧缓存继续授权。

## 注册与邀请接入

业务应用调用成员邀请接口时，Pero 从已验证的 Access Token 记录来源客户端。接受邀请后，应用可通过来源客户端的 `login_uri` 和返回的 `tenant_id` 发起新授权。授权时会校验组织成员资格与应用准入。回跳及重试流程见 [注册与邀请接入](registration-invitation-design.md)。
