# Pero 用户、租户与应用接入

## 职责与权限边界

Pero 维护统一用户身份、登录与会话、个人/组织空间及 owner/admin/member 组织治理角色。业务资源、业务角色和数据 ACL **不在** Pero 维护。

每个业务数据表独立保存非空 `tenant_id`，请求中的租户标识必须与已验证 Access Token 的 `tenant_id` 匹配。仅接受 `typ=at+jwt`、可信 `iss`、预期 `aud`、有效签名及 `exp` 的 Access Token；ID Token 不用于业务接口鉴权。需要即时撤销判断时调用 `POST /api/oauth2/introspect`，本地 JWT 校验无法保证实时失效。

SSO 会话只关联用户；切换空间必须重新授权，Refresh Token 不能切换租户。个人空间随用户创建，无组织治理能力。非系统应用按照 `tenant_mode` 选择个人/组织/两者。

## 组织创建资格与成员上限

平台超级管理员在用户详情管理是否允许创建组织、用户最多可创建多少个组织。配额只约束**新组织创建**，仅计算该用户已创建且未注销的组织；转让 Owner 或降低创建额度，均不影响已有组织的邀请、成员与应用接入。

每个组织有独立成员上限 `max_members`（初始值 100，平台超级管理员可设置 1–100000）。包含 Owner/Admin/Member 的**有效成员**；不把已移除成员计入。组织状态为 active 且有效成员数小于上限时才能邀请；接受邀请时在组织锁下再次校验，防止并发超额。降低上限不会删除或降级已有成员；超过上限只阻止新增成员，保留已有成员操作。已发送但未接受的邀请在名额用尽后不能使用，需释放名额或增加上限。成员上限变更会触发 `tenant.membership.changed` 同步提示，下游可重新读取 `/api/tenants/sync` 获取最新 `max_members`，但不会因此使现有登录令牌失效。

## 组织生命周期

- **active**：Owner/Admin 按其治理角色管理成员；Owner 可改名、停用与恢复组织。
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
| GET / POST | `/tenants` | 列出自己的空间 / 按个人创建额度创建组织；创建成功返回 HTTP 201 和 `{"id":"<tenant-uuid>"}` |
| GET | `/tenants/{id}` | 获取当前组织信息 |
| GET | `/tenants/{id}/members` | 列出成员 |
| GET / POST | `/tenants/{id}/invitations` | 查看最近 100 条邀请 / 邀请成员：`{email,role}` |
| POST | `/tenants/{id}/invitations/{invitation}/revoke` | 撤销待接受邀请 |
| POST | `/tenants/{id}/members/{user}` | 修改角色/移除：`{action}` |
| POST | `/tenants/{id}/rename` | 修改组织名称：`{name}` |
| POST | `/tenants/{id}/leave` | 退出组织 |
| POST | `/tenants/{id}/status` | 设置组织状态：`{status:"active"|"disabled"}`；相同状态重复提交无副作用 |

所有操作从**已验证的 Access Token** 获取操作者；除列出及创建外，Token 的 `tenant_id` 必须与路径中的组织 ID 完全一致。**唯一例外**：组织已停用且无法再为该组织签发 Token 时，其当前 Owner 可使用具有 `tenant.manage` 的**个人空间** Access Token 调用 `POST /tenants/{id}/status` 并提交 `{status:"active"}` 以恢复自行停用的组织。该例外只允许恢复已停用且未被平台锁定的组织，不能用个人空间 Token 停用别的活动组织或执行其他跨租户管理。进一步复用现有 Owner/Admin 规则和安全校验，不接受客户端伪造的 actor。

组织解散是不可逆高风险操作，**不通过业务 API 委托**。Owner 必须在 Pero 的 `/account/tenants/{id}` 页面完成近期再认证后输入组织 slug 解散。

UserInfo 与 Access Token introspection 返回当前 `tenant_id`、`tenant_kind` 和实时 `membership_role`；后者只代表组织治理身份，不替代业务系统 ACL。

## 同步与全量对账

具有 Account Sync URI 的非系统应用 confidential 客户端，可通过 `client_secret_basic` 或 `client_secret_post` 调用：

- `POST /api/accounts/sync`：已知 `sub` 的用户最新账户投影。
- `POST /api/tenants/membership/sync`：已知 `sub,tenant_id` 的成员快照（包括 `app_allowed`、`app_access_active` 和最终 `active`）。仅查询该应用曾具备准入资格的用户-租户关系；撤销后仍返回 `active=false`，但从未在该应用准入范围内的成员关系返回 404。
- `POST /api/accounts/sync/list`：按 `user_id` 升序分页读取本应用有历史准入关系的用户账户投影，每页最多 100 条；可提交 `after_user_id`。
- `POST /api/tenants/membership/list`：按 `(tenant_id,user_id)` 分页读取本应用**曾可准入的历史成员关系**（即使成员已退出、组织已停用、应用不再支持该租户类别）；每条包含 `tenant_name`、`membership_role`、`tenant_status`、`membership_status`、`app_allowed`、`app_access_active`、`active` 以及版本；每页最多 100 条；续页提交 `after_tenant_id` 与 `after_user_id`。
- `POST /api/tenants/sync`：提交 `tenant_id`，读取本应用曾可准入的单个租户目录快照，包括 `tenant_name`、`tenant_kind`、`slug`、`tenant_status`、`max_members`、`member_count`、`app_allowed`、`active`。不可见租户返回 404。
- `POST /api/tenants/list`：按 `tenant_id` 升序列出本应用曾可准入的租户目录快照，每页最多 100 条；续页提交 `after_tenant_id`（UUID），响应仍为 `{rows,next}`。

三个分页接口响应均为 `{rows,next}`，`next=null` 表示结束；从 `next` 中取游标继续查询。所有响应不缓存。全量对账用于初次接入、事件过期后的恢复及主动核对；分页不是跨页一致性事务快照，对账时持续应用增量事件，并在必要时重新执行一轮对账。

现有签名事件 `tenant.membership.changed` 保留 `tenant_id`；事件仅提示重新查询最新状态，接收端应校验签名、受众、时间、jti 并实现幂等，切勿按消息产生顺序直接覆盖业务侧状态。业务系统负责本地数据投影、资源 ACL 和业务数据生命周期。


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

- **首次接入**：业务系统通过 confidential client 凭据（`client_secret_basic` 或 `client_secret_post`）调用 `POST /api/accounts/sync/list`、`POST /api/tenants/list` 和 `POST /api/tenants/membership/list` 建立本地投影。每个请求使用 `application/x-www-form-urlencoded`，这三种列表使用各自独立的游标。
- **日常更新**：校验签名的 `tenant.membership.changed` 事件仅提示变化（携带 `sub` 和 `tenant_id`），先调用 `POST /api/tenants/membership/sync` 查询最新成员状态；再视需要调用 `POST /api/tenants/sync` 更新组织目录。应用成员资格授予/撤销同样会产生有关历史租户关系的变更通知。账户事件仍通过 `POST /api/accounts/sync` 获取最新状态。
- **断线恢复**：使用三个列表重复全量对账，保留并重放对账期间的增量事件。历史关系可能变为 `active=false`，不能因为记录仍在列表中就继续授予访问，也不应因为某页缺行就直接删除业务历史数据。
- **接入范围**：所有服务端同步接口都要求**非系统应用的、已配置 Account Sync URI 的 confidential OAuth 客户端**。目录及成员列表以应用曾实际符合准入条件的用户-租户关系为边界，并非平台全部组织的全局枚举接口。个人模式应用不能据此枚举用户所在的无关组织；准入撤销、成员移除或组织停用后，历史关系仍可对账，但不再新增无关组织的可见性。应用整体停用后，仍允许有效的 confidential 客户端凭据读取历史投影以完成撤权对账，投影中的 `app_allowed` / `active` 将为 `false`；停用不会允许用户继续以该应用获得访问令牌。
- **字段语义**：`app_allowed` 反映该应用当前模式、状态及组织准入条件；`active` 反映当前是否有效。成员列表的 `active` 还要求账户、应用账户准入和组织成员关系均有效。历史记录和租户 tombstone 仅供同步与审计；业务数据是否清理由业务系统自行决定。

## 组织应用申请

Owner 可在 `/account/tenants/{id}` 查看组织适用的应用，对 `organization_access=restricted` 的应用申请准入或撤回待审申请。平台超级管理员在 `/dashboard/tenants/{id}` 批准或拒绝申请，批准与组织应用准入变更在同一事务内完成；仍保留原有平台直接授权入口。每个组织/应用保留一条当前申请记录，拒绝后可以再次申请。停用组织、禁用应用或已开通应用均不允许再提交新申请。

当用户通过独立应用注册/加入流程完成验证后，原先来自组织自动准入的用户应用资格将升级为显式准入；此后可以按应用租户模式进入个人空间。被管理员明确撤销的准入不会经此流程被隐式恢复。
