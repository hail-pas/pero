# Pero 用户、租户与应用接入

## 职责与权限边界

Pero 维护统一用户身份、登录与会话、个人/组织空间及 owner/admin/member 组织治理角色。业务资源、业务角色和数据 ACL **不在** Pero 维护。

每个业务数据表独立保存非空 `tenant_id`，请求中的租户标识必须与已验证 Access Token 的 `tenant_id` 匹配。仅接受 `typ=at+jwt`、可信 `iss`、预期 `aud`、有效签名及 `exp` 的 Access Token；ID Token 不用于业务接口鉴权。需要即时撤销判断时调用 `POST /api/oauth2/introspect`，本地 JWT 校验无法保证实时失效。

SSO 会话只关联用户；切换空间必须重新授权，Refresh Token 不能切换租户。个人空间随用户创建，无组织治理能力。非系统应用按照 `tenant_mode` 选择个人/组织/两者。

## 组织创建资格与成员上限

平台超级管理员在用户详情管理是否允许创建组织、用户最多可创建多少个组织。配额只约束**新组织创建**，仅计算该用户已创建且未注销的组织；转让 Owner 或降低创建额度，均不影响已有组织的邀请、成员与应用接入。

每个组织有独立成员上限 `max_members`（初始值 100，平台超级管理员可设置 1–100000）。包含 Owner/Admin/Member 的**有效成员**；不把已移除成员计入。组织状态为 active 且有效成员数小于上限时才能邀请；接受邀请时在组织锁下再次校验，防止并发超额。降低上限不会删除或降级已有成员；超过上限只阻止新增成员，保留已有成员操作。已发送但未接受的邀请在名额用尽后不能使用，需释放名额或增加上限。

## 组织生命周期

- **active**：Owner/Admin 按其治理角色管理成员；Owner 可改名、停用与恢复组织。
- **disabled**：保留组织及成员，拒绝新邀请、接受邀请和业务授权；可由 Owner 或平台超级管理员恢复，旧租户授权不会恢复。
- **deleted**：只允许 Owner 通过组织标识确认主动解散，且组织已没有其他有效成员。解散后不可恢复；保留租户 ID、成员历史与审计记录以供下游对账，释放 slug；撤销租户令牌、待用授权码和未接受邀请，并发送状态变更事件。业务系统仍自行决定业务数据保留与清理。
- 平台后台 `/dashboard/tenants` 提供分页搜索、状态过滤、成员检索、组织成员上限配置、所有者应急提升、组织应用准入和停用/恢复。平台管理员不因这些操作自动获得业务数据访问权。

## 应用与组织准入

`apps.tenant_mode` 表示应用接受 personal、organization 或 both。`apps.organization_access` 表示组织准入方式：

- `open`（默认）：满足应用准入资格的组织成员均可授权进入。
- `restricted`：必须由平台超级管理员在组织详情显式授予应用准入；组织被移出准入列表时无法再通过该组织登录应用。
- 个人空间不受 `organization_access` 限制，但仍需应用本身允许 personal 模式及用户具备应用访问资格。

准入关系仅回答“这个组织是否允许进入应用”，不授予具体业务权限。修改应用全局准入策略会撤销该应用原有授权；修改单个组织的应用准入，推进该组织的认证版本并撤销该组织在目标应用中的未失效刷新令牌，确保撤销后重授不能让旧 JWT 恢复；这也会使该组织的其他应用的旧租户版本失效，需要重新授权。

## 面向业务系统的管理 API

业务应用显式申请 `tenant.manage` scope，用户同意后持 Access Token 调用以下 JSON API（路径前缀 `/api`）：

| 方法 | 地址 | 操作 |
| --- | --- | --- |
| GET / POST | `/tenants` | 列出自己的空间 / 按个人创建额度创建组织；创建成功返回 HTTP 201 和 `{"id":"<tenant-uuid>"}` |
| GET | `/tenants/{id}` | 获取当前组织信息 |
| GET | `/tenants/{id}/members` | 列出成员 |
| POST | `/tenants/{id}/invitations` | 邀请成员：`{email,role}` |
| POST | `/tenants/{id}/members/{user}` | 修改角色/移除：`{action}` |
| POST | `/tenants/{id}/rename` | 修改组织名称：`{name}` |
| POST | `/tenants/{id}/leave` | 退出组织 |
| POST | `/tenants/{id}/toggle` | 停用/恢复组织 |
| POST | `/tenants/{id}/delete` | 解散组织：`{confirmation:slug}` |

所有操作从**已验证的 Access Token** 获取操作者；除列出及创建外，Token 的 `tenant_id` 必须与路径中的组织 ID 完全一致。**唯一例外**：组织已停用且无法再为该组织签发 Token 时，其当前 Owner 可使用具有 `tenant.manage` 的**个人空间** Access Token 调用 `POST /tenants/{id}/toggle` 以恢复组织。该路径只允许恢复已停用组织，不能用个人空间 Token 停用别的活动组织或执行其他跨租户管理。进一步复用现有 Owner/Admin 规则和安全校验，不接受客户端伪造的 actor。

## 同步与全量对账

具有 Account Sync URI 的非系统应用 confidential 客户端，可通过 `client_secret_basic` 或 `client_secret_post` 调用：

- `POST /api/accounts/sync`：已知 `sub` 的用户最新账户投影。
- `POST /api/tenants/membership/sync`：已知 `sub,tenant_id` 的成员快照（包括 `app_allowed`）。
- `POST /api/accounts/sync/list`：按 `user_id` 升序分页读取本应用有历史准入关系的用户账户投影，每页最多 100 条；可提交 `after_user_id`。
- `POST /api/tenants/membership/list`：按 `(tenant_id,user_id)` 分页读取本应用可见租户类别下的历史关系及当前 `active`、`tenant_name` 和 `membership_role`，每页最多 100 条；续页提交 `after_tenant_id` 与 `after_user_id`。

分页响应均为 `{rows,next}`，`next=null` 表示结束；从 `next` 中取游标继续查询。所有响应不缓存。全量对账用于初次接入、事件过期后的恢复及主动核对；分页不是跨页一致性事务快照，对账时持续应用增量事件，并在必要时重新执行一轮对账。

现有签名事件 `tenant.membership.changed` 保留 `tenant_id`；事件仅提示重新查询最新状态，接收端应校验签名、受众、时间、jti 并实现幂等，切勿按消息产生顺序直接覆盖业务侧状态。业务系统负责本地数据投影、资源 ACL 和业务数据生命周期。


### 组织元数据与治理角色同步

组织改名会触发 `tenant.membership.changed`，但**不会**撤销既有 Access Token（组织名称不是权限判断条件）。成员角色变更同样触发该事件。增量查询和全量成员对账均返回 `tenant_name` 与 `membership_role`，业务系统可用于组织名称显示及基础治理信息同步，但业务资源授权仍以业务系统自身的规则为准。
