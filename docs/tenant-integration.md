# Pero 多租户业务接入约定

## 认证与租户边界

Pero 负责统一用户身份、个人和组织租户及成员关系；业务应用自行维护资源隔离、业务角色和 ACL。所有业务记录使用非空 `tenant_id`，严禁直接信任未经 Access Token 比对的客户端 `X-Tenant-ID`。

使用 OAuth2 Authorization Code + PKCE，`/oauth2/authorize` 接收可选 `tenant_id=<UUID>`。个人应用默认选个人空间；多组织应用在用户身份认证后选择租户，`prompt=none` 在上下文不唯一时返回 `interaction_required`。SSO 保持用户级，不把租户存进共享 SSO 会话。

业务 API 必须检验 Access Token 签名、`typ=at+jwt`、`iss`、`aud`、`exp`，并将请求租户与可信 `tenant_id` 精确比对。ID Token 只供登录客户端使用，不能作为业务 API Bearer。Pero 的 owner/admin/member 仅表示组织治理角色，不是业务权限。跨组织切换应重新授权，不能凭 Refresh Token 修改租户。

```sql
-- 即使外部传入全局资源 UUID，读写也必须额外限定已验证租户
SELECT id,title FROM documents WHERE tenant_id=$1 AND id=$2;
UPDATE documents SET title=$3 WHERE tenant_id=$1 AND id=$2;
```

## 在线撤权与同步

对即时撤权敏感的接口使用 `POST /api/oauth2/introspect` 查询当前 Token 有效性；离线 JWT 仅在过期前做签名校验，不能保证即时失效。成员移除、租户停用会使相应版本的凭据失效，不影响同一用户在其他租户的授权。

仅限配置 Account Sync URI 的非系统应用 confidential 客户端，通过 `POST /api/tenants/membership/sync` 携带 `sub`、`tenant_id` 查询当前成员快照，返回 `active`、`tenant_kind`、`tenant_status`、`membership_status`、`tenant_version`、`membership_version`。不可查询其他用户在无关租户的成员信息。

在现有签名 Account Sync 投递队列上新增 `tenant.membership.changed`，接收方需验证事件签名、aud、过期时间、jti 去重，并重新获取当前快照，不能依据消息送达顺序恢复旧状态。原 `membership.granted/revoked` 仍仅表示用户应用准入，不等于租户成员变更。

## 运维入口

- 用户个人/组织管理：`/account/tenants`；组织 owner 可停用和恢复组织，组织 admin 仅可管理普通成员和邀请。
- 平台运维：`/dashboard/tenants`；超级管理员权限不会自动授予组织的业务数据权限。
- 存量非系统应用的未绑定租户授权与刷新凭据在迁移时失效，需重新授权；系统应用登录仍保持无租户上下文。

## 组织创建配额

平台超级管理员在「用户详情 → 组织创建权限」开启用户创建组织的权限并设置非负整数上限。未配置时默认禁止创建。配额只统计该用户创建的组织（包括已停用组织），不统计个人空间；所有者转移不改变创建人和配额归属。

新建组织必须具有权限且已创建数量小于上限。禁止权限或超出上限时，不得发出新邀请、接受尚未加入组织的邀请；已经加入的成员仍可变更角色、退出或被移除，组织更名与启停不受影响。正常达到上限时，只阻止新建组织，不阻止现有组织邀请成员。

管理员调低配额时，后台在同一事务中优先删除超出额度部分的空组织；空组织严格定义为**只有一位有效 owner 且不存在其他有效成员**，已移除的成员不计入。保留所有非空组织；若仍超额，停止扩张直至数量回落或管理员增额。删除前撤销租户相关授权，并向已配置 Account Sync 的下游发送携带被删 `tenant_id` 的 `tenant.membership.changed`，接收方查询当前状态应得到 `active=false`；操作写入审计。移除成员后如果一个超额组织变为空组织，也执行同样的清理。
