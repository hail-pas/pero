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
