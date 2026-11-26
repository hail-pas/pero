# 应用侧账户生命周期同步

超级管理员为非系统应用的 confidential 客户端配置“账户生命周期同步”的公共 HTTPS 接收地址。清空地址即停用同步。SPA 和移动端应由服务端使用独立的 confidential 客户端接收，客户端密钥保存在服务端。

启用代表超级管理员允许该客户端同步本应用成员的账户状态，以及客户端 `profile`、`email`、`phone` scope 对应的资料。这是应用账户同步接口，使用客户端认证，不依赖某次用户登录或 consent；未开启同步的客户端不能读取。普通管理员不能开启/改向同步，也不能修改已启用同步客户端的 scope、设置或轮换其密钥，避免通过客户端管理绕过全局联系方式读取限制。启用同步前应确认客户端凭据仅由可信接收方持有。平台账户没有本应用成员关系时不通知，也不能查询。成员撤销后保留关系以便投递退出事件和查询停用状态。

## 变更来源

| 事件 | 触发条件 |
| --- | --- |
| `sync.requested` | 启用、更换接收地址，或修改客户端 scope/启停状态、应用启停状态及准入策略；组织自动准入资格变化时也为受影响成员安排重新同步 |
| `membership.granted` | 注册/邀请完成、管理员授权、恢复成员资格 |
| `membership.revoked` | 管理员撤销、用户退出应用、账户注销时撤销成员资格 |
| `account.updated` | 用户或管理员修改用户名、昵称、头像、联系方式及验证状态 |
| `account.status_changed` | 账户停用、锁定或恢复 |
| `account.deleted` | 用户注销账户、清除中心个人资料 |
| `tenant.membership.changed` | 租户成员、组织状态或应用准入等变化，影响业务应用的成员投影 |

数据库触发器在业务事务内入队，事务回滚不会产生通知。重复保存相同资料/成员状态、单纯撤销 consent 或令牌不产生账户变更；会话退出继续使用原 Back-channel Logout。

## 接收签名事件

中心向配置地址 POST `application/x-www-form-urlencoded`，字段为 `event_token`。它是 RS256 JWT，使用中心现有 JWKS，header 的 `typ` 为 `pero-account-sync+jwt`，包含：

```json
{
  "iss": "https://auth.example.com",
  "aud": "your-client-id",
  "sub": "019a0000-0000-7000-8000-000000000001",
  "jti": "019a0000-0000-7000-8000-000000000002",
  "iat": 1793232000,
  "exp": 1793232120,
  "event": "account.updated",
  "occurred_at": 1793231990
}
```

`sub` 是中心稳定用户 ID，和 ID Token 的 `sub` 相同。`jti` 是通知 ID，重试保持不变；每次发送重新签名，有效期 120 秒。`occurred_at` 保留事件产生时间。通知不携带邮箱、手机、资料、密码或任何用户访问令牌。

接收方从预配的可信 issuer 和 JWKS 获取 RS256 公钥，校验签名、`kid`、`typ`、`iss`、`aud`、时间和事件类型，并用 `jti` 去重。JWT 自带的 `jku` 和 `x5u` 不参与取钥。已处理的重复事件返回 HTTP 200，处理失败返回非 2xx 以便 Pero 重试。

## 读取当前状态

收到事件后，使用本客户端凭据调用固定的中心地址：

```http
POST /api/accounts/sync
Content-Type: application/x-www-form-urlencoded

client_id=your-client-id&client_secret=YOUR_SECRET&sub=USER_UUID
```

也支持 `client_secret_basic`，不能同时提交两种认证。密钥平滑轮换沿用现有机制。接口有独立来源限流，响应禁止缓存。

```json
{
  "sub": "019a0000-0000-7000-8000-000000000001",
  "active": true,
  "account_status": "active",
  "membership_status": "active",
  "profile": {
    "preferred_username": "alice",
    "name": "Alice",
    "email": "alice@example.com",
    "email_verified": true
  }
}
```

- `account_status` 为 `active`、`disabled`、`locked` 或 `deleted`；`membership_status` 为 `active` 或 `disabled`。
- 账户未注销且状态正常、成员资格有效、应用启用时，`active=true`。其他情况为 false，且 `profile={}`。
- `profile` 复用 UserInfo 的字段与 scope 过滤。它是当前完整投影；字段缺失表示清除旧同步值，不能仅合并非空字段。客户端 scope 减少时也会重新同步。
- 未关联本应用或用户不存在时返回 HTTP 404。凭据错误或客户端停用时返回 HTTP 401。Public 客户端或未配置同步地址的客户端返回 HTTP 403。依赖故障返回 HTTP 503。查询失败应保留待处理事件，以便后续重试。

组织自动准入的账户资格取决于是否仍属于至少一个当前获准访问本应用的组织；成员状态、组织状态或组织应用授权变化会额外触发账户重新同步。账户同步和租户成员同步分别更新各自的完整投影。

应用以 `(iss, sub)` 绑定本地账户，按 `(iss, client_id, sub)` 串行执行“读取当前状态 → 更新本地投影”，将本地变更和消费的 `jti` 同事务提交。按通知内容直接回放旧状态，或并行读取后无序覆盖，均可能恢复已经撤销的账户；这里的事件仅用于触发读取当前状态，事件本身没有顺序保证。

`active=false` 时阻止该中心身份继续访问并清理对应本地会话；重新启用只恢复中心管理的访问条件，不覆盖应用自己的封禁策略。`account_status=deleted` 时按应用的数据归属清理同步资料，业务记录是否删除由应用决定。账户同步是最终一致性机制，不能替代敏感请求的在线 introspection 和原注销协议。

## 投递与排查

至少一次投递；每 5 秒取队列，120 秒租约、60 秒发送超时，失败从 30 秒递增退避，最长一小时，最多重试一天。后台“通知投递”显示最近 100 条账户同步通知，超级管理员可在有效期内立即重试。记录只存通知元数据及受控错误类别，保留 30 天，不保存接收方响应正文。

更换或清空地址会取消旧待投递记录；修改 scope/客户端状态也重新安排现有成员同步。在途 HTTP 无法撤回。停用客户端时暂停发送；重新启用时重新同步现有成员。队列过期后，修复接收方，可清空并重新配置地址，重新安排当前全部成员同步。签名密钥轮换和旧公钥保留期复用现有机制。

在仓库根目录运行 [账户同步示例](../examples/account-sync/app.py)。

```bash
python3 -m pip install -r examples/account-sync/requirements.txt
# 设置 OIDC_ISSUER、OIDC_CLIENT_ID、OIDC_CLIENT_SECRET、REDIS_URL 后运行
flask --app examples/account-sync/app run --port 8091
```

通过 HTTPS 反向代理暴露 `/account-sync` 并登记到客户端。此示例用 Redis 保存账户投影和去重标记，租户成员事件仅验签并确认。实际接入时在应用数据库事务中保存投影和已处理的 `jti`，在业务请求中检查本地投影的 `active`。示例将去重标记保留两天，覆盖 Pero 的一天重试窗口。

## 租户成员通知与全量对账

`tenant.membership.changed` 在 JWT 中额外携带 `tenant_id`。收到事件后，调用 `POST /api/tenants/membership/sync` 读取 `sub` 与 `tenant_id` 对应的当前成员快照，按需调用 `POST /api/tenants/sync` 更新租户目录。

首次接入或超过事件投递期限时，分别用账户、租户目录和租户成员的列表接口全量对账。全量对账期间继续处理增量事件，使用当前投影中的 `active` 控制访问，并保留业务历史。接口与游标格式见 [租户同步与全量对账](tenant-integration.md#同步与全量对账)。
