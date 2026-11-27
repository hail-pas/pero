# 应用侧账户生命周期同步

超级管理员可在非系统应用的 confidential 客户端上开启「授权查询账户、租户和成员」。应用使用有效客户端凭据查询本应用的成员状态，资料字段按客户端的 `profile`、`email`、`phone` scope 提供。查询无需配置回调或等待用户登录。成员撤销后仍可按 `sub` 查询停用状态。SPA 和移动端应通过应用后端查询，由后端持有客户端密钥。

查询授权默认关闭。启用前应确认客户端密钥由可信服务持有。已授权的客户端由超级管理员管理 scope 和密钥，停用后也须由超级管理员重新启用。需要接收事件时，可选填公共 HTTPS 回调地址。清空地址会停止推送，查询授权仍有效。关闭查询授权会清除回调地址并停止推送。

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

应用可随时使用客户端凭据调用以下接口，包括收到事件后刷新本地状态时。

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
- `profile` 复用 UserInfo 的字段与 scope 过滤。它是当前完整投影，字段缺失时应清除对应的旧值。已配置回调时，scope 减少会触发重新同步。
- 未关联本应用或用户不存在时返回 HTTP 404。凭据错误或客户端停用时返回 HTTP 401。未获查询授权的客户端、Public 客户端及系统应用客户端返回 HTTP 403。依赖故障返回 HTTP 503。查询失败应保留待处理事件，以便后续重试。

组织自动准入的账户资格取决于是否仍属于至少一个当前获准访问本应用的组织；成员状态、组织状态或组织应用授权变化会额外触发账户重新同步。账户同步和租户成员同步分别更新各自的完整投影。

### 按用户名查找和下拉搜索

应用后端可用同一套客户端认证按完整用户名点查，也可分页搜索下拉选项。两种查找都要求客户端具备 `profile` scope，范围限于本应用当前 `active=true` 的成员。缺少 `profile` 时返回 HTTP 403。

| 接口 | 表单字段 | 用法 |
| --- | --- | --- |
| `POST /api/accounts/sync` | `username=alice` | 按完整用户名匹配，忽略大小写。`username` 和 `sub` 必须且只能传一个。无可见匹配时返回 HTTP 404。 |
| `POST /api/accounts/sync/list` | `search=ali&active=true&limit=20` | 按用户名或昵称的前缀搜索，忽略大小写。所有字符按字面匹配，无结果时返回 `{"rows":[],"next":null}`。 |

两个参数都会去掉首尾空白，传入空字符串时返回 HTTP 400。列表可单独传 `active=true` 或 `active=false` 筛选有效或非有效账户。搜索只匹配有效账户，与 `active=false` 一起使用时结果为空。`limit` 可取 1 到 100，省略时每页 100 条。下一页使用 `after_user_id=<next>`，并保持相同的筛选条件。全量对账时省略筛选条件，以保留撤权所需的非有效账户记录。

下拉选项可以用 `profile.name` 或 `profile.preferred_username` 显示，使用 `sub` 作为选中值和后续账户标识。同步客户端凭据保存在应用后端。

接收推送的应用以 `(iss, sub)` 绑定本地账户，按 `(iss, client_id, sub)` 串行执行“读取当前状态 → 更新本地投影”，将本地变更和消费的 `jti` 同事务提交。按通知内容直接回放旧状态，或并行读取后无序覆盖，均可能恢复已经撤销的账户；这里的事件仅用于触发读取当前状态，事件本身没有顺序保证。

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

首次接入或超过事件投递期限时，分别用账户、租户目录和租户成员的列表接口全量对账。已配置回调的应用在全量对账期间继续处理增量事件。使用当前投影中的 `active` 控制访问，并保留业务历史。接口与游标格式见 [租户同步与全量对账](tenant-integration.md#同步与全量对账)。
