# 应用门户、发送渠道和签名密钥运维

密钥生命周期与注销结构包含在 `001_init.sql`，启动时自动核对迁移并验收。通知配置均为可选；缺失或格式无效不影响启动。主动发起注册邮件、联系方式验证、密码恢复时，所需渠道未配置会返回 HTTP 503；已排队通知遇到连接、认证或供应商失败时记录受控错误并重试，异步投递结果在后台查看。

## 我的应用

登录后打开 `/account/applications`。只有启用的应用及有效访问资格出现在“我的应用”，可按名称、标识或说明搜索。管理员在应用配置中填写 `homepage_url`、`logo_url`。打开主页后，由应用按原有 OIDC 流程完成单点登录；门户不向 URL 注入令牌。缺少主页的卡片提示联系管理员。

## SMTP 与短信

```toml
[notification.smtp]
host = "smtp.example.com"
port = 587
security = "starttls" # 或 tls（通常使用 465）；不允许明文连接
username = "notify@example.com"
password = "REPLACE_WITH_SMTP_PASSWORD"
from = "Pero <notify@example.com>"

# 可独立配置。短信当前直连 Twilio Messages API，无需自建网关。
[notification.sms]
account_sid = "AC_REPLACE_WITH_32_HEX_DIGITS"
auth_token = "REPLACE_WITH_TWILIO_TOKEN"
from = "+12025550123"
```

SMTP 可使用无认证的可信 TLS 中继，此时留空 username/password。必须配置 host、port、security、from。服务不会在启动时连接 SMTP；证书由系统配置的可信根验证。邮件正文包含通知类别、验证码或操作链接，SMTP Message-ID 固定为通知 ID。短信 To 使用账户保存的国际号码，发送文本包含同样的操作信息。Twilio 账户须具备对应地区发送权限。

两类渠道复用现有加密 outbox、租约、过期清理、重试及 `/dashboard/notifications`。发送服务接受消息只代表提交成功，不代表最终送达。SMTP 和短信提供至少一次提交语义：连接超时后可能已被接收，重试可能重复发送。验证码与操作链接仍沿用原有效期和一次性校验，不因重试生成新凭据。默认重试从 30 秒递增至 300 秒，到期停止。日志不会记录正文、收件地址或凭据。

原有 `[notification] endpoint/bearer_token` 可作未配置直连适配器的渠道的网关；配置了 smtp/sms 后该渠道优先使用直连适配器，错误不会自动切换。网关需为 HTTPS 并按 `Idempotency-Key` 去重。

## 密钥轮换

身份源详情页执行实际 RSA 密钥对签名校验并检查有效期；活动密钥到期前 30 天显示提醒，后台每分钟输出到期告警。建议将日志告警接入现有运维系统。

1. 提前添加非活动 RS256 密钥，确认公私钥匹配，并设置有效期。
2. 在“轮换计划”输入带时区的 RFC3339 时间，如 `2026-12-01T02:00:00+08:00`。每个身份源保留一个计划；新计划替换旧计划，可在页面取消；手动激活也会清除尚未执行的计划。后台每分钟检查，激活时再次验证密钥。也可以手动激活。
3. 激活新密钥后，旧公钥继续通过 JWKS 发布，旧私钥不再用于签名。
4. 等待页面“可安全撤销时间”，再撤销旧密钥。系统记录签发时的最长访问/ID 令牌有效期（含注销令牌）并额外预留 300 秒时钟偏差；客户端后续改变 TTL 不缩短既有保留期。普通撤销拒绝活动密钥及仍在保留期的密钥。

迁移会为存量公钥保守预留当前最大令牌有效期。公钥验证缓存应在未知 kid 时重新拉取；应用必须检查 exp，不能把 JWT 的存在等同永久本地会话。密钥确已泄露时使用“紧急撤销”：立即停签、从 JWKS 移除，无视保留期，可能中断登录。应用的公钥缓存仍需刷新；要求立即失效的资源应使用中心在线令牌状态校验。

## Back-channel Logout

在应用详情中为每个 OAuth 客户端设置“应用注销通知”的公共 HTTPS 接收地址。Discovery 提供 `backchannel_logout_supported` 和 `backchannel_logout_session_supported`；ID Token 中已有 `sid`。应用应按 `(iss, client_id, sid)` 建立中心会话与本地会话的映射。

中心在成功签发 ID Token 的同一事务中记录 RP 会话。所有中心会话撤销（退出、账户关闭、密码/安全策略撤销等）通过数据库触发器原子入队。应用资格/授权撤销也通知对应应用。迁移可从已有刷新令牌补建关联；升级前没有刷新令牌的本地会话需重新登录以建立关联。

投递使用 HTTPS POST，`application/x-www-form-urlencoded` 中携带 `logout_token`。令牌用当前 RS256 密钥签名，包含 `iss/aud/sub/sid/iat/exp/jti/events`，不含 nonce，`typ=logout+jwt`，有效期 120 秒。单个事件重试保持 jti，重新签名刷新短期有效期。接收方应：

- 只从预先信任的 issuer/JWKS 验签，固定 RS256，验证 issuer、audience、类型、时间及 logout event，拒绝 nonce。
- 按 sid 撤销服务端本地会话，持久保存 jti 去重；重复和未知会话返回 200。持久撤销完成前不能提前确认成功。
- 此端点无需浏览器 CSRF token 或用户 cookie；以 Logout Token 验证请求。客户端必须在每次请求检查服务端会话，才能让浏览器旧 cookie 失效。

队列提供至少一次投递，120 秒租约，60 秒请求超时，30 秒递增退避至一小时，最长重试一天。后台通知页显示最近 100 条注销通知、状态、受控错误及重试入口。记录保留 30 天。接收端长时间不可用会在一天后过期，需要运维修复并让用户重新登录。

可运行的 Flask/Redis 接收端在 `examples/backchannel-logout/app.py`。安装 requirements，设置 `OIDC_ISSUER`、`OIDC_CLIENT_ID`、`REDIS_URL`，执行 `flask --app app run --port 8090`，通过 HTTPS 反向代理暴露 `/backchannel-logout`。把示例中的 Redis 本地会话写入逻辑接到应用自己的 OIDC 回调及会话中间件。

协议参考：[OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)，[SMTP 库](https://docs.rs/lettre/latest/lettre/transport/smtp/struct.AsyncSmtpTransport.html)，[Twilio Messages API](https://www.twilio.com/docs/messaging/api/message-resource)。
