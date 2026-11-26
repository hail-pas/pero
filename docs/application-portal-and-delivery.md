# 应用接入与运维

本指南适用于 Pero 管理员和负责 OAuth / OIDC 接入的应用团队。Linux Docker 部署、验收和回退步骤见 [部署指南](../deploy/pero/README.md)。

## 我的应用

登录后打开 `/account/applications`。只有启用的应用及有效访问资格出现在“我的应用”，可按名称、标识或说明搜索。管理员在应用配置中填写 `homepage_url`、`logo_url`。打开主页后，由应用按原有 OIDC 流程完成单点登录；门户不向 URL 注入令牌。缺少主页的卡片提示联系管理员。

## 应用设备会话上限

`max_sessions` 按用户和应用限制同时有效的逻辑设备数。普通应用默认允许 1 台，正整数允许相应数量，`0` 表示不限。内置 user-center 应用不限。逻辑设备对应一条 SSO 浏览器会话，同一设备下的多个 OAuth 客户端或租户会话共用应用配额。设备列表反映仍有效的认证会话。

满额时接入新设备，或再次使用在该应用被撤销的设备，需要在交互式授权中明确确认。静默授权无法接管。设备在授权码兑换事务中加入应用，新设备接管时淘汰最早加入的有效设备。收紧额度时保留最新的有效设备。应用设备会话沿用 SSO 的空闲和绝对有效期。

个人会话页和管理员会话处置页支持撤销指定应用设备，撤销范围包含该设备下的客户端会话及关联刷新令牌。其他应用的会话继续有效。接入方使用 Access Token、ID Token 和 Logout Token 中的 RP 会话 ID `sid`，即时撤销判断使用在线令牌校验。

## SMTP 与短信

邮件、短信和 HTTPS 网关按需配置。注册邀请和联系方式验证所需渠道不可用时，相应操作返回 HTTP 503。密码找回在所有渠道均不可用时返回 HTTP 503。只缺少请求对应的渠道时，仍返回统一提示。

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

两类渠道共用加密通知队列、租约和重试机制，可在 `/dashboard/notifications` 查看投递结果。供应商接受消息只代表提交成功，最终送达状态由供应商确认。连接超时后重试可能重复提交同一消息。验证码和操作链接保留原有效期及一次性校验。重试间隔按 30 秒递增，最多 300 秒，通知到期后停止。

原有 `[notification] endpoint/bearer_token` 可作未配置直连适配器的渠道的网关；配置了 smtp/sms 后该渠道优先使用直连适配器，错误不会自动切换。网关需为 HTTPS 并按 `Idempotency-Key` 去重。

## 密钥轮换

身份源详情页执行实际 RSA 密钥对签名校验并检查有效期；活动密钥到期前 30 天显示提醒，后台每分钟输出到期告警。建议将日志告警接入现有运维系统。

1. 提前添加非活动 RS256 密钥，确认公私钥匹配，并设置有效期。
2. 在“轮换计划”输入带时区的 RFC3339 时间，如 `2026-12-01T02:00:00+08:00`。每个身份源保留一个计划；新计划替换旧计划，可在页面取消；手动激活也会清除尚未执行的计划。后台每分钟检查，激活时再次验证密钥。也可以手动激活。
3. 激活新密钥后，旧公钥继续通过 JWKS 发布，旧私钥不再用于签名。
4. 等待页面“可安全撤销时间”，再撤销旧密钥。系统记录签发时的最长访问/ID 令牌有效期（含注销令牌）并额外预留 300 秒时钟偏差；客户端后续改变 TTL 不缩短既有保留期。普通撤销拒绝活动密钥及仍在保留期的密钥。

遇到未知 `kid` 时，应用应重新获取 JWKS，并在验签时校验 `exp`。密钥泄露时可使用“紧急撤销”，立即停签并从 JWKS 移除，可能中断登录。应用应刷新公钥缓存，需要即时判断令牌失效的资源使用在线令牌校验。

## Back-channel Logout

在客户端配置中设置“应用注销通知”的公共 HTTPS 接收地址。Discovery 提供 `backchannel_logout_supported` 和 `backchannel_logout_session_supported`。应用应按 `(iss, client_id, sid)` 建立 RP 会话与本地会话的映射。

授权码兑换在同一事务内记录 RP 会话并签发令牌。退出中心会话、撤销应用设备或应用授权等操作通过数据库触发器为受影响的 RP 会话原子入队。SSO 会话达到绝对有效期或空闲超时后，清理任务先入队再删除会话。

投递使用 HTTPS POST，`application/x-www-form-urlencoded` 中携带 `logout_token`。令牌用当前 RS256 密钥签名，包含 `iss/aud/sub/sid/iat/exp/jti/events`，不含 nonce，`typ=logout+jwt`，有效期 120 秒。单个事件重试保持 jti，重新签名刷新短期有效期。接收方应：

- 只从预先信任的 issuer/JWKS 验签，固定 RS256，验证 issuer、audience、类型、时间及 logout event，拒绝 nonce。
- 按 sid 撤销服务端本地会话，持久保存 jti 去重；重复和未知会话返回 200。持久撤销完成前不能提前确认成功。
- 此端点无需浏览器 CSRF token 或用户 cookie；以 Logout Token 验证请求。客户端必须在每次请求检查服务端会话，才能让浏览器旧 cookie 失效。

队列提供至少一次投递，120 秒租约，60 秒请求超时，30 秒递增退避至一小时，最长重试一天。后台通知页显示最近 100 条注销通知、状态、受控错误及重试入口。自动和手动重试仅允许当前仍配置的接收地址；已移除或更换地址的待投递记录不再发送至旧地址，后台显示已取消。若在有效期内重新配置原地址，尚未过期的记录可以继续投递。已经发出的请求无法撤回。记录保留 30 天。接收端长时间不可用会在一天后过期，需要运维修复并让用户重新登录。

可运行的 [Flask / Redis 接收端](../examples/backchannel-logout/app.py) 提供注销处理示例。在仓库根目录安装依赖并配置 `OIDC_ISSUER`、`OIDC_CLIENT_ID` 和 `REDIS_URL` 后启动。

```bash
python3 -m pip install -r examples/backchannel-logout/requirements.txt
flask --app examples/backchannel-logout/app run --port 8090
```

通过 HTTPS 反向代理暴露 `/backchannel-logout`，并将示例的 Redis 会话存储逻辑接入应用的 OIDC 回调及会话中间件。协议见 [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)。

## 授权时缺少应用访问资格

非管理平台默认不要求 MFA，仅在该用户明确开启对应应用的 `require_mfa` 后要求验证。已绑定验证器或拥有超级管理员角色不会单独触发普通应用的 MFA；管理平台仍强制 MFA。密码和第三方登录完成后，OAuth 流程按目标应用策略执行。

OAuth 登录发现超级管理员缺少目标应用访问资格时，会自动开通本人的资格（已有停用记录会恢复为 active），再继续原来的 MFA、授权确认及回调流程；不会降低已有 MFA 要求或重置令牌撤销版本，停用的应用仍不可访问。普通管理员和用户继续使用显式应用准入流程。

交互式 OAuth 登录发现普通账号没有应用访问资格时，认证中心进入权限恢复页。用户可前往个人中心申请或查看资格。应用已登记有效的 `login_uri` 时，符合条件的门户申请可关联来源授权。资格取得后，可从原请求重试并继续 MFA、授权确认及回调，或依照 [注册与邀请接入](registration-invitation-design.md#应用配置和回调) 从应用登录入口重新发起。

“登录其他账号”会撤销当前中心登录状态，再继续原授权请求；“取消并返回个人中心”会结束本次请求。恢复入口绑定原会话，并校验签名、CSRF、请求有效期和完成状态。审批期间不会延长授权请求期限；请求过期或会话变化后，应从原业务应用重新发起登录。

`prompt=none` 不展示此页面，仍通过已验证的回调地址返回 OAuth 错误。业务应用的回调端仍需处理协议错误，校验 state，并提供友好的登录失败及重试入口。
