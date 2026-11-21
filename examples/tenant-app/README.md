# Pero 可运行的业务端接入模板

面向服务端 Web（Confidential + BFF），演示 **OIDC 授权码 + PKCE → 登录身份校验 → 租户选择/切换 → 在线撤销判断 → RP 退出 → 账户和成员增量同步/全量对账**。所有 OAuth 凭据保存在 Redis 服务端；浏览器仅保存 HttpOnly 不透明会话 ID。

## 配置

1. 在 Pero 创建支持 `personal` / `organization` / `both` 的业务应用。
2. 创建 **confidential** OAuth Client，开启 `authorization_code,refresh_token`、S256 PKCE 和 `openid,profile,email` scopes；添加回调 `http://127.0.0.1:8092/callback`。生产环境请改为 HTTPS。
3. 如需同步，将 Account Sync URI 配置为此模板经 **HTTPS** 公开的 `/account-sync`。公网接收端可参考仓库内 `examples/account-sync`。
4. 确保 Redis 可用，配置密钥并启动：

```bash
pip install -r examples/tenant-app/requirements.txt
export PERO_ISSUER=https://auth.example.com
export PERO_CLIENT_ID=your-client-id
export PERO_CLIENT_SECRET=your-secret
export PERO_REDIRECT_URI=http://127.0.0.1:8092/callback
export REDIS_URL=redis://127.0.0.1:6379/0
python examples/tenant-app/app.py
```

访问 `http://127.0.0.1:8092/login`。启用 HTTPS 时设置 `COOKIE_SECURE=true` 并使用 `https://...` 的回调地址。

## 集成契约

- **登录**：从中心取得 code、校验一次性 state、PKCE、OIDC ID Token 的签名/iss/aud/nonce，然后使用 introspection 在线验证 Access Token 和实际租户上下文。
- **租户切换**：使用 Bearer Token 查询 `/api/tenants/choices`，通过携带 CSRF Token 的 POST 表单发起全新的授权码流程。每次登录生成新的随机业务会话 ID，成功切换后清理旧会话；不要修改现有 Token 的 `tenant_id`。
- **受保护请求**：调用 introspection 校验 `active`、`sub`、`tenant_id`；依赖返回 503 时不当作用户已注销。真实应用还需基于当前租户强制校验其业务资源的数据隔离。
- **退出**：携带 CSRF，撤销本客户端授权并引导浏览器退出中心 SSO。RP 回调地址与 Logout URI 请按正式环境配置。
- **同步**：可在 `/account-sync` 接收 JWT 签名事件，通过服务端客户端认证查询账户或租户成员的当前状态；`python examples/tenant-app/app.py reconcile` 可以遍历三个游标接口执行初始/断线全量对账。Redis 投影仅演示，不代替生产业务库、事务和完整的幂等事件处理。

**前提**：本示例只有一台服务进程和一个 Redis；没有业务角色、订单、文件等业务层 ACL。生产应用应使用自己的数据库事务处理账户投影与事件 jti，并根据业务资源的租户归属实现严格隔离。短信/邮件注册、组织申请均由 Pero 用户中心页面处理，无须业务端复制认证逻辑。
