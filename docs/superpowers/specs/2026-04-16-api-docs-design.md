# API Documentation Design Spec

> Date: 2026-04-16
> Status: Draft
> Scope: 为 pero 嵌入在线 Swagger UI 接口文档

## 1. 目标

在 pero 服务中嵌入 Swagger UI，提供：

- 在线可读的接口文档（`/docs`）
- 可导出的 OpenAPI 3.0 JSON spec（`/openapi.json`）
- 需要 auth 的接口显示锁图标 + Bearer token 输入
- 多环境 host 切换（dev / staging / prod）

## 2. 技术选型

- **`utoipa`** (v5) — 通过 Rust 宏/属性从 handler 签名和类型自动生成 OpenAPI 3.0 spec
- **`utoipa-swagger-ui`** (v8+) — 编译时嵌入 Swagger UI，无需外部静态文件
- utoipa v5 对应 utoipa-swagger-ui v8+，确保版本兼容

## 3. 功能实现

### 3.1 OpenAPI Spec 生成

在 `src/docs/mod.rs` 中定义 `ApiDoc` struct，使用 `#[derive(OpenApi)]`：

```rust
#[derive(OpenApi)]
#[openapi(
    paths(/* all handler paths */),
    components(schemas(/* all DTOs */)),
    modifiers(&SecurityAddon),
    security(("bearer_auth" = [])),
)]
struct ApiDoc;
```

### 3.2 Security Scheme（锁图标 + Bearer）

定义 `SecurityAddon` 实现 `Modify` trait，添加 `bearer_auth` security scheme：

```rust
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
        }
    }
}
```

每个需要 auth 的 handler 添加 `security` 属性：

- 无需 auth 的 handler：不标注 security（公开）
- 需要 JWT 的 handler：`#[utoipa::path(security(("bearer_auth" = [])))]`
- 需要 JWT + ABAC 的 handler：同上，通过 tag 或 description 区分

### 3.3 多环境 Server

在 config 中定义多环境 URL：

```toml
[docs]
servers = [
    { url = "http://localhost:8080", description = "Development" },
]
```

`ApiDoc` 通过 modifier 注入 servers 数组到 OpenAPI spec。Swagger UI 顶栏显示下拉菜单切换环境。

### 3.4 路由挂载

在 `src/app.rs` 中：

- `GET /openapi.json` — 返回 OpenAPI spec JSON
- `GET /docs` — Swagger UI 页面（utoipa-swagger-ui 自动处理 `/docs/*` 所有子路由）

这两个路由放在 public router 中，不需要 auth。

## 4. Handler 标注

每个 handler 需要添加 `#[utoipa::path(...)]` 属性，声明：

- `path` — URL 路径
- `tag` — 分组标签（Identity / OAuth2 / OIDC / ABAC / Apps / Health）
- `request_body` — 请求体类型（如有）
- `responses` — 响应类型和状态码
- `security` — 是否需要 auth（如有）
- `params` — 路径参数和查询参数（如有）

需要标注 `utoipa::ToSchema` 的类型：
- 所有 Request DTO（`TokenRequest`, `CreatePolicyRequest`, `RegisterRequest` 等）
- 所有 Response DTO（`TokenResponse`, `PolicyDTO`, `UserDTO` 等）
- `ApiResponse<T>` 和 `PageData<T>`

## 5. 文件结构

| 操作 | 文件 | 说明 |
|------|------|------|
| 新增 | `src/docs/mod.rs` | `ApiDoc`, `SecurityAddon`, `ServersAddon` |
| 修改 | `src/app.rs` | 挂载 `/docs` 和 `/openapi.json` |
| 修改 | `Cargo.toml` | 添加 utoipa + utoipa-swagger-ui |
| 修改 | `config/settings.rs` | 添加 `DocsConfig` |
| 修改 | `config/default.toml` | 添加 `[docs]` 配置 |
| 修改 | 各 domain handler 文件 | 添加 `#[utoipa::path(...)]` |
| 修改 | 各 model 文件 | 添加 `#[derive(ToSchema)]` |

## 6. Tag 分组

| Tag | 说明 | Handler 文件 |
|-----|------|-------------|
| Health | 健康检查 | `routes/health.rs` |
| Identity | 注册、登录、profile、密码、绑定 | `domains/identity/routes/*` |
| Apps | 应用 CRUD | `domains/app/routes/crud.rs` |
| OAuth2 | 授权、token、客户端管理 | `domains/oauth2/routes/*` |
| OIDC | Discovery、JWKS、UserInfo | `domains/oidc/routes/*` |
| ABAC | 策略 CRUD、用户策略分配 | `domains/abac/routes/policies.rs` |
