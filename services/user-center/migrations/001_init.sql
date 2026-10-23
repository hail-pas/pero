-- ============================================================
-- User Center — Init Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- encrypt_key 由 DatabaseConfig 管理，通过 PostgreSQL session-level custom setting 注入：
--   SET app.encrypt_key = '<key>';
-- 加密/解密函数：
--   pgp_sym_encrypt(plaintext, current_setting('app.encrypt_key'))
--   pgp_sym_decrypt(ciphertext, current_setting('app.encrypt_key'))


-- ============================================================
-- 0. Enum Types
-- ============================================================

CREATE TYPE user_status AS ENUM ('active', 'disabled', 'locked');

CREATE TYPE common_status AS ENUM ('active', 'disabled');

CREATE TYPE app_type AS ENUM ('web', 'spa', 'mobile', 'service');

CREATE TYPE oauth_client_type AS ENUM ('confidential', 'public');

CREATE TYPE identity_provider_kind AS ENUM ('wechat', 'local', 'oauth2', 'oidc');

CREATE TYPE key_use AS ENUM ('sig', 'enc');

CREATE TYPE key_algorithm AS ENUM ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512');

CREATE TYPE identity_kind AS ENUM ('password', 'oauth');

CREATE TYPE code_challenge_method AS ENUM ('plain', 'S256');

CREATE TYPE contact_change_type AS ENUM ('email', 'phone');

CREATE TYPE contact_change_status AS ENUM ('pending', 'verified', 'cancelled', 'expired');

CREATE TYPE login_event_type AS ENUM ('login_success', 'login_failure', 'logout');


-- ============================================================
-- 1. users
-- ============================================================

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    username citext NOT NULL,
    email citext NULL,
    email_verified_at timestamptz NULL,

    phone citext NULL,
    phone_verified_at timestamptz NULL,

    nickname text NULL,
    avatar_url text NULL,

    status user_status NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz NULL,

    CONSTRAINT ck_users_deleted_status
        CHECK (deleted_at IS NULL OR status IN ('disabled', 'locked')),

    CONSTRAINT ck_users_email_verified_requires_email
        CHECK (email IS NOT NULL OR email_verified_at IS NULL),

    CONSTRAINT ck_users_phone_verified_requires_phone
        CHECK (phone IS NOT NULL OR phone_verified_at IS NULL)
);

CREATE UNIQUE INDEX ux_users_email_alive
ON users (email)
WHERE email IS NOT NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX ux_users_phone_alive
ON users (phone)
WHERE phone IS NOT NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX ux_users_username_alive
ON users (username)
WHERE deleted_at IS NULL;

CREATE INDEX ix_users_status
ON users (status);

CREATE INDEX ix_users_created_at
ON users (created_at);

COMMENT ON TABLE users IS
'用户主表。第一阶段不引入 tenant；email 和 phone 直接保存在本表中，并用 *_verified_at 标识验证时间。逻辑删除由 deleted_at 控制，status 中不包含 deleted 值。';

COMMENT ON COLUMN users.id IS
'用户主键，使用 PostgreSQL 18 内置 uuidv7() 生成。';

COMMENT ON COLUMN users.username IS
'用户名。使用 citext，大小写不敏感。';

COMMENT ON COLUMN users.email IS
'用户邮箱。使用 citext，大小写不敏感。允许为空，因为用户可能只通过第三方 OAuth 创建。';

COMMENT ON COLUMN users.email_verified_at IS
'邮箱验证时间。为空表示未验证；不为空时 email 必须存在。';

COMMENT ON COLUMN users.phone IS
'用户手机号。建议应用层统一规范化为 E.164 格式。使用 citext 主要是为了统一关键字段比较行为。';

COMMENT ON COLUMN users.phone_verified_at IS
'手机号验证时间。为空表示未验证；不为空时 phone 必须存在。';

COMMENT ON COLUMN users.nickname IS
'用户展示名称，不作为登录唯一标识。';

COMMENT ON COLUMN users.avatar_url IS
'用户头像地址，可来自本地资料或第三方 OAuth profile。';

COMMENT ON COLUMN users.status IS
'用户状态。active=正常；disabled=禁用；locked=锁定。逻辑删除由 deleted_at 字段控制，不在此枚举中。';

COMMENT ON COLUMN users.created_at IS
'创建时间。';

COMMENT ON COLUMN users.updated_at IS
'更新时间。无自定义触发器，应用层更新记录时需要同步维护。';

COMMENT ON COLUMN users.deleted_at IS
'逻辑删除时间。deleted_at 不为空时，email 和 phone 的唯一索引不再约束该历史记录。此时 status 必须为 disabled 或 locked。';

COMMENT ON INDEX ux_users_email_alive IS
'未删除用户的 email 唯一。';

COMMENT ON INDEX ux_users_phone_alive IS
'未删除用户的 phone 唯一。';


-- ============================================================
-- 2. apps
-- ============================================================

CREATE TABLE apps (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    code citext NOT NULL,
    name text NOT NULL,
    type app_type NOT NULL DEFAULT 'web',

    description text NULL,
    homepage_url text NULL,
    logo_url text NULL,

    status common_status NOT NULL DEFAULT 'active',
    auto_access boolean NOT NULL DEFAULT false,
    system boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_apps_code
ON apps (code);

CREATE INDEX ix_apps_status
ON apps (status);

COMMENT ON TABLE apps IS
'子应用表。一个用户中心可以服务多个子应用，例如管理后台、数据平台、业务系统等。';

COMMENT ON COLUMN apps.id IS
'应用主键，uuid v7。';

COMMENT ON COLUMN apps.code IS
'应用编码，全局唯一，使用 citext。示例：admin、research-platform、data-center。';

COMMENT ON COLUMN apps.name IS
'应用展示名称。';

COMMENT ON COLUMN apps.type IS
'应用类型：web=传统 Web 应用（confidential client）；spa=单页应用（public client + PKCE）；mobile=移动应用；service=后端服务。';

COMMENT ON COLUMN apps.description IS
'应用说明。';

COMMENT ON COLUMN apps.homepage_url IS
'应用首页地址。';

COMMENT ON COLUMN apps.logo_url IS
'应用 Logo 地址。';

COMMENT ON COLUMN apps.status IS
'应用状态。disabled 时不允许通过 SSO 登录该应用。';

COMMENT ON COLUMN apps.auto_access IS
'是否在用户注册或第三方首次登录且来源为该 app 的授权请求时自动授予访问权限。默认 false，避免新用户自动获得应用访问权。';

COMMENT ON COLUMN apps.created_at IS
'创建时间。';

COMMENT ON COLUMN apps.updated_at IS
'更新时间，由应用层维护。';


-- ============================================================
-- 3. oauth_clients
-- ============================================================

CREATE TABLE oauth_clients (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,

    identifier citext NOT NULL,
    secret_hash text NULL,

    name text NULL,
    type oauth_client_type NOT NULL DEFAULT 'confidential',

    redirect_uris text[] NOT NULL,
    post_logout_redirect_uris text[] NOT NULL DEFAULT ARRAY[]::text[],

    scopes text[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email']::text[],
    grant_types citext[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token']::citext[],

    require_pkce boolean NOT NULL DEFAULT true,

    access_token_ttl_seconds integer NOT NULL DEFAULT 7200,
    refresh_token_ttl_seconds integer NOT NULL DEFAULT 2592000,
    id_token_ttl_seconds integer NOT NULL DEFAULT 7200,

    status common_status NOT NULL DEFAULT 'active',
    token_version bigint NOT NULL DEFAULT 0,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_oauth_clients_redirect_uris_not_empty
        CHECK (cardinality(redirect_uris) > 0),

    CONSTRAINT ck_oauth_clients_access_token_ttl_positive
        CHECK (access_token_ttl_seconds > 0),

    CONSTRAINT ck_oauth_clients_refresh_token_ttl_positive
        CHECK (refresh_token_ttl_seconds > 0),

    CONSTRAINT ck_oauth_clients_id_token_ttl_positive
        CHECK (id_token_ttl_seconds > 0),

    CONSTRAINT ck_oauth_clients_confidential_secret
        CHECK (
            (type = 'confidential' AND secret_hash IS NOT NULL)
            OR
            (type = 'public')
        )
);

CREATE UNIQUE INDEX ux_oauth_clients_identifier
ON oauth_clients (identifier);

CREATE INDEX ix_oauth_clients_app_id
ON oauth_clients (app_id);

CREATE INDEX ix_oauth_clients_status
ON oauth_clients (status);

COMMENT ON COLUMN oauth_clients.token_version IS
'客户端安全策略版本，签发及在线验证 access token 时绑定。';

COMMENT ON TABLE oauth_clients IS
'子应用 OAuth Client 配置表。一个 app 可以有多个 client，例如 Web 端、移动端、测试环境、生产环境。';

COMMENT ON COLUMN oauth_clients.id IS
'Client 配置主键，uuid v7。';

COMMENT ON COLUMN oauth_clients.app_id IS
'所属子应用 ID。';

COMMENT ON COLUMN oauth_clients.identifier IS
'OAuth client_id，对外暴露给子应用。使用 citext，避免大小写造成重复配置。';

COMMENT ON COLUMN oauth_clients.secret_hash IS
'Client Secret 哈希。confidential client 必须配置；public client 可为空。推荐使用 bcrypt 或 SHA-256。';

COMMENT ON COLUMN oauth_clients.name IS
'Client 展示名称。';

COMMENT ON COLUMN oauth_clients.type IS
'Client 类型：confidential=后端保密客户端；public=前端或移动端公开客户端。';

COMMENT ON COLUMN oauth_clients.redirect_uris IS
'允许的 OAuth 回调地址白名单。必须精确匹配，不建议只做域名匹配。';

COMMENT ON COLUMN oauth_clients.post_logout_redirect_uris IS
'允许的登出后跳转地址白名单。';

COMMENT ON COLUMN oauth_clients.scopes IS
'允许申请的 scopes。第一阶段通常为 openid、profile、email。';

COMMENT ON COLUMN oauth_clients.grant_types IS
'允许的授权类型。第一阶段建议 authorization_code 和 refresh_token。';

COMMENT ON COLUMN oauth_clients.require_pkce IS
'是否强制 PKCE。建议第一阶段即默认开启。';

COMMENT ON COLUMN oauth_clients.access_token_ttl_seconds IS
'Access Token 有效期，单位秒。';

COMMENT ON COLUMN oauth_clients.refresh_token_ttl_seconds IS
'Refresh Token 有效期，单位秒。';

COMMENT ON COLUMN oauth_clients.id_token_ttl_seconds IS
'ID Token 有效期，单位秒。';

COMMENT ON COLUMN oauth_clients.status IS
'Client 状态。disabled 时拒绝 authorize 和 token 请求。';


-- ============================================================
-- 4. identity_providers
-- ============================================================

CREATE TABLE identity_providers (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    code citext NOT NULL,
    name text NOT NULL,
    kind identity_provider_kind NOT NULL,

    issuer text NULL,

    authorization_endpoint text NULL,
    token_endpoint text NULL,
    userinfo_endpoint text NULL,
    jwks_uri text NULL,
    end_session_endpoint text NULL,

    client_id text NULL,
    client_secret_enc text NULL,

    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,

    enabled boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_identity_providers_issuer_required
        CHECK (kind NOT IN ('local', 'oidc') OR issuer IS NOT NULL)
);

CREATE UNIQUE INDEX ux_identity_providers_code
ON identity_providers (code);

CREATE INDEX ix_identity_providers_kind
ON identity_providers (kind);

CREATE INDEX ix_identity_providers_enabled
ON identity_providers (enabled);

COMMENT ON TABLE identity_providers IS
'身份提供方配置表。local 表示用户中心自身；github、google 等第三方也作为 provider 配置在本表。';

COMMENT ON COLUMN identity_providers.id IS
'Provider 主键，uuid v7。';

COMMENT ON COLUMN identity_providers.code IS
'Provider 编码，全局唯一。示例：local、github、google。使用 citext。';

COMMENT ON COLUMN identity_providers.name IS
'Provider 展示名称。';

COMMENT ON COLUMN identity_providers.kind IS
'Provider 类型：local=本地用户中心；oauth2=普通 OAuth2；oidc=OpenID Connect。';

COMMENT ON COLUMN identity_providers.issuer IS
'签发者标识。local 和 oidc provider 必填，用于 JWT iss；oauth2 provider 可选。';

COMMENT ON COLUMN identity_providers.authorization_endpoint IS
'授权端点。local 可填写用户中心自己的 /oauth2/authorize；GitHub/Google 填第三方授权地址。';

COMMENT ON COLUMN identity_providers.token_endpoint IS
'Token 端点。local 可填写用户中心自己的 /oauth2/token；GitHub/Google 填第三方 token 地址。';

COMMENT ON COLUMN identity_providers.userinfo_endpoint IS
'UserInfo 端点。OIDC provider 通常使用；GitHub 可配置其用户信息 API。';

COMMENT ON COLUMN identity_providers.jwks_uri IS
'JWKS 地址。local 可填写用户中心自己的 /oauth2/jwks；Google OIDC 可填写其 JWKS 地址。';

COMMENT ON COLUMN identity_providers.end_session_endpoint IS
'OIDC end_session_endpoint 端点。用于 RP-initiated logout 流程。Google、Keycloak 等支持此端点。';

COMMENT ON COLUMN identity_providers.client_id IS
'连接第三方 provider 时使用的 client_id。local provider 通常为空。';

COMMENT ON COLUMN identity_providers.client_secret_enc IS
'连接第三方 provider 时使用的 client_secret，使用 pgp_sym_encrypt 加密存储。密钥由 DatabaseConfig 通过 app.encrypt_key 注入。';

COMMENT ON COLUMN identity_providers.scopes IS
'请求第三方 provider 时默认申请的 scopes。';

COMMENT ON COLUMN identity_providers.settings IS
'Provider 扩展配置。local 可放 signing_alg、default_scopes、password_policy、allow_password_login 等配置。';

COMMENT ON COLUMN identity_providers.enabled IS
'是否启用该 provider。';


-- ============================================================
-- 5. identity_provider_keys
-- ============================================================

CREATE TABLE identity_provider_keys (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    provider_id uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,

    kid citext NOT NULL,
    use key_use NOT NULL DEFAULT 'sig',
    algorithm key_algorithm NOT NULL DEFAULT 'RS256',

    public_key_pem text NOT NULL,
    private_key_pem_enc text NULL,
    certificate_pem text NULL,

    active boolean NOT NULL DEFAULT false,

    not_before timestamptz NULL,
    expires_at timestamptz NULL,
    revoked_at timestamptz NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_identity_provider_keys_time_order
        CHECK (expires_at IS NULL OR not_before IS NULL OR expires_at > not_before)
);

CREATE UNIQUE INDEX ux_identity_provider_keys_provider_kid
ON identity_provider_keys (provider_id, kid);

CREATE UNIQUE INDEX ux_identity_provider_keys_active_signing
ON identity_provider_keys (provider_id)
WHERE active = true AND use = 'sig' AND revoked_at IS NULL;

CREATE INDEX ix_identity_provider_keys_provider_id
ON identity_provider_keys (provider_id);

CREATE INDEX ix_identity_provider_keys_active
ON identity_provider_keys (active);

COMMENT ON TABLE identity_provider_keys IS
'Provider 密钥表。第一阶段主要用于 local provider 的 JWT 签名和 JWKS 暴露。私钥使用 pgp_sym_encrypt 加密存储，密钥由 DatabaseConfig 通过 app.encrypt_key 注入。';

COMMENT ON COLUMN identity_provider_keys.id IS
'密钥主键，uuid v7。';

COMMENT ON COLUMN identity_provider_keys.provider_id IS
'所属 provider。通常指向 code=local 的 provider。';

COMMENT ON COLUMN identity_provider_keys.kid IS
'Key ID。写入 JWT header，用于子应用或 JWKS 客户端选择验证公钥。';

COMMENT ON COLUMN identity_provider_keys.use IS
'密钥用途。sig=签名；enc=加密。第一阶段主要使用 sig。';

COMMENT ON COLUMN identity_provider_keys.algorithm IS
'JWT 签名算法，例如 RS256。';

COMMENT ON COLUMN identity_provider_keys.public_key_pem IS
'公钥 PEM。用于 JWKS 暴露和子应用验证 JWT。明文保存。';

COMMENT ON COLUMN identity_provider_keys.private_key_pem_enc IS
'私钥 PEM 加密密文。local provider 签发 JWT 时使用 pgp_sym_decrypt 解密。密钥由 DatabaseConfig 通过 app.encrypt_key 注入。';

COMMENT ON COLUMN identity_provider_keys.certificate_pem IS
'证书 PEM，可选。没有证书链时可以为空。';

COMMENT ON COLUMN identity_provider_keys.active IS
'是否为当前签名用活跃密钥。同一 provider 同一时间只允许一个 active signing key。';

COMMENT ON COLUMN identity_provider_keys.not_before IS
'密钥生效时间。为空表示立即可用。';

COMMENT ON COLUMN identity_provider_keys.expires_at IS
'密钥过期时间。过期后不应用于新 token 签名，但历史 token 验证可按业务策略保留。';

COMMENT ON COLUMN identity_provider_keys.revoked_at IS
'密钥吊销时间。吊销后不应再用于签名或验证。';


-- ============================================================
-- 6. identities
-- ============================================================

CREATE TABLE identities (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id uuid NOT NULL REFERENCES identity_providers(id) ON DELETE RESTRICT,

    kind identity_kind NOT NULL,

    subject text NOT NULL,

    password_hash text NULL,
    password_algorithm text NULL,
    password_updated_at timestamptz NULL,

    profile jsonb NOT NULL DEFAULT '{}'::jsonb,

    last_login_at timestamptz NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    unbound_at timestamptz NULL,

    CONSTRAINT ck_identities_password_shape
        CHECK (
            (
                kind = 'password'
                AND password_hash IS NOT NULL
                AND password_algorithm IS NOT NULL
            )
            OR
            (
                kind = 'oauth'
                AND password_hash IS NULL
                AND password_algorithm IS NULL
            )
        )
);

CREATE UNIQUE INDEX ux_identities_provider_subject_bound
ON identities (provider_id, subject)
WHERE unbound_at IS NULL;

CREATE UNIQUE INDEX ux_identities_one_password_per_provider
ON identities (user_id, provider_id)
WHERE kind = 'password' AND unbound_at IS NULL;

CREATE UNIQUE INDEX ux_identities_one_oauth_per_provider
ON identities (user_id, provider_id)
WHERE kind = 'oauth' AND unbound_at IS NULL;

CREATE INDEX ix_identities_user_id
ON identities (user_id);

CREATE INDEX ix_identities_provider_id
ON identities (provider_id);

CREATE INDEX ix_identities_kind
ON identities (kind);

COMMENT ON TABLE identities IS
'登录身份表。只支持 password 和 oauth 两类身份。不保存 username、email、phone、totp。';

COMMENT ON COLUMN identities.id IS
'身份主键，uuid v7。';

COMMENT ON COLUMN identities.user_id IS
'绑定的本地用户 ID。';

COMMENT ON COLUMN identities.provider_id IS
'身份提供方 ID。password 通常对应 local provider；oauth 对应 github、google 等 provider。';

COMMENT ON COLUMN identities.kind IS
'身份类型：password 或 oauth。第一阶段不设计 totp。';

COMMENT ON COLUMN identities.subject IS
'身份主体。password 身份建议使用 user_id 字符串；oauth 身份使用第三方平台返回的稳定唯一 ID，例如 Google sub 或 GitHub id。';

COMMENT ON COLUMN identities.password_hash IS
'密码哈希。仅 kind=password 时存在。';

COMMENT ON COLUMN identities.password_algorithm IS
'密码哈希算法标识，例如 argon2id、bcrypt。仅 kind=password 时存在。';

COMMENT ON COLUMN identities.password_updated_at IS
'密码最近更新时间。';

COMMENT ON COLUMN identities.profile IS
'OAuth profile 的快照，可保存第三方昵称、头像等非登录唯一标识信息；不作为绑定唯一依据。';

COMMENT ON COLUMN identities.last_login_at IS
'该身份最近一次登录时间。';

COMMENT ON COLUMN identities.unbound_at IS
'解绑时间。为空表示当前仍处于绑定状态。';

COMMENT ON INDEX ux_identities_provider_subject_bound IS
'防止同一个第三方账号同时绑定多个 user。provider_id + subject 在未解绑状态下唯一。';

COMMENT ON INDEX ux_identities_one_password_per_provider IS
'同一用户在同一 local provider 下只允许一个当前有效 password 身份。';

COMMENT ON INDEX ux_identities_one_oauth_per_provider IS
'同一用户在同一 OAuth provider 下只允许一个当前有效 OAuth 身份。';


-- ============================================================
-- 7. authorization_requests
-- ============================================================

CREATE TABLE authorization_requests (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,

    redirect_uri text NOT NULL,
    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],

    client_state text NULL,
    nonce text NULL,

    code_challenge text NULL,
    code_challenge_method code_challenge_method NULL,

    prompt text NULL,
    max_age bigint NULL CHECK (max_age >= 0),
    login_hint citext NULL,

    authorized_user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    completed_at timestamptz NULL,

    CONSTRAINT ck_authorization_requests_expiry
        CHECK (expires_at > created_at)
);

CREATE INDEX ix_authorization_requests_client_id
ON authorization_requests (client_id);

CREATE INDEX ix_authorization_requests_app_id
ON authorization_requests (app_id);

CREATE INDEX ix_authorization_requests_expires_at
ON authorization_requests (expires_at);

CREATE INDEX ix_authorization_requests_cleanup
ON authorization_requests (expires_at, completed_at);

COMMENT ON TABLE authorization_requests IS
'SSO /oauth2/authorize 请求上下文表。用于在用户登录、第三方跳转、授权码生成之间保留原始请求信息。';

COMMENT ON COLUMN authorization_requests.id IS
'授权请求 ID，uuid v7。';

COMMENT ON COLUMN authorization_requests.client_id IS
'发起授权请求的 OAuth Client 内部 ID。';

COMMENT ON COLUMN authorization_requests.app_id IS
'目标子应用 ID。冗余保存是为了查询和校验方便。';

COMMENT ON COLUMN authorization_requests.redirect_uri IS
'本次请求使用的回调地址，必须来自 oauth_clients.redirect_uris 白名单。';

COMMENT ON COLUMN authorization_requests.scopes IS
'本次请求申请的 scopes。';

COMMENT ON COLUMN authorization_requests.client_state IS
'子应用传入的 state。用户中心只保存并原样回传，不应解析其业务含义。';

COMMENT ON COLUMN authorization_requests.nonce IS
'OIDC nonce，用于 ID Token 防重放。';

COMMENT ON COLUMN authorization_requests.code_challenge IS
'PKCE code challenge。';

COMMENT ON COLUMN authorization_requests.code_challenge_method IS
'PKCE 方法：plain 或 S256。建议只允许 S256。';

COMMENT ON COLUMN authorization_requests.prompt IS
'OIDC prompt 参数，可用于强制登录、选择账号等。第一阶段可选。';

COMMENT ON COLUMN authorization_requests.login_hint IS
'登录提示，例如用户邮箱。仅作为 UI 提示，不作为身份唯一依据。';

COMMENT ON COLUMN authorization_requests.authorized_user_id IS
'完成授权的用户 ID。用户认证成功后写入，用于审计追溯。';

COMMENT ON COLUMN authorization_requests.expires_at IS
'授权请求上下文过期时间，建议 5-10 分钟。';

COMMENT ON COLUMN authorization_requests.completed_at IS
'请求完成时间。生成授权码后可写入。';

COMMENT ON INDEX ix_authorization_requests_cleanup IS
'用于定时清理过期且未完成的授权请求。';


-- ============================================================
-- 8. sso_sessions
-- ============================================================

CREATE TABLE sso_sessions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    token_hash text NOT NULL,

    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_id uuid NULL REFERENCES identities(id) ON DELETE SET NULL,
    provider_id uuid NULL REFERENCES identity_providers(id) ON DELETE SET NULL,

    ip inet NULL,
    user_agent text NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    authenticated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    revoke_reason text NULL,

    CONSTRAINT ck_sso_sessions_expiry
        CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX ux_sso_sessions_token_hash
ON sso_sessions (token_hash);

CREATE INDEX ix_sso_sessions_user_id
ON sso_sessions (user_id);

CREATE INDEX ix_sso_sessions_user_active
ON sso_sessions (user_id, revoked_at);

CREATE INDEX ix_sso_sessions_expires_at
ON sso_sessions (expires_at);

COMMENT ON TABLE sso_sessions IS
'用户中心 SSO 登录态表。浏览器 Cookie 中保存不透明 session token，数据库只保存 token_hash。';

COMMENT ON COLUMN sso_sessions.id IS
'SSO session 主键，uuid v7。';

COMMENT ON COLUMN sso_sessions.token_hash IS
'SSO session token 的哈希。Cookie 中不应直接使用数据库 ID。';

COMMENT ON COLUMN sso_sessions.user_id IS
'当前登录用户。';

COMMENT ON COLUMN sso_sessions.identity_id IS
'本次登录使用的身份。可能是 password 身份，也可能是 GitHub / Google OAuth 身份。';

COMMENT ON COLUMN sso_sessions.provider_id IS
'本次登录使用的 provider。冗余保存便于快速判断登录来源。';

COMMENT ON COLUMN sso_sessions.ip IS
'登录或最近活动 IP。';

COMMENT ON COLUMN sso_sessions.user_agent IS
'浏览器 User-Agent。';

COMMENT ON COLUMN sso_sessions.created_at IS
'会话创建时间。';

COMMENT ON COLUMN sso_sessions.last_seen_at IS
'最近活跃时间。';

COMMENT ON COLUMN sso_sessions.expires_at IS
'会话过期时间。';

COMMENT ON COLUMN sso_sessions.revoked_at IS
'会话撤销时间。用户退出、被踢下线、风险控制时写入。';

COMMENT ON COLUMN sso_sessions.revoke_reason IS
'会话撤销原因。';

COMMENT ON INDEX ix_sso_sessions_user_active IS
'查询用户所有有效会话（revoked_at IS NULL）及按撤销状态过滤。';


-- ============================================================
-- 9. authorization_codes
-- ============================================================

CREATE TABLE authorization_codes (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    code_hash text NOT NULL,

    authorization_request_id uuid NULL REFERENCES authorization_requests(id) ON DELETE SET NULL,

    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    session_id uuid NULL REFERENCES sso_sessions(id) ON DELETE SET NULL,

    redirect_uri text NOT NULL,
    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],

    nonce text NULL,

    code_challenge text NULL,
    code_challenge_method code_challenge_method NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,

    CONSTRAINT ck_authorization_codes_expiry
        CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX ux_authorization_codes_code_hash
ON authorization_codes (code_hash);

CREATE INDEX ix_authorization_codes_user_id
ON authorization_codes (user_id);

CREATE INDEX ix_authorization_codes_client_id
ON authorization_codes (client_id);

CREATE INDEX ix_authorization_codes_session_id
ON authorization_codes (session_id);

CREATE INDEX ix_authorization_codes_expires_at
ON authorization_codes (expires_at);

COMMENT ON TABLE authorization_codes IS
'SSO 授权码表。授权码只保存哈希，不保存明文。授权码短有效期且只能消费一次。';

COMMENT ON COLUMN authorization_codes.id IS
'授权码记录主键，uuid v7。';

COMMENT ON COLUMN authorization_codes.code_hash IS
'授权码哈希。真实 code 只返回给子应用，不落库。';

COMMENT ON COLUMN authorization_codes.authorization_request_id IS
'对应的 authorize 请求上下文。';

COMMENT ON COLUMN authorization_codes.user_id IS
'授权码对应的用户。';

COMMENT ON COLUMN authorization_codes.app_id IS
'授权码对应的目标应用。';

COMMENT ON COLUMN authorization_codes.client_id IS
'授权码对应的 OAuth Client 内部 ID。';

COMMENT ON COLUMN authorization_codes.session_id IS
'生成该授权码时使用的 SSO 会话。';

COMMENT ON COLUMN authorization_codes.redirect_uri IS
'授权码绑定的 redirect_uri。token 请求时必须完全一致。';

COMMENT ON COLUMN authorization_codes.scopes IS
'授权码批准的 scopes。';

COMMENT ON COLUMN authorization_codes.nonce IS
'OIDC nonce。签发 ID Token 时写入。';

COMMENT ON COLUMN authorization_codes.code_challenge IS
'PKCE code challenge。';

COMMENT ON COLUMN authorization_codes.code_challenge_method IS
'PKCE 方法。建议只允许 S256。';

COMMENT ON COLUMN authorization_codes.expires_at IS
'授权码过期时间，建议 3-5 分钟。';

COMMENT ON COLUMN authorization_codes.consumed_at IS
'授权码消费时间。非空表示已经换过 token，不能再次使用。';


-- ============================================================
-- 10. refresh_tokens
-- ============================================================

CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    token_hash text NOT NULL,

    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    session_id uuid NULL REFERENCES sso_sessions(id) ON DELETE SET NULL,

    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],

    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,

    revoked_at timestamptz NULL,
    revoke_reason text NULL,

    replaced_by_id uuid NULL,

    CONSTRAINT ck_refresh_tokens_expiry
        CHECK (expires_at > created_at)
);

ALTER TABLE refresh_tokens
ADD CONSTRAINT fk_refresh_tokens_replaced_by
FOREIGN KEY (replaced_by_id)
REFERENCES refresh_tokens(id)
ON DELETE SET NULL;

CREATE UNIQUE INDEX ux_refresh_tokens_token_hash
ON refresh_tokens (token_hash);

CREATE INDEX ix_refresh_tokens_user_id
ON refresh_tokens (user_id);

CREATE INDEX ix_refresh_tokens_user_active
ON refresh_tokens (user_id, revoked_at);

CREATE INDEX ix_refresh_tokens_client_id
ON refresh_tokens (client_id);

CREATE INDEX ix_refresh_tokens_session_id
ON refresh_tokens (session_id);

CREATE INDEX ix_refresh_tokens_expires_at
ON refresh_tokens (expires_at);

COMMENT ON TABLE refresh_tokens IS
'Refresh Token 表。Access Token / ID Token 建议使用 JWT 不落库；Refresh Token 需要落库以支持撤销、轮换、单应用退出和全端退出。';

COMMENT ON COLUMN refresh_tokens.id IS
'Refresh Token 记录主键，uuid v7。';

COMMENT ON COLUMN refresh_tokens.token_hash IS
'Refresh Token 哈希。真实 refresh token 不落库。';

COMMENT ON COLUMN refresh_tokens.user_id IS
'Refresh Token 对应的用户。';

COMMENT ON COLUMN refresh_tokens.app_id IS
'Refresh Token 对应的目标应用。';

COMMENT ON COLUMN refresh_tokens.client_id IS
'Refresh Token 对应的 OAuth Client 内部 ID。';

COMMENT ON COLUMN refresh_tokens.session_id IS
'Refresh Token 来源 SSO 会话。';

COMMENT ON COLUMN refresh_tokens.scopes IS
'Refresh Token 可续期的 scopes。';

COMMENT ON COLUMN refresh_tokens.expires_at IS
'Refresh Token 过期时间。';

COMMENT ON COLUMN refresh_tokens.revoked_at IS
'Refresh Token 撤销时间。';

COMMENT ON COLUMN refresh_tokens.revoke_reason IS
'撤销原因，例如 logout、rotation、risk_control。';

COMMENT ON COLUMN refresh_tokens.replaced_by_id IS
'Refresh Token 轮换后的新 token 记录 ID。应用层必须校验新 token 属于同一 user 和 client。';


-- ============================================================
-- 11. user_consents
-- ============================================================

CREATE TABLE user_consents (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,

    scopes text[] NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, client_id)
);

COMMENT ON TABLE user_consents IS
'用户对 OAuth Client 的 scope 授权同意记录。首次同意后后续 authorize 可跳过同意页。';

COMMENT ON COLUMN user_consents.user_id IS
'用户 ID。';

COMMENT ON COLUMN user_consents.client_id IS
'OAuth Client 内部 ID。';

COMMENT ON COLUMN user_consents.scopes IS
'用户同意授权的 scopes。每次重新同意时更新。';

COMMENT ON COLUMN user_consents.granted_at IS
'最近一次同意时间。';


-- ============================================================
-- 12. user_app_access
-- ============================================================

CREATE TABLE user_app_access (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,

    status common_status NOT NULL DEFAULT 'active',
    token_version bigint NOT NULL DEFAULT 0,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, app_id)
);

CREATE INDEX ix_user_app_access_app_id
ON user_app_access (app_id);

CREATE INDEX ix_user_app_access_status
ON user_app_access (status);

COMMENT ON COLUMN user_app_access.token_version IS
'用户应用授权版本，撤销时递增，重新授权不重置。';

COMMENT ON TABLE user_app_access IS
'用户与子应用访问关系表。使用 (user_id, app_id) 作为自然主键。';

COMMENT ON COLUMN user_app_access.user_id IS
'用户 ID。';

COMMENT ON COLUMN user_app_access.app_id IS
'应用 ID。';

COMMENT ON COLUMN user_app_access.status IS
'访问状态。active=允许访问；disabled=禁止访问。';

COMMENT ON COLUMN user_app_access.created_at IS
'创建时间。';

COMMENT ON COLUMN user_app_access.updated_at IS
'更新时间，由应用层维护。';


-- ============================================================
-- 13. contact_change_requests
-- ============================================================

CREATE TABLE contact_change_requests (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    change_type contact_change_type NOT NULL,
    new_value text NOT NULL,

    status contact_change_status NOT NULL DEFAULT 'pending',

    verification_code_hash text NOT NULL,
    nonce text NOT NULL,

    requested_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    verified_at timestamptz NULL,
    cancelled_at timestamptz NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ck_contact_change_requests_expiry
        CHECK (expires_at > requested_at),

    CONSTRAINT ck_contact_change_requests_verified_time
        CHECK (status <> 'verified' OR verified_at IS NOT NULL),

    CONSTRAINT ck_contact_change_requests_cancelled_time
        CHECK (status <> 'cancelled' OR cancelled_at IS NOT NULL)
);

CREATE UNIQUE INDEX ux_contact_change_user_type_value
ON contact_change_requests (user_id, change_type, new_value);

CREATE UNIQUE INDEX ux_contact_change_one_pending_per_type
ON contact_change_requests (user_id, change_type)
WHERE status = 'pending';

CREATE UNIQUE INDEX ux_contact_change_nonce
ON contact_change_requests (nonce);

CREATE UNIQUE INDEX ux_contact_change_value_pending
ON contact_change_requests (change_type, new_value)
WHERE status = 'pending';

CREATE INDEX ix_contact_change_requests_user_id
ON contact_change_requests (user_id);

CREATE INDEX ix_contact_change_requests_status
ON contact_change_requests (status);

CREATE INDEX ix_contact_change_requests_expires_at
ON contact_change_requests (expires_at);

COMMENT ON TABLE contact_change_requests IS
'邮箱或手机号变更申请表。只保留最新有效申请，不设计 user_contacts。';

COMMENT ON COLUMN contact_change_requests.id IS
'变更申请主键，uuid v7。';

COMMENT ON COLUMN contact_change_requests.user_id IS
'申请变更联系方式的用户。';

COMMENT ON COLUMN contact_change_requests.change_type IS
'变更类型：email 或 phone。';

COMMENT ON COLUMN contact_change_requests.new_value IS
'申请变更的新邮箱或新手机号。使用 text 类型，应用层负责格式校验（手机号建议 E.164）。';

COMMENT ON COLUMN contact_change_requests.status IS
'申请状态：pending=待验证；verified=已验证；cancelled=已取消；expired=已过期。';

COMMENT ON COLUMN contact_change_requests.verification_code_hash IS
'验证码哈希。验证码明文不落库。';

COMMENT ON COLUMN contact_change_requests.requested_at IS
'申请时间。重复申请同一个值时可刷新该时间。';

COMMENT ON COLUMN contact_change_requests.expires_at IS
'验证码或申请过期时间。';

COMMENT ON COLUMN contact_change_requests.verified_at IS
'验证成功时间。status=verified 时必须存在。';

COMMENT ON COLUMN contact_change_requests.cancelled_at IS
'取消时间。status=cancelled 时必须存在。';

COMMENT ON INDEX ux_contact_change_user_type_value IS
'同一用户、同一变更类型、同一新值只保留一条记录；重复申请同一个值时应更新现有记录。';

COMMENT ON INDEX ux_contact_change_one_pending_per_type IS
'同一用户同一变更类型只允许一个 pending 申请，用于保证只保留最新待验证申请。';

COMMENT ON INDEX ux_contact_change_value_pending IS
'同一个新邮箱或新手机号在 pending 状态下全局唯一；已验证值由 users 表的 email/phone 唯一索引约束。';


-- ============================================================
-- 14. password_reset_tokens
-- ============================================================

CREATE TABLE password_reset_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token_hash text NOT NULL,

    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,

    CONSTRAINT ck_password_reset_tokens_expiry
        CHECK (expires_at > issued_at)
);

CREATE UNIQUE INDEX ux_password_reset_tokens_hash
ON password_reset_tokens (token_hash);

CREATE INDEX ix_password_reset_tokens_user_id
ON password_reset_tokens (user_id);

CREATE INDEX ix_password_reset_tokens_expires_at
ON password_reset_tokens (expires_at);

CREATE INDEX ix_password_reset_tokens_consumed_at
ON password_reset_tokens (consumed_at)
WHERE consumed_at IS NOT NULL;

COMMENT ON TABLE password_reset_tokens IS
'密码重置 token 消费表。token 明文不落库，只保存 hash；提交重置时事务内一次性标记 consumed，防重放。';

COMMENT ON COLUMN password_reset_tokens.token_hash IS
'password reset JWT 的 SHA-256 哈希。';

COMMENT ON COLUMN password_reset_tokens.consumed_at IS
'消费时间。非空表示 token 已使用，不能再次重置密码。';


-- ============================================================
-- 15. login_events
-- ============================================================

CREATE TABLE login_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),

    user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    identity_id uuid NULL REFERENCES identities(id) ON DELETE SET NULL,
    provider_id uuid NULL REFERENCES identity_providers(id) ON DELETE SET NULL,

    event_type login_event_type NOT NULL,

    ip inet NULL,
    user_agent text NULL,

    detail jsonb NOT NULL DEFAULT '{}'::jsonb,

    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_login_events_user_id
ON login_events (user_id);

CREATE INDEX ix_login_events_created_at
ON login_events (created_at);

CREATE INDEX ix_login_events_type
ON login_events (event_type);

COMMENT ON TABLE login_events IS
'登录事件审计表。记录所有登录成功、失败和登出事件，用于安全监控和审计追溯。';

COMMENT ON COLUMN login_events.id IS
'事件主键，uuid v7。';

COMMENT ON COLUMN login_events.user_id IS
'关联用户 ID。登录失败时可能为空（用户不存在或输入错误）。ON DELETE SET NULL 保留历史记录。';

COMMENT ON COLUMN login_events.identity_id IS
'关联身份 ID。记录本次登录使用的具体身份。';

COMMENT ON COLUMN login_events.provider_id IS
'关联 provider ID。记录登录使用的身份提供方。';

COMMENT ON COLUMN login_events.event_type IS
'事件类型：login_success=登录成功；login_failure=登录失败；logout=登出。';

COMMENT ON COLUMN login_events.ip IS
'事件发生时的客户端 IP。';

COMMENT ON COLUMN login_events.user_agent IS
'事件发生时的浏览器 User-Agent。';

COMMENT ON COLUMN login_events.detail IS
'事件详情。可记录失败原因（wrong_password、account_locked、provider_error 等）、登录方式等扩展信息。';

COMMENT ON COLUMN login_events.created_at IS
'事件发生时间。';

-- 数据初始化
INSERT INTO apps (id, code, name, type, status, auto_access, system, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    'user-center',
    '用户中心',
    'web',
    'active',
    false,
    true,
    now(),
    now()
) ON CONFLICT (code) DO UPDATE SET system = true;

-- Durable, encrypted notification delivery.
CREATE TABLE notification_outbox (
    id uuid PRIMARY KEY,
    payload_enc bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL,
    lease_id uuid NULL,
    leased_until timestamptz NULL
);
CREATE INDEX ix_notification_outbox_due ON notification_outbox (next_attempt_at);
CREATE INDEX ix_notification_outbox_user ON notification_outbox (user_id);
CREATE INDEX ix_notification_outbox_expiry ON notification_outbox (expires_at);
