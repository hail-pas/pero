-- Apps
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL UNIQUE,
    code VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    nickname VARCHAR(64),
    avatar_url TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    phone_verified BOOLEAN NOT NULL DEFAULT false,
    status SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Identities (multi-provider login)
CREATE TABLE IF NOT EXISTS identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_uid VARCHAR(255) NOT NULL DEFAULT '',
    credential TEXT,
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider, provider_uid)
);
CREATE INDEX idx_identities_user_provider ON identities(user_id, provider);

-- User attributes (ABAC subject attributes)
CREATE TABLE IF NOT EXISTS user_attributes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key VARCHAR(128) NOT NULL,
    value TEXT NOT NULL,
    UNIQUE(user_id, key)
);

-- Policies (with app scope)
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,
    effect VARCHAR(16) NOT NULL CHECK (effect IN ('allow', 'deny')),
    priority INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_policies_priority ON policies(priority);
CREATE INDEX idx_policies_app_id ON policies(app_id);

-- Policy conditions
CREATE TABLE IF NOT EXISTS policy_conditions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    condition_type VARCHAR(16) NOT NULL CHECK (condition_type IN ('subject', 'resource', 'action', 'app')),
    key VARCHAR(128) NOT NULL,
    operator VARCHAR(16) NOT NULL CHECK (operator IN ('eq', 'in', 'wildcard', 'regex', 'gt', 'lt', 'contains')),
    value TEXT NOT NULL
);
CREATE INDEX idx_policy_conditions_policy_id ON policy_conditions(policy_id);

-- User-policy association
CREATE TABLE IF NOT EXISTS user_policies (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, policy_id)
);

-- OAuth2 clients
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    client_name VARCHAR(128) NOT NULL,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{"authorization_code"}',
    scopes TEXT[] NOT NULL DEFAULT '{"openid","profile","email"}',
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_oauth2_clients_app_id ON oauth2_clients(app_id);

-- OAuth2 authorization codes
CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
    code VARCHAR(128) PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    code_challenge TEXT,
    nonce TEXT,
    code_challenge_method VARCHAR(16),
    sid TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    auth_time BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_codes_client ON oauth2_authorization_codes(client_id);
CREATE INDEX idx_auth_codes_user_id ON oauth2_authorization_codes(user_id);
CREATE INDEX idx_auth_codes_expires ON oauth2_authorization_codes(expires_at);

-- OAuth2 tokens (refresh tokens)
CREATE TABLE IF NOT EXISTS oauth2_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    auth_time BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tokens_user ON oauth2_tokens(user_id);
CREATE INDEX idx_tokens_client_id ON oauth2_tokens(client_id);
CREATE INDEX idx_tokens_user_client ON oauth2_tokens(user_id, client_id);

-- Social Provider
CREATE TABLE IF NOT EXISTS social_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(32) NOT NULL UNIQUE,
    display_name VARCHAR(64) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret TEXT NOT NULL,
    authorize_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    userinfo_url TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
