-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    status SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User attributes (ABAC subject attributes)
CREATE TABLE IF NOT EXISTS user_attributes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key VARCHAR(128) NOT NULL,
    value TEXT NOT NULL,
    UNIQUE(user_id, key)
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,
    effect VARCHAR(16) NOT NULL CHECK (effect IN ('allow', 'deny')),
    priority INT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Policy conditions
CREATE TABLE IF NOT EXISTS policy_conditions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    condition_type VARCHAR(16) NOT NULL CHECK (condition_type IN ('subject', 'resource', 'action')),
    key VARCHAR(128) NOT NULL,
    operator VARCHAR(16) NOT NULL CHECK (operator IN ('eq', 'in', 'wildcard', 'regex', 'gt', 'lt', 'contains')),
    value TEXT NOT NULL
);

-- User-policy association
CREATE TABLE IF NOT EXISTS user_policies (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, policy_id)
);

-- Indexes
CREATE INDEX idx_user_attributes_user_id ON user_attributes(user_id);
CREATE INDEX idx_policy_conditions_policy_id ON policy_conditions(policy_id);
CREATE INDEX idx_policies_priority ON policies(priority);
