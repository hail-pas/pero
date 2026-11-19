-- C/B tenancy: global users, personal workspaces and organization memberships.
ALTER TABLE apps ADD COLUMN tenant_mode text NOT NULL DEFAULT 'personal'
    CHECK (tenant_mode IN ('personal', 'organization', 'both'));
CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    kind text NOT NULL CHECK (kind IN ('personal','organization')),
    name text NOT NULL,
    slug citext,
    owner_user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    auth_version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_tenant_owner_shape CHECK (
        (kind='personal' AND owner_user_id IS NOT NULL AND slug IS NULL)
        OR (kind='organization' AND owner_user_id IS NULL)
    )
);
CREATE UNIQUE INDEX ux_tenant_personal_owner ON tenants(owner_user_id) WHERE kind='personal';
CREATE UNIQUE INDEX ux_tenant_organization_slug ON tenants(slug) WHERE kind='organization' AND slug IS NOT NULL;
CREATE TABLE tenant_members (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner','admin','member')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','removed')),
    auth_version bigint NOT NULL DEFAULT 0,
    joined_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,user_id)
);
CREATE INDEX ix_tenant_members_user_active ON tenant_members(user_id, tenant_id) WHERE status='active';
CREATE TABLE tenant_invitations (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email citext NOT NULL,
    role text NOT NULL CHECK (role IN ('admin','member')),
    token_hash text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','revoked','expired')),
    invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ux_tenant_invitation_pending ON tenant_invitations(tenant_id,email) WHERE status='pending';
CREATE INDEX ix_tenant_invitation_expiry ON tenant_invitations(expires_at) WHERE status='pending';

-- A personal workspace always exists even when users are provisioned via bootstrap or upstream login.
CREATE FUNCTION pero_create_personal_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tid uuid;
BEGIN
    INSERT INTO tenants(kind,name,owner_user_id) VALUES ('personal',COALESCE(NEW.nickname, NEW.username::text),NEW.id)
        RETURNING id INTO tid;
    INSERT INTO tenant_members(tenant_id,user_id,role) VALUES(tid, NEW.id, 'owner');
    RETURN NEW;
END $$;
CREATE TRIGGER tg_pero_personal_tenant AFTER INSERT ON users
    FOR EACH ROW EXECUTE FUNCTION pero_create_personal_tenant();
INSERT INTO tenants(kind,name,owner_user_id)
SELECT 'personal', COALESCE(nickname,username::text), id FROM users
ON CONFLICT DO NOTHING;
INSERT INTO tenant_members(tenant_id,user_id,role)
SELECT id,owner_user_id,'owner' FROM tenants WHERE kind='personal'
ON CONFLICT DO NOTHING;

ALTER TABLE authorization_requests ADD COLUMN tenant_id uuid REFERENCES tenants(id);
ALTER TABLE authorization_codes ADD COLUMN tenant_id uuid REFERENCES tenants(id);
ALTER TABLE refresh_tokens ADD COLUMN tenant_id uuid REFERENCES tenants(id);
-- Existing pending grants are deliberately invalidated by the new protocol context.
UPDATE authorization_requests SET completed_at=now() WHERE completed_at IS NULL;
UPDATE authorization_codes SET consumed_at=now() WHERE consumed_at IS NULL;
UPDATE refresh_tokens SET revoked_at=now(),revoke_reason='tenant_context_migration' WHERE revoked_at IS NULL;
