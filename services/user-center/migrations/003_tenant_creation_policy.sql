-- Organization creation policy belongs to the original creator, not a changeable owner role.
ALTER TABLE tenants ADD COLUMN created_by uuid REFERENCES users(id) ON DELETE SET NULL;
UPDATE tenants t SET created_by = (
    SELECT m.user_id FROM tenant_members m
    WHERE m.tenant_id=t.id AND m.role='owner' AND m.status='active'
    ORDER BY m.joined_at,m.user_id LIMIT 1
) WHERE t.kind='organization';
CREATE INDEX ix_tenants_created_by ON tenants(created_by) WHERE kind='organization';

-- Absence of an explicit policy means creation is disabled.
CREATE TABLE tenant_creation_policies (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    max_tenants integer NOT NULL DEFAULT 0 CHECK (max_tenants >= 0),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
