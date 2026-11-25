-- Platform-configurable active membership ceiling, independent of creation quotas.
ALTER TABLE tenants ADD COLUMN max_members integer NOT NULL DEFAULT 100
    CONSTRAINT tenants_max_members_check CHECK (max_members BETWEEN 1 AND 100000);
COMMENT ON COLUMN tenants.max_members IS
    'Maximum active memberships, including owners. Lowering the value never evicts existing members.';
