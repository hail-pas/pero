-- A business application may optionally restrict organization admission to explicit grants.
ALTER TABLE apps ADD COLUMN organization_access text NOT NULL DEFAULT 'open'
    CONSTRAINT apps_organization_access_check CHECK (organization_access IN ('open','restricted'));
CREATE TABLE tenant_app_grants (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    app_id uuid NOT NULL REFERENCES apps(id),
    PRIMARY KEY (tenant_id,app_id)
);
CREATE INDEX ix_tenant_app_grants_app ON tenant_app_grants(app_id,tenant_id);

-- Both organization status and authorization epoch changes invalidate cached tenant state.
CREATE OR REPLACE FUNCTION enqueue_tenant_status_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (OLD.status,OLD.auth_version) IS NOT DISTINCT FROM (NEW.status,NEW.auth_version) THEN RETURN NEW; END IF;
 INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
 SELECT c.id,m.user_id,NEW.id,'tenant.membership.changed',c.account_sync_uri
 FROM tenant_members m JOIN user_app_access a ON a.user_id=m.user_id AND a.status='active'
 JOIN apps app ON app.id=a.app_id JOIN oauth_clients c ON c.app_id=app.id
 WHERE m.tenant_id=NEW.id AND m.status='active' AND c.account_sync_uri IS NOT NULL AND c.status='active'
 AND (app.tenant_mode='both' OR app.tenant_mode=NEW.kind);
 RETURN NEW;
END $$;
DROP TRIGGER tenant_status_sync ON tenants;
CREATE TRIGGER tenant_status_sync AFTER UPDATE OF status,auth_version ON tenants
FOR EACH ROW WHEN ((OLD.status,OLD.auth_version) IS DISTINCT FROM (NEW.status,NEW.auth_version))
EXECUTE FUNCTION enqueue_tenant_status_sync();

-- Changing the global app policy also requires downstream re-synchronization.
DROP TRIGGER app_account_sync ON apps;
CREATE TRIGGER app_account_sync AFTER UPDATE OF status,tenant_mode,organization_access ON apps
FOR EACH ROW WHEN ((OLD.status,OLD.tenant_mode,OLD.organization_access) IS DISTINCT FROM
                   (NEW.status,NEW.tenant_mode,NEW.organization_access))
EXECUTE FUNCTION enqueue_app_account_sync();
