-- Organization naming and governance role are part of the downstream membership projection.
-- A rename notifies consumers, but does not rotate tenant authorization versions.
CREATE OR REPLACE FUNCTION enqueue_tenant_status_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (OLD.status,OLD.auth_version,OLD.name)
    IS NOT DISTINCT FROM (NEW.status,NEW.auth_version,NEW.name) THEN RETURN NEW; END IF;
 INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
 SELECT c.id,m.user_id,NEW.id,'tenant.membership.changed',c.account_sync_uri
 FROM tenant_members m
 JOIN user_app_access a ON a.user_id=m.user_id AND a.status='active'
 JOIN apps app ON app.id=a.app_id
 JOIN oauth_clients c ON c.app_id=app.id
 WHERE m.tenant_id=NEW.id AND m.status='active'
 AND c.account_sync_uri IS NOT NULL AND c.status='active'
 AND (app.tenant_mode='both' OR app.tenant_mode=NEW.kind);
 RETURN NEW;
END $$;

DROP TRIGGER tenant_status_sync ON tenants;
CREATE TRIGGER tenant_status_sync AFTER UPDATE OF status,auth_version,name ON tenants
FOR EACH ROW WHEN ((OLD.status,OLD.auth_version,OLD.name)
                   IS DISTINCT FROM (NEW.status,NEW.auth_version,NEW.name))
EXECUTE FUNCTION enqueue_tenant_status_sync();
