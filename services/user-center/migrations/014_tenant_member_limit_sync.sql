-- Member capacity is part of the tenant directory projection. Notify admitted
-- applications when the platform changes it, without invalidating user tokens.
CREATE OR REPLACE FUNCTION enqueue_tenant_status_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.status, OLD.auth_version, OLD.name, OLD.max_members)
       IS NOT DISTINCT FROM
       (NEW.status, NEW.auth_version, NEW.name, NEW.max_members) THEN
        RETURN NEW;
    END IF;

    INSERT INTO account_sync_deliveries(client_id, user_id, tenant_id, kind, endpoint)
    SELECT c.id, m.user_id, NEW.id, 'tenant.membership.changed', c.account_sync_uri
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
CREATE TRIGGER tenant_status_sync
    AFTER UPDATE OF status, auth_version, name, max_members ON tenants
    FOR EACH ROW
    WHEN ((OLD.status, OLD.auth_version, OLD.name, OLD.max_members)
          IS DISTINCT FROM
          (NEW.status, NEW.auth_version, NEW.name, NEW.max_members))
    EXECUTE FUNCTION enqueue_tenant_status_sync();
