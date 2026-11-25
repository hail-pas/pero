-- Organization auto-admission contributes to the account projection as well as
-- the tenant membership projection. Notify both when eligibility changes.
CREATE OR REPLACE FUNCTION enqueue_tenant_membership_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND (OLD.status,OLD.auth_version)
        IS NOT DISTINCT FROM (NEW.status,NEW.auth_version) THEN RETURN NEW; END IF;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,NEW.user_id,NEW.tenant_id,'tenant.membership.changed',c.account_sync_uri
    FROM tenant_app_history h
    JOIN oauth_clients c ON c.app_id=h.app_id
    WHERE h.user_id=NEW.user_id AND h.tenant_id=NEW.tenant_id
      AND c.status='active' AND c.account_sync_uri IS NOT NULL;

    IF TG_OP='INSERT' OR OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
        SELECT c.id,h.user_id,'sync.requested',c.account_sync_uri
        FROM tenant_app_history h
        JOIN tenants t ON t.id=h.tenant_id
        JOIN user_app_access a ON a.app_id=h.app_id AND a.user_id=h.user_id
        JOIN apps app ON app.id=a.app_id
        JOIN oauth_clients c ON c.app_id=a.app_id
        WHERE h.user_id=NEW.user_id AND h.tenant_id=NEW.tenant_id
          AND t.kind='organization' AND a.admission_origin='organization'
          AND a.status='active' AND app.organization_auto_access
          AND c.status='active' AND c.account_sync_uri IS NOT NULL;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enqueue_tenant_status_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.status,OLD.auth_version,OLD.name,OLD.max_members)
        IS NOT DISTINCT FROM
       (NEW.status,NEW.auth_version,NEW.name,NEW.max_members) THEN RETURN NEW; END IF;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,h.user_id,NEW.id,'tenant.membership.changed',c.account_sync_uri
    FROM tenant_app_history h
    JOIN oauth_clients c ON c.app_id=h.app_id
    WHERE h.tenant_id=NEW.id AND c.status='active'
      AND c.account_sync_uri IS NOT NULL;

    -- Organization app-grant changes also advance the tenant authorization epoch.
    IF NEW.kind='organization' AND (OLD.status,OLD.auth_version)
        IS DISTINCT FROM (NEW.status,NEW.auth_version) THEN
        INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
        SELECT c.id,h.user_id,'sync.requested',c.account_sync_uri
        FROM tenant_app_history h
        JOIN user_app_access a ON a.app_id=h.app_id AND a.user_id=h.user_id
        JOIN apps app ON app.id=a.app_id
        JOIN oauth_clients c ON c.app_id=a.app_id
        WHERE h.tenant_id=NEW.id AND a.admission_origin='organization'
          AND a.status='active' AND app.organization_auto_access
          AND c.status='active' AND c.account_sync_uri IS NOT NULL;
    END IF;
    RETURN NEW;
END $$;
