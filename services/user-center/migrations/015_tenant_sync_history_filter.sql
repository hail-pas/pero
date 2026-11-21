-- Emit tenant events only for user/tenant pairs that the receiving app has
-- actually been eligible to access. The history table retains revoked pairs
-- so downstream clients still receive removal and policy-change hints.

CREATE OR REPLACE FUNCTION enqueue_tenant_membership_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND (OLD.status,OLD.auth_version)
        IS NOT DISTINCT FROM (NEW.status,NEW.auth_version) THEN RETURN NEW; END IF;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,NEW.user_id,NEW.tenant_id,'tenant.membership.changed',c.account_sync_uri
    FROM tenant_app_history h
    JOIN user_app_access a ON a.user_id=h.user_id AND a.app_id=h.app_id
    JOIN apps app ON app.id=h.app_id
    JOIN oauth_clients c ON c.app_id=h.app_id
    JOIN tenants t ON t.id=h.tenant_id
    WHERE h.user_id=NEW.user_id AND h.tenant_id=NEW.tenant_id
      AND a.status='active' AND c.status='active' AND c.account_sync_uri IS NOT NULL
      AND (app.tenant_mode='both' OR app.tenant_mode=t.kind);
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
    JOIN tenant_members m ON m.tenant_id=h.tenant_id AND m.user_id=h.user_id
    JOIN user_app_access a ON a.user_id=h.user_id AND a.app_id=h.app_id
    JOIN apps app ON app.id=h.app_id
    JOIN oauth_clients c ON c.app_id=h.app_id
    WHERE h.tenant_id=NEW.id AND m.status='active' AND a.status='active'
      AND c.status='active' AND c.account_sync_uri IS NOT NULL
      AND (app.tenant_mode='both' OR app.tenant_mode=NEW.kind);
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enqueue_membership_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND OLD.status IS NOT DISTINCT FROM NEW.status THEN RETURN NEW; END IF;

    INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
    SELECT c.id,NEW.user_id,
           CASE WHEN NEW.status='active' THEN 'membership.granted' ELSE 'membership.revoked' END,
           c.account_sync_uri
    FROM oauth_clients c
    WHERE c.app_id=NEW.app_id AND c.account_sync_uri IS NOT NULL;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,NEW.user_id,h.tenant_id,'tenant.membership.changed',c.account_sync_uri
    FROM tenant_app_history h
    JOIN oauth_clients c ON c.app_id=h.app_id
    WHERE h.app_id=NEW.app_id AND h.user_id=NEW.user_id
      AND c.status='active' AND c.account_sync_uri IS NOT NULL;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION configure_account_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND (OLD.account_sync_uri,OLD.scopes,OLD.status)
        IS NOT DISTINCT FROM (NEW.account_sync_uri,NEW.scopes,NEW.status) THEN RETURN NEW; END IF;

    UPDATE account_sync_deliveries SET cancelled_at=now(),lease_id=NULL,leased_until=NULL
    WHERE client_id=NEW.id AND delivered_at IS NULL AND cancelled_at IS NULL;

    IF NEW.account_sync_uri IS NOT NULL THEN
        INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
        SELECT NEW.id,a.user_id,'sync.requested',NEW.account_sync_uri
        FROM user_app_access a WHERE a.app_id=NEW.app_id;

        IF NEW.status='active' THEN
            INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
            SELECT NEW.id,h.user_id,h.tenant_id,'tenant.membership.changed',NEW.account_sync_uri
            FROM tenant_app_history h WHERE h.app_id=NEW.app_id;
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION enqueue_app_account_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
    SELECT c.id,a.user_id,'sync.requested',c.account_sync_uri
    FROM user_app_access a JOIN oauth_clients c ON c.app_id=a.app_id
    WHERE a.app_id=NEW.id AND c.account_sync_uri IS NOT NULL FOR SHARE OF c;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,h.user_id,h.tenant_id,'tenant.membership.changed',c.account_sync_uri
    FROM tenant_app_history h JOIN oauth_clients c ON c.app_id=h.app_id
    WHERE h.app_id=NEW.id AND c.status='active' AND c.account_sync_uri IS NOT NULL;
    RETURN NEW;
END $$;
