-- When an app is disabled or its tenancy policy changes, downstream systems
-- must receive revocation hints for former memberships as well as new ones.
CREATE OR REPLACE FUNCTION enqueue_app_account_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
    SELECT c.id,a.user_id,'sync.requested',c.account_sync_uri
    FROM user_app_access a JOIN oauth_clients c ON c.app_id=a.app_id
    WHERE a.app_id=NEW.id AND c.account_sync_uri IS NOT NULL FOR SHARE OF c;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,a.user_id,m.tenant_id,'tenant.membership.changed',c.account_sync_uri
    FROM user_app_access a
    JOIN tenant_members m ON m.user_id=a.user_id
    JOIN oauth_clients c ON c.app_id=a.app_id
    WHERE a.app_id=NEW.id AND c.status='active'
      AND c.account_sync_uri IS NOT NULL;
    RETURN NEW;
END $$;
