-- App access revocation must also invalidate the downstream tenant-member
-- projection. Retain all historical tenants, even if no longer eligible.
CREATE OR REPLACE FUNCTION enqueue_membership_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND OLD.status IS NOT DISTINCT FROM NEW.status THEN
        RETURN NEW;
    END IF;
    INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
    SELECT c.id,NEW.user_id,
           CASE WHEN NEW.status='active' THEN 'membership.granted' ELSE 'membership.revoked' END,
           c.account_sync_uri
    FROM oauth_clients c
    WHERE c.app_id=NEW.app_id AND c.account_sync_uri IS NOT NULL;

    INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
    SELECT c.id,NEW.user_id,m.tenant_id,'tenant.membership.changed',c.account_sync_uri
    FROM oauth_clients c JOIN tenant_members m ON m.user_id=NEW.user_id
    WHERE c.app_id=NEW.app_id AND c.status='active'
      AND c.account_sync_uri IS NOT NULL;
    RETURN NEW;
END $$;
