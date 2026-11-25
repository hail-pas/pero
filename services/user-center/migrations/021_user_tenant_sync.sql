-- Account status also affects historical tenant membership projections.
CREATE INDEX ix_tenant_app_history_user_app
    ON tenant_app_history(user_id,app_id,tenant_id);

CREATE OR REPLACE FUNCTION enqueue_account_sync() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event_kind text;
BEGIN
    IF OLD.deleted_at IS NOT NULL THEN RETURN NEW; END IF;
    event_kind := CASE WHEN NEW.deleted_at IS NOT NULL THEN 'account.deleted'
                       WHEN OLD.status IS DISTINCT FROM NEW.status THEN 'account.status_changed'
                       ELSE 'account.updated' END;
    INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
    SELECT c.id,NEW.id,event_kind,c.account_sync_uri
    FROM user_app_access a JOIN oauth_clients c ON c.app_id=a.app_id
    WHERE a.user_id=NEW.id AND c.account_sync_uri IS NOT NULL FOR SHARE OF c;

    IF (OLD.status,OLD.deleted_at) IS DISTINCT FROM (NEW.status,NEW.deleted_at) THEN
        INSERT INTO account_sync_deliveries(client_id,user_id,tenant_id,kind,endpoint)
        SELECT c.id,NEW.id,h.tenant_id,'tenant.membership.changed',c.account_sync_uri
        FROM tenant_app_history h
        JOIN oauth_clients c ON c.app_id=h.app_id
        JOIN apps app ON app.id=h.app_id
        WHERE h.user_id=NEW.id AND NOT app.system
          AND c.status='active' AND c.account_sync_uri IS NOT NULL;
    END IF;
    RETURN NEW;
END $$;
