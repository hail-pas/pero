-- Opt-in automatic admission for active organization members; explicit revocation wins.
ALTER TABLE apps ADD COLUMN organization_auto_access boolean NOT NULL DEFAULT false;
ALTER TABLE user_app_access ADD COLUMN admission_origin text NOT NULL DEFAULT 'explicit'
    CONSTRAINT ck_app_admission_origin CHECK (admission_origin IN ('explicit','organization'));

-- Capture only real organization admissions, not unrelated personal workspaces.
CREATE OR REPLACE FUNCTION pero_record_tenant_app_history(
    p_app uuid DEFAULT NULL, p_user uuid DEFAULT NULL, p_tenant uuid DEFAULT NULL
) RETURNS void LANGUAGE sql AS $$
    INSERT INTO tenant_app_history(app_id,tenant_id,user_id)
    SELECT a.app_id,t.id,a.user_id
    FROM user_app_access a
    JOIN apps app ON app.id=a.app_id
    JOIN users u ON u.id=a.user_id
    JOIN tenant_members m ON m.user_id=a.user_id
    JOIN tenants t ON t.id=m.tenant_id
    WHERE (p_app IS NULL OR a.app_id=p_app)
      AND (p_user IS NULL OR a.user_id=p_user)
      AND (p_tenant IS NULL OR t.id=p_tenant)
      AND NOT app.system AND app.status='active' AND a.status='active'
      AND u.status='active' AND u.deleted_at IS NULL
      AND t.status='active' AND m.status='active'
      AND (app.tenant_mode='both' OR app.tenant_mode=t.kind)
      AND (a.admission_origin='explicit' OR (
          a.admission_origin='organization' AND app.organization_auto_access AND t.kind='organization'))
      AND (t.kind='personal' OR app.organization_access='open'
           OR EXISTS (SELECT 1 FROM tenant_app_grants g
                      WHERE g.tenant_id=t.id AND g.app_id=app.id))
    ON CONFLICT DO NOTHING;
$$;
DROP TRIGGER aa_tenant_app_history_access ON user_app_access;
CREATE TRIGGER aa_tenant_app_history_access
    AFTER INSERT OR UPDATE OF status,admission_origin ON user_app_access
    FOR EACH ROW EXECUTE FUNCTION pero_track_tenant_app_history();
DROP TRIGGER aa_tenant_app_history_app ON apps;
CREATE TRIGGER aa_tenant_app_history_app
    AFTER INSERT OR UPDATE OF status,tenant_mode,organization_access,organization_auto_access ON apps
    FOR EACH ROW EXECUTE FUNCTION pero_track_tenant_app_history();

-- Notify downstream projections whenever auto admission or explicit admission changes.
CREATE OR REPLACE FUNCTION enqueue_membership_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND (OLD.status,OLD.admission_origin)
        IS NOT DISTINCT FROM (NEW.status,NEW.admission_origin) THEN
        RETURN NEW;
    END IF;
    INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint)
    SELECT c.id,NEW.user_id,
           CASE WHEN TG_OP='UPDATE' AND OLD.status IS NOT DISTINCT FROM NEW.status
                THEN 'sync.requested'
                WHEN NEW.status='active' THEN 'membership.granted'
                ELSE 'membership.revoked' END,
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

DROP TRIGGER membership_account_sync ON user_app_access;
CREATE TRIGGER membership_account_sync
    AFTER INSERT OR UPDATE OF status,admission_origin ON user_app_access
    FOR EACH ROW EXECUTE FUNCTION enqueue_membership_sync();

DROP TRIGGER app_account_sync ON apps;
CREATE TRIGGER app_account_sync
    AFTER UPDATE OF status,tenant_mode,organization_access,organization_auto_access ON apps
    FOR EACH ROW
    WHEN ((OLD.status,OLD.tenant_mode,OLD.organization_access,OLD.organization_auto_access)
          IS DISTINCT FROM
          (NEW.status,NEW.tenant_mode,NEW.organization_access,NEW.organization_auto_access))
    EXECUTE FUNCTION enqueue_app_account_sync();
