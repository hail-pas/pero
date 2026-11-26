ALTER TABLE enrollments
    ADD COLUMN requested_user_id uuid REFERENCES users(id),
    ADD COLUMN tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
    ADD COLUMN authorization_session_id uuid REFERENCES sso_sessions(id) ON DELETE SET NULL;
CREATE INDEX ix_enrollments_requested_user ON enrollments(requested_user_id,created_at DESC)
    WHERE requested_user_id IS NOT NULL;
CREATE INDEX ix_enrollments_authorization_session ON enrollments(authorization_session_id)
    WHERE authorization_session_id IS NOT NULL;

ALTER TABLE tenant_invitations ADD COLUMN notification_id uuid;

CREATE FUNCTION cancel_tenant_invitation_notification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM notification_outbox WHERE id=OLD.notification_id;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenant_invitation_notification_cancelled
    AFTER UPDATE OF status ON tenant_invitations
    FOR EACH ROW
    WHEN (OLD.status='pending' AND NEW.status<>'pending' AND OLD.notification_id IS NOT NULL)
    EXECUTE FUNCTION cancel_tenant_invitation_notification();
