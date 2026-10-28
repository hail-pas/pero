-- Operational metadata never contains codes, links, raw recipients or gateway bodies.
CREATE TABLE notification_deliveries (
    id uuid PRIMARY KEY,
    user_id uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    kind text NOT NULL,
    channel text NOT NULL,
    recipient text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','retrying','delivered','expired','cancelled')),
    attempts integer NOT NULL DEFAULT 0,
    last_error text NULL,
    http_status integer NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_notification_deliveries_created ON notification_deliveries (created_at DESC, id DESC);
CREATE INDEX ix_notification_deliveries_status ON notification_deliveries (status, created_at DESC);
CREATE INDEX ix_notification_deliveries_cleanup ON notification_deliveries (updated_at) WHERE status IN ('delivered','expired','cancelled');

-- Existing encrypted messages remain deliverable without decrypting them during migration.
INSERT INTO notification_deliveries (id,user_id,kind,channel,recipient,status,attempts)
SELECT id,user_id,kind,'unknown','***',CASE WHEN attempts > 0 THEN 'retrying' ELSE 'queued' END,attempts
FROM notification_outbox;

-- Credential invalidation already deletes queued messages in the same transaction.
-- Capture cancellation here so every existing invalidation path remains authoritative.
CREATE FUNCTION notification_outbox_deleted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE notification_deliveries
    SET status = CASE WHEN OLD.expires_at <= now() THEN 'expired' ELSE 'cancelled' END,
        updated_at = now()
    WHERE id = OLD.id AND status IN ('queued','retrying');
    RETURN OLD;
END;
$$;
CREATE TRIGGER notification_outbox_deleted AFTER DELETE ON notification_outbox
FOR EACH ROW EXECUTE FUNCTION notification_outbox_deleted();
