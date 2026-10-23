-- Keep audit metadata independent of mutable/deleted user records. Never store request bodies.
CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    actor_id uuid NOT NULL,
    actor_username text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    ip inet,
    user_agent text,
    request_id text,
    outcome text NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending', 'success', 'failure')),
    http_status integer,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_events_created_at ON audit_events (created_at DESC, id DESC);
CREATE INDEX ix_audit_events_actor ON audit_events (actor_id, created_at DESC);
CREATE INDEX ix_login_events_user_created ON login_events (user_id, created_at DESC, id DESC);
