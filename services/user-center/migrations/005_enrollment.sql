-- Platform defaults and explicit per-application overrides share one policy shape.
CREATE TABLE registration_policies (
    id uuid PRIMARY KEY,
    app_id uuid UNIQUE REFERENCES apps(id) ON DELETE CASCADE,
    mode text NOT NULL CHECK (mode IN ('closed','invite_only','self_service')),
    domains text[] NOT NULL DEFAULT '{}',
    approval_required boolean NOT NULL DEFAULT true,
    emergency_stop boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1,
    CHECK ((app_id IS NULL AND id='00000000-0000-0000-0000-000000000000') OR (app_id IS NOT NULL AND id=app_id))
);
INSERT INTO registration_policies(id,mode) VALUES ('00000000-0000-0000-0000-000000000000','invite_only');
CREATE TABLE enrollments (
    id uuid PRIMARY KEY,
    app_id uuid REFERENCES apps(id) ON DELETE CASCADE,
    email citext NOT NULL,
    invitation boolean NOT NULL DEFAULT false,
    invited_by uuid REFERENCES users(id),
    domain_exception boolean NOT NULL DEFAULT false,
    reason text NOT NULL DEFAULT '',
    token_hash text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'pending_verification' CHECK (status IN ('pending_verification','pending_approval','ready','completed','rejected','revoked','expired')),
    verified_at timestamptz,
    approved_by uuid REFERENCES users(id),
    approved_at timestamptz,
    provider_id uuid REFERENCES identity_providers(id),
    subject text,
    completed_user_id uuid REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_sent_at timestamptz NOT NULL DEFAULT now(),
    CHECK (invitation=(invited_by IS NOT NULL)),
    CHECK (NOT domain_exception OR invitation),
    CHECK ((provider_id IS NULL)=(subject IS NULL))
);
CREATE INDEX ix_enrollments_pending ON enrollments(status,created_at);
CREATE UNIQUE INDEX ux_enrollments_invitation ON enrollments(email,COALESCE(app_id,'00000000-0000-0000-0000-000000000000')) WHERE invitation AND status IN ('pending_verification','pending_approval','ready');
ALTER TABLE notification_outbox ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE notification_outbox ADD COLUMN enrollment_id uuid REFERENCES enrollments(id) ON DELETE CASCADE;
ALTER TABLE notification_deliveries ADD COLUMN enrollment_id uuid REFERENCES enrollments(id) ON DELETE SET NULL;
ALTER TABLE notification_outbox ADD CHECK (num_nonnulls(user_id,enrollment_id)=1);
-- Application admission is governed by registration_policies; remove the competing switch.
ALTER TABLE apps DROP COLUMN auto_access;
