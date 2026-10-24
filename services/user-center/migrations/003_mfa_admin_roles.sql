CREATE TABLE admin_roles (
    user_id uuid PRIMARY KEY REFERENCES users(id),
    role text NOT NULL CHECK (role IN ('super_admin','admin'))
);
INSERT INTO admin_roles(user_id, role)
SELECT a.user_id, 'super_admin' FROM user_app_access a JOIN apps p ON p.id=a.app_id
WHERE p.code='user-center' AND a.status='active';
CREATE TABLE user_mfa (
    user_id uuid PRIMARY KEY REFERENCES users(id),
    secret_enc bytea NOT NULL,
    pending_secret_enc bytea,
    setup_session uuid REFERENCES sso_sessions(id) ON DELETE SET NULL,
    enabled boolean NOT NULL DEFAULT false,
    setup_expires_at timestamptz NOT NULL DEFAULT now() + interval '5 minutes',
    last_step bigint NOT NULL DEFAULT -1,
    recovery_hashes text[] NOT NULL DEFAULT '{}'
);
ALTER TABLE sso_sessions ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;
ALTER TABLE sso_sessions ADD COLUMN mfa_verified_at timestamptz;
ALTER TABLE sso_sessions ADD COLUMN oidc_reauthenticated_at timestamptz;
ALTER TABLE sso_sessions ADD COLUMN reauthenticated_at timestamptz;
ALTER TABLE sso_sessions ADD COLUMN recovery_pending boolean NOT NULL DEFAULT false;
-- Existing sessions must not inherit assurance they never established.
UPDATE sso_sessions SET revoked_at=now(), revoke_reason='security_upgrade' WHERE revoked_at IS NULL;
UPDATE refresh_tokens SET revoked_at=now(), revoke_reason='security_upgrade' WHERE revoked_at IS NULL;
