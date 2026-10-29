SELECT user_id, app_id, permission FROM admin_app_permissions LIMIT 0;
SELECT user_id, revision, updated_by, updated_at FROM admin_permission_state LIMIT 0;
SELECT user_id, permission FROM admin_permissions LIMIT 0;
SELECT user_id, role FROM admin_roles LIMIT 0;
SELECT id, code, name, type, description, homepage_url, logo_url, status, system, created_at, updated_at FROM apps LIMIT 0;
SELECT details, id, actor_id, actor_username, action, target, ip, user_agent, request_id, outcome, http_status, created_at FROM audit_events LIMIT 0;
SELECT id, code_hash, authorization_request_id, user_id, app_id, client_id, session_id, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, created_at, expires_at, consumed_at FROM authorization_codes LIMIT 0;
SELECT id, client_id, app_id, redirect_uri, scopes, client_state, nonce, code_challenge, code_challenge_method, prompt, max_age, login_hint, authorized_user_id, created_at, expires_at, completed_at, diagnostic_session_id FROM authorization_requests LIMIT 0;
SELECT id, session_id, client_id, user_id, endpoint, created_at, expires_at, next_attempt_at, attempts, lease_id, leased_until, delivered_at, last_error FROM backchannel_logout_deliveries LIMIT 0;
SELECT id, user_id, change_type, new_value, status, verification_code_hash, nonce, requested_at, expires_at, verified_at, cancelled_at, created_at, updated_at FROM contact_change_requests LIMIT 0;
SELECT id, app_id, email, invitation, invited_by, domain_exception, reason, token_hash, status, verified_at, approved_by, approved_at, provider_id, subject, completed_user_id, created_at, expires_at, last_sent_at FROM enrollments LIMIT 0;
SELECT id, user_id, provider_id, kind, subject, password_hash, password_algorithm, password_updated_at, profile, last_login_at, created_at, updated_at, unbound_at FROM identities LIMIT 0;
SELECT activate_at, last_issued_until, id, provider_id, kid, use, algorithm, public_key_pem, private_key_pem_enc, certificate_pem, active, not_before, expires_at, revoked_at, created_at, updated_at FROM identity_provider_keys LIMIT 0;
SELECT id, code, name, kind, issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, end_session_endpoint, client_id, client_secret_enc, scopes, settings, enabled, created_at, updated_at FROM identity_providers LIMIT 0;
SELECT id, user_id, identity_id, provider_id, event_type, ip, user_agent, detail, created_at FROM login_events LIMIT 0;
SELECT id, user_id, kind, channel, recipient, status, attempts, last_error, http_status, created_at, updated_at, enrollment_id FROM notification_deliveries LIMIT 0;
SELECT id, payload_enc, expires_at, next_attempt_at, attempts, user_id, kind, lease_id, leased_until, enrollment_id FROM notification_outbox LIMIT 0;
SELECT account_sync_uri, backchannel_logout_uri, previous_secret_expires_at, previous_secret_hash, id, app_id, identifier, secret_hash, name, type, redirect_uris, post_logout_redirect_uris, scopes, grant_types, require_pkce, access_token_ttl_seconds, refresh_token_ttl_seconds, id_token_ttl_seconds, status, token_version, created_at, updated_at FROM oauth_clients LIMIT 0;
SELECT session_id, client_id, user_id FROM oidc_rp_sessions LIMIT 0;
SELECT id, user_id, token_hash, issued_at, expires_at, consumed_at FROM password_reset_tokens LIMIT 0;
SELECT id, token_hash, user_id, app_id, client_id, session_id, scopes, created_at, expires_at, revoked_at, revoke_reason, replaced_by_id FROM refresh_tokens LIMIT 0;
SELECT id, app_id, mode, domains, approval_required, emergency_stop, version FROM registration_policies LIMIT 0;
SELECT recovery_pending, reauthenticated_at, oidc_reauthenticated_at, mfa_verified_at, mfa_required, id, token_hash, user_id, identity_id, provider_id, ip, user_agent, created_at, authenticated_at, last_seen_at, expires_at, revoked_at, revoke_reason FROM sso_sessions LIMIT 0;
SELECT user_id, app_id, status, token_version, created_at, updated_at FROM user_app_access LIMIT 0;
SELECT user_id, client_id, scopes, granted_at FROM user_consents LIMIT 0;
SELECT assisted_recovery_expires_at, assisted_recovery_hash, user_id, secret_enc, pending_secret_enc, setup_session, enabled, setup_expires_at, last_step, recovery_hashes FROM user_mfa LIMIT 0;
SELECT id, username, email, email_verified_at, phone, phone_verified_at, nickname, avatar_url, status, created_at, updated_at, deleted_at FROM users LIMIT 0;
SELECT id,client_id,user_id,kind,endpoint,created_at,expires_at,next_attempt_at,attempts,lease_id,leased_until,delivered_at,cancelled_at,last_error FROM account_sync_deliveries LIMIT 0;
-- Verify security-sensitive indexes/constraints and durable logout/cancellation hooks.
DO $$
DECLARE object_name text;
BEGIN
    -- Never satisfy application-table checks via a fallback schema on search_path.
    FOREACH object_name IN ARRAY ARRAY[
        'admin_app_permissions', 'admin_permission_state', 'admin_permissions', 'admin_roles',
        'account_sync_deliveries', 'apps', 'audit_events', 'authorization_codes', 'authorization_requests',
        'backchannel_logout_deliveries', 'contact_change_requests', 'enrollments', 'identities',
        'identity_provider_keys', 'identity_providers', 'login_events', 'notification_deliveries',
        'notification_outbox', 'oauth_clients', 'oidc_rp_sessions', 'password_reset_tokens',
        'refresh_tokens', 'registration_policies', 'sso_sessions', 'user_app_access',
        'user_consents', 'user_mfa', 'users'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace=current_schema()::regnamespace
                       AND relname=object_name AND relkind='r') THEN
            RAISE EXCEPTION 'Missing application table in current schema: %', object_name;
        END IF;
    END LOOP;
    FOREACH object_name IN ARRAY ARRAY[
        'ux_users_email_alive', 'ux_users_phone_alive', 'ux_users_username_alive',
        'ux_sso_sessions_token_hash', 'ux_identity_provider_keys_active_signing',
        'ux_refresh_tokens_token_hash', 'ux_contact_change_nonce',
        'ux_contact_change_one_pending_per_type', 'ux_contact_change_value_pending',
        'ux_password_reset_tokens_hash', 'ux_enrollments_invitation'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
                       WHERE c.relnamespace=current_schema()::regnamespace AND c.relname=object_name
                       AND i.indisvalid AND i.indisunique) THEN
            RAISE EXCEPTION 'Missing/invalid security index: %', object_name;
        END IF;
    END LOOP;
    FOREACH object_name IN ARRAY ARRAY['assisted_recovery_pair','ck_previous_client_secret','ck_account_sync_confidential'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE connamespace=current_schema()::regnamespace
                       AND conname=object_name AND convalidated) THEN
            RAISE EXCEPTION 'Missing security constraint: %', object_name;
        END IF;
    END LOOP;
    FOREACH object_name IN ARRAY ARRAY['session_backchannel_logout','app_backchannel_logout',
                                      'client_backchannel_logout','notification_outbox_deleted',
                                      'user_account_sync','membership_account_sync','client_account_sync','app_account_sync'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                       WHERE c.relnamespace=current_schema()::regnamespace AND t.tgname=object_name
                       AND t.tgenabled IN ('O','A')) THEN
            RAISE EXCEPTION 'Missing/disabled security trigger: %', object_name;
        END IF;
    END LOOP;
    IF pgp_sym_decrypt(pgp_sym_encrypt('migration-check','migration-check'),'migration-check') <> 'migration-check' THEN
        RAISE EXCEPTION 'pgcrypto verification failed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM apps WHERE code='user-center' AND system)
       OR NOT EXISTS (SELECT 1 FROM registration_policies WHERE id='00000000-0000-0000-0000-000000000000') THEN
        RAISE EXCEPTION 'Required platform seed data missing';
    END IF;
END $$;
