# Application device session limits

Application settings use `max_sessions`: 0 disables the count limit, 1 is the default, and positive N allows up to N logical devices for each user in that application. A device is a global SSO browser session, not a hardware identifier. Clients and tenant contexts within a device share its application-level quota.

The authorization flow asks for consent when taking over a full quota or returning to a revoked device. Silent authorization cannot take over. Admission happens in the authorization-code exchange transaction. New admitted devices evict the oldest active devices; lowering the limit keeps the newest devices. Revocation affects the application device and its child client sessions, not unrelated SSO applications.

Clients must use the RP-specific `sid` in access and ID tokens. Resource servers requiring immediate logout must use online token validation/introspection; local JWT signature validation alone cannot detect early revocation. Back-channel logout uses the RP session ID; refresh tokens attached to revoked sessions are rejected.

Account security and administrator session pages support application-specific device revocation in addition to global session revocation.

The schema changes are included in the initial migration as requested. An existing installation is not migrated; provision a fresh database for this schema. Do not apply the changed initial migration to an existing production database or bypass migration checksum validation.

Application sessions intentionally share the SSO session lifetime, rather than introducing a second idle timeout or per-request writes. The device list reports logical authenticated sessions, not online presence. The protected built-in user-center application has no quota (`max_sessions = 0`); ordinary applications default to 1.
