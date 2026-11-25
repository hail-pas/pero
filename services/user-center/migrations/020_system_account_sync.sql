-- System applications are outside the account synchronization boundary.
-- Updating the endpoint also cancels outstanding deliveries via client_account_sync.
UPDATE oauth_clients c
SET account_sync_uri = NULL, updated_at = now()
FROM apps a
WHERE c.app_id = a.id AND a.system AND c.account_sync_uri IS NOT NULL;
