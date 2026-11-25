-- Retire pending admission requests that are no longer eligible for approval.
UPDATE tenant_app_requests r
SET status = 'withdrawn', updated_at = now()
FROM apps a
WHERE r.app_id = a.id AND r.status = 'pending'
  AND (a.system OR a.tenant_mode = 'personal' OR a.organization_access = 'open');
