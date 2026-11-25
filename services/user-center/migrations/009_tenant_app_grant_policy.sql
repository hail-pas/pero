-- Only restricted organization-capable applications retain explicit organization grants.
-- This prevents stale grants from silently reappearing after a mode/policy change.
DELETE FROM tenant_app_grants g USING apps a
WHERE g.app_id=a.id
  AND (a.organization_access<>'restricted' OR a.tenant_mode='personal');
