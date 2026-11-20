-- Account-sync notifications describe historical tenant membership state.
-- Keep the tenant ID in the outbox after a tenant is deleted so receivers can
-- query /api/tenants/membership/sync and observe active=false.
ALTER TABLE account_sync_deliveries
    DROP CONSTRAINT account_sync_deliveries_tenant_id_fkey;
COMMENT ON COLUMN account_sync_deliveries.tenant_id IS
    'Tenant identity of a membership change, including deleted tenants; intentionally not a foreign key.';
