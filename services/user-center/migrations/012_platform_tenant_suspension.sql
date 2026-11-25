-- Separate platform enforcement from owner-controlled organization suspension.
ALTER TABLE tenants ADD COLUMN platform_suspended boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN tenants.platform_suspended IS
    'True when platform super administrators suspended the organization; owners cannot reactivate it.';
