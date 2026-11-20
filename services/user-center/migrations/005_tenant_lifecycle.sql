-- Decouple creation quotas from organization operations; preserve organization identity on closure.
ALTER TABLE tenants DROP CONSTRAINT tenants_status_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_status_check CHECK (status IN ('active','disabled','deleted'));
-- Deleted organizations keep their IDs for downstream synchronization, but release their slug.
COMMENT ON COLUMN tenants.status IS 'deleted is an irreversible tombstone; existing references remain valid for history.';
