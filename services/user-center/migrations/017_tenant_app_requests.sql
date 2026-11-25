-- One current application admission request per organization and app.
CREATE TABLE tenant_app_requests (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    requested_by uuid NOT NULL REFERENCES users(id),
    status text NOT NULL CHECK (status IN ('pending','approved','rejected','withdrawn')),
    reviewed_by uuid REFERENCES users(id),
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,app_id)
);
CREATE INDEX ix_tenant_app_requests_pending ON tenant_app_requests(updated_at)
    WHERE status='pending';
