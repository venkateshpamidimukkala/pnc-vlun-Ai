-- Durable read models for the deterministic local integration placeholders.
-- The payload remains provider-neutral so external Jira/Git providers can replace
-- these records without changing the Operations API contract.
CREATE TABLE IF NOT EXISTS pnc.mvp_read_models (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    record_type text NOT NULL CHECK (record_type IN ('application', 'remediation', 'jira', 'branch', 'pull_request', 'knowledge')),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    modified_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, record_type, id)
);

CREATE INDEX IF NOT EXISTS ix_mvp_read_models_tenant_type
    ON pnc.mvp_read_models (tenant_id, record_type, modified_at DESC);

ALTER TABLE pnc.mvp_read_models ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_mvp_read_models ON pnc.mvp_read_models;
CREATE POLICY tenant_mvp_read_models ON pnc.mvp_read_models
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);