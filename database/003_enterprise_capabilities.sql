-- PNC Vuln AI enterprise capability migration.
-- Forward-only and idempotent so it can be applied by CI/CD or a recovery job.
CREATE TABLE IF NOT EXISTS pnc.teams (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    name text NOT NULL, cost_center text, owner_user_id uuid REFERENCES pnc.users(id),
    created_at timestamptz NOT NULL DEFAULT now(), modified_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE TABLE IF NOT EXISTS pnc.repository_scans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    repository_id uuid NOT NULL REFERENCES pnc.repositories(id), provider text NOT NULL, scanner text NOT NULL,
    external_run_id text, status text NOT NULL, findings_count integer NOT NULL DEFAULT 0,
    started_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, raw_artifact_uri text,
    UNIQUE (tenant_id, scanner, external_run_id)
);
CREATE TABLE IF NOT EXISTS pnc.cves (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cve_id text NOT NULL UNIQUE, description text,
    cvss numeric(4,2), exploitability numeric(8,4), published_at timestamptz, exploited_in_wild boolean NOT NULL DEFAULT false,
    source_payload jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS pnc.cwes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cwe_id text NOT NULL UNIQUE, name text NOT NULL, description text
);
CREATE TABLE IF NOT EXISTS pnc.vulnerability_sources (
    vulnerability_id uuid NOT NULL, discovered_at timestamptz NOT NULL, scanner text NOT NULL,
    external_finding_id text NOT NULL, raw_payload jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (vulnerability_id, discovered_at, scanner, external_finding_id)
);
CREATE TABLE IF NOT EXISTS pnc.ai_recommendations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    vulnerability_id uuid NOT NULL, remediation_action_id uuid REFERENCES pnc.remediation_actions(id),
    agent_name text NOT NULL, model_name text, confidence text NOT NULL, recommendation text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}', policy_decision text NOT NULL DEFAULT 'REVIEW', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pnc.branches (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    repository_id uuid NOT NULL REFERENCES pnc.repositories(id), remediation_action_id uuid REFERENCES pnc.remediation_actions(id),
    name text NOT NULL, base_branch text NOT NULL, commit_sha text, status text NOT NULL DEFAULT 'CREATED', created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, repository_id, name)
);
CREATE TABLE IF NOT EXISTS pnc.approval_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    workflow_id uuid NOT NULL REFERENCES pnc.approval_workflows(id), level integer NOT NULL, approver_user_id uuid REFERENCES pnc.users(id),
    decision text NOT NULL, comment text, decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pnc.validation_results (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    remediation_action_id uuid REFERENCES pnc.remediation_actions(id), validation_type text NOT NULL, status text NOT NULL,
    summary text, artifact_uri text, duration_ms integer, completed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pnc.security_scans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    repository_id uuid REFERENCES pnc.repositories(id), pull_request_id uuid REFERENCES pnc.pull_requests(id),
    scanner text NOT NULL, scan_type text NOT NULL, status text NOT NULL, findings_count integer NOT NULL DEFAULT 0,
    artifact_uri text, completed_at timestamptz
);
CREATE TABLE IF NOT EXISTS pnc.notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id),
    recipient_user_id uuid REFERENCES pnc.users(id), channel text NOT NULL, event_type text NOT NULL, payload jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'QUEUED', sent_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pnc.external_tickets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id), provider text NOT NULL,
    external_id text NOT NULL, url text, status text, vulnerability_id uuid, pull_request_id uuid, payload jsonb NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, provider, external_id)
);
CREATE TABLE IF NOT EXISTS pnc.reports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES pnc.tenants(id), report_type text NOT NULL,
    parameters jsonb NOT NULL DEFAULT '{}', status text NOT NULL DEFAULT 'QUEUED', artifact_uri text, requested_by uuid REFERENCES pnc.users(id),
    created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS ix_repository_scans_tenant_repo ON pnc.repository_scans(tenant_id, repository_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_ai_recommendations_tenant_confidence ON pnc.ai_recommendations(tenant_id, confidence, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_validation_results_action ON pnc.validation_results(remediation_action_id, completed_at DESC);
CREATE INDEX IF NOT EXISTS ix_notifications_queue ON pnc.notifications(status, created_at);
CREATE INDEX IF NOT EXISTS ix_reports_tenant_status ON pnc.reports(tenant_id, status, created_at DESC);