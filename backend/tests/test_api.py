from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.auth import DEMO_TENANT_ID, DEMO_USERS
from app.domain import Severity, Vulnerability
from app.main import app, repository


def headers(tenant, user):
    return {"X-Tenant-ID": str(tenant), "X-User-ID": str(user)}


def test_health():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_inventory_requires_identity():
    assert TestClient(app).get("/api/v1/vulnerabilities").status_code == 401


def test_bulk_remediation_is_tenant_scoped_and_approval_gated():
    tenant, user = uuid4(), uuid4()
    repository.seed(Vulnerability(tenant_id=tenant, mnemonic="PME", application="Portal", repository="WebPortal", title="Log4J", category="DEPENDENCY", severity=Severity.CRITICAL, cve="CVE-2021-44228", created_at=datetime.now(timezone.utc)))
    response = TestClient(app).post("/api/v1/remediation/bulk", headers=headers(tenant, user), json={"tenant_id": str(tenant), "scope": "MNEMONIC", "mnemonic": "PME", "cve": "CVE-2021-44228", "requested_by": str(user)})
    assert response.status_code == 202
    assert response.json()["matched_vulnerabilities"] == 1
    assert response.json()["status"] == "AWAITING_APPROVAL"


def test_bulk_scope_requires_selector():
    tenant, user = uuid4(), uuid4()
    response = TestClient(app).post("/api/v1/remediation/bulk", headers=headers(tenant, user), json={"tenant_id": str(tenant), "scope": "MNEMONIC", "requested_by": str(user)})
    assert response.status_code == 422


def test_approval_requires_reviewer_and_updates_local_finding():
    finding = Vulnerability(tenant_id=DEMO_TENANT_ID, mnemonic="PME", application="Portal", repository="WebPortal", title="Cookie flag", category="SAST", severity=Severity.MEDIUM, created_at=datetime.now(timezone.utc))
    repository.seed(finding)
    analyst_id = DEMO_USERS["analyst@pnc.local"]["user_id"]
    reviewer_id = DEMO_USERS["reviewer@pnc.local"]["user_id"]
    denied = TestClient(app).post(f"/api/v1/approvals/{finding.id}/decision", headers=headers(DEMO_TENANT_ID, analyst_id), json={"decision": "APPROVE"})
    assert denied.status_code == 403
    approved = TestClient(app).post(f"/api/v1/approvals/{finding.id}/decision", headers=headers(DEMO_TENANT_ID, reviewer_id), json={"decision": "APPROVE"})
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVE"


def test_engine_workflow_returns_pipeline_evidence_and_is_tenant_scoped():
    client = TestClient(app)
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    created = client.post("/api/v1/engine/workflows", headers=headers(DEMO_TENANT_ID, user), json={"project": "Payments API", "repository_path": "local-demo"})
    assert created.status_code == 202
    body = created.json()
    assert body["status"] == "AWAITING_APPROVAL"
    assert body["evidence"]["classification"]["status"] == "COMPLETED"
    assert body["evidence"]["validation"]["status"] == "PASSED"
    assert len(body["evidence"]["approval"]["required_levels"]) == 3

    other_tenant = client.get(f"/api/v1/engine/workflows/{body['workflow_id']}", headers=headers(uuid4(), user))
    assert other_tenant.status_code == 404


def test_engine_agents_expose_provider_neutral_catalog():
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    response = TestClient(app).get("/api/v1/engine/agents", headers=headers(DEMO_TENANT_ID, user))
    assert response.status_code == 200
    assert {item["name"] for item in response.json()} >= {"classification", "remediation", "validation", "pull_request", "knowledge"}


def test_engine_workflow_rejects_blank_project_and_cross_tenant_findings():
    client = TestClient(app)
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    blank = client.post("/api/v1/engine/workflows", headers=headers(DEMO_TENANT_ID, user), json={"project": "   ", "repository_path": "local-demo"})
    assert blank.status_code == 422

    foreign_finding = Vulnerability(tenant_id=uuid4(), mnemonic="OTHER", application="Other", repository="other", title="Foreign", category="SAST", severity=Severity.LOW)
    repository.seed(foreign_finding)
    response = client.post("/api/v1/engine/workflows", headers=headers(DEMO_TENANT_ID, user), json={"project": "Payments API", "repository_path": "local-demo", "finding_ids": [str(foreign_finding.id)]})
    assert response.status_code == 404


def test_engine_workflows_and_integrations_are_tenant_scoped():
    client = TestClient(app)
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    created = client.post("/api/v1/engine/workflows", headers=headers(DEMO_TENANT_ID, user), json={"project": "Inventory", "repository_path": "local-demo"})
    workflow_id = created.json()["workflow_id"]
    listed = client.get("/api/v1/engine/workflows", headers=headers(DEMO_TENANT_ID, user))
    assert listed.status_code == 200
    assert any(item["workflow_id"] == workflow_id for item in listed.json())
    assert client.get("/api/v1/engine/workflows", headers=headers(uuid4(), user)).json() == []

    integrations = client.get("/api/v1/engine/integrations", headers=headers(DEMO_TENANT_ID, user))
    assert integrations.status_code == 200
    assert next(item for item in integrations.json() if item["provider"] == "jira")["enabled"] is False
