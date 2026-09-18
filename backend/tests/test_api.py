from datetime import datetime, timezone
import subprocess
from uuid import uuid4

from fastapi.testclient import TestClient
import time

from app.auth import DEMO_TENANT_ID, DEMO_USERS
from app.domain import Severity, Vulnerability
from app.main import app, repository


def headers(tenant, user):
    return {"X-Tenant-ID": str(tenant), "X-User-ID": str(user)}


def completed_scan(client, response, request_headers):
    assert response.status_code == 202
    body = response.json()
    for _ in range(100):
        if body.get("status") == "COMPLETED":
            return body.get("result", body)
        time.sleep(0.01)
        body = client.get(f"/api/v1/mvp/jobs/{body['job_id']}", headers=request_headers).json()
    raise AssertionError(f"scan did not complete: {body}")


def test_health():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_inventory_requires_identity():
    assert TestClient(app).get("/api/v1/vulnerabilities").status_code == 401


def test_application_inventory_groups_findings_by_mnemonic_application_and_repository():
    tenant, user = uuid4(), uuid4()
    repository.seed(Vulnerability(tenant_id=tenant, mnemonic="PME", application="Payments", repository="payments-api", title="SQL", category="SAST", severity=Severity.HIGH))
    repository.seed(Vulnerability(tenant_id=tenant, mnemonic="PME", application="Payments", repository="payments-worker", title="XSS", category="SAST", severity=Severity.CRITICAL))
    repository.seed(Vulnerability(tenant_id=uuid4(), mnemonic="OTHER", application="Hidden", repository="hidden", title="Other", category="SAST", severity=Severity.LOW))

    response = TestClient(app).get("/api/v1/mvp/application-inventory", headers=headers(tenant, user))

    assert response.status_code == 200
    assert response.json() == [{
        "mnemonic": "PME", "total_findings": 2, "critical_findings": 1,
        "applications": [{
            "name": "Payments", "repo_path": "payments-api", "total_findings": 2,
            "critical_findings": 1,
            "repositories": [
                {"name": "payments-api", "total_findings": 1, "critical_findings": 0},
                {"name": "payments-worker", "total_findings": 1, "critical_findings": 1},
            ],
        }],
    }]


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


def test_local_scan_reports_custom_sast_scanner(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text("import os\nos.system(user_input)\n", encoding="utf-8")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    client = TestClient(app)
    result = completed_scan(client, client.post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    assert result["scanner"] == "Custom Local SAST Scanner"
    assert result["findings"]


def test_local_scan_rejects_missing_repository_path():
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    response = TestClient(app).post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": "C:/does-not-exist"})
    assert response.status_code == 400
    assert "existing directory" in response.json()["detail"]


def test_upload_scan_rejects_non_zip(tmp_path):
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    response = TestClient(app).post("/api/v1/mvp/scans/upload", headers=headers(DEMO_TENANT_ID, user), files={"file": ("repo.txt", b"not a zip", "text/plain")})
    assert response.status_code == 400
    assert "ZIP" in response.json()["detail"]


def test_pull_request_requires_branch_then_creates_local_pr(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    source = tmp_path / "unsafe.py"
    source.write_text("import os\nos.system(user_input)\n", encoding="utf-8")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    client = TestClient(app)

    scan = completed_scan(client, client.post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    finding_id = scan["findings"][0]["id"]

    before_branch = client.post(f"/api/v1/mvp/vulnerabilities/{finding_id}/pull-request", headers=headers(DEMO_TENANT_ID, user))
    assert before_branch.status_code == 409

    branch = client.post(f"/api/v1/mvp/vulnerabilities/{finding_id}/branch", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)})
    assert branch.status_code == 200

    pull_request = client.post(f"/api/v1/mvp/vulnerabilities/{finding_id}/pull-request", headers=headers(DEMO_TENANT_ID, user))
    assert pull_request.status_code == 200
    assert pull_request.json()["status"] == "OPEN"
    assert pull_request.json()["branch_name"] == branch.json()["branch_name"]


def test_local_scan_checks_config_files_but_skips_unrelated_and_dependency_files(tmp_path):
    (tmp_path / "pom.xml").write_text("<password>hardcoded-secret</password>\n", encoding="utf-8")
    (tmp_path / "application.yaml").write_text("api_key: hardcoded-key\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("password = should_not_be_scanned\n", encoding="utf-8")
    dependency_dir = tmp_path / "node_modules"
    dependency_dir.mkdir()
    (dependency_dir / "third-party.js").write_text("token = 'should_not_be_scanned'\n", encoding="utf-8")

    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    client = TestClient(app)
    response = completed_scan(client, client.post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    finding_files = {finding["file_name"] for finding in response["findings"]}
    assert "pom.xml" in finding_files
    assert "application.yaml" in finding_files
    assert all("README.md" not in filename for filename in finding_files)
    assert all("node_modules" not in filename for filename in finding_files)


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
