from datetime import datetime, timezone
import subprocess
from uuid import uuid4

from fastapi.testclient import TestClient
import time
import threading

from app.auth import DEMO_TENANT_ID, DEMO_USERS
from app.domain import Severity, Vulnerability
import app.main as app_module
import app.llm as llm_module
from app.main import app, repository
from app.performance import TimingTimeline, measure_time, timed, timed_function
from app.cache import TtlCache


def headers(tenant, user):
    return {"X-Tenant-ID": str(tenant), "X-User-ID": str(user)}


def test_ttl_cache_reuses_values_and_invalidates_by_prefix():
    cache = TtlCache()
    calls = []
    assert cache.get_or_set("tenant:metrics", 60, lambda: calls.append(1) or "value") == "value"
    assert cache.get_or_set("tenant:metrics", 60, lambda: calls.append(1) or "new") == "value"
    cache.invalidate(contains="tenant")
    assert cache.get_or_set("tenant:metrics", 60, lambda: calls.append(1) or "new") == "new"
    assert len(calls) == 2


def completed_scan(client, response, request_headers):
    assert response.status_code == 202
    body = response.json()
    for _ in range(100):
        if body.get("status") == "COMPLETED":
            return body.get("result", body)
        time.sleep(0.01)
        body = client.get(f"/api/v1/mvp/jobs/{body['job_id']}", headers=request_headers).json()
    raise AssertionError(f"scan did not complete: {body}")


def completed_workflow(client, response, request_headers):
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "QUEUED"
    for _ in range(100):
        body = client.get(f"/api/v1/engine/workflow-jobs/{body['job_id']}", headers=request_headers).json()
        if body.get("status") == "COMPLETED":
            return body["result"]
        time.sleep(0.01)
    raise AssertionError(f"workflow did not complete: {body}")


def test_health():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_timing_context_decorator_and_bottleneck_report():
    timeline = TimingTimeline("test-timeline")
    with timed("fast.stage", timeline=timeline):
        pass

    @timed_function("decorated.stage")
    def decorated():
        return "ok"

    assert decorated() == "ok"
    report = timeline.report()
    assert report["stages"][0]["operation"] == "fast.stage"


def test_measure_time_alias_and_performance_endpoint():
    @measure_time("test.measure_time")
    def measured():
        return "ok"

    assert measured() == "ok"
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    response = TestClient(app).get("/api/v1/performance/report", headers=headers(DEMO_TENANT_ID, user))
    assert response.status_code == 200
    assert any(item["operation"] == "test.measure_time" for item in response.json()["top_slowest_functions"])


def test_copilot_uses_local_fallback_without_ai_configuration(monkeypatch):
    monkeypatch.setattr(app_module.settings, "ai_provider", "local")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    response = TestClient(app).post(
        "/api/v1/copilot/query",
        headers=headers(DEMO_TENANT_ID, user),
        json={"tenant_id": str(DEMO_TENANT_ID), "question": "What are my highest-risk findings?"},
    )
    assert response.status_code == 200
    assert "findings" in response.json()["answer"]


def test_copilot_uses_ollama_when_configured(monkeypatch):
    calls = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "Ollama response"}}

    def fake_post(url, **kwargs):
        calls.update(url=url, kwargs=kwargs)
        return FakeResponse()

    monkeypatch.setattr(llm_module.httpx, "post", fake_post)
    monkeypatch.setattr(app_module.settings, "ai_provider", "ollama")
    monkeypatch.setattr(app_module.settings, "ollama_base_url", "http://localhost:11434/")
    monkeypatch.setattr(app_module.settings, "ollama_model", "qwen2.5:3b")
    result = llm_module.generate_answer("Summarize risk", {"total": 2, "unresolved_critical": 1, "unresolved_high": 0})
    assert result == "Ollama response"
    assert calls["url"] == "http://localhost:11434/api/chat"
    assert calls["kwargs"]["json"]["model"] == "qwen2.5:3b"
    assert calls["kwargs"]["json"]["stream"] is False


def test_copilot_provider_failure_falls_back(monkeypatch):
    def failed_post(*args, **kwargs):
        raise llm_module.httpx.TimeoutException("timeout")

    monkeypatch.setattr(llm_module.httpx, "post", failed_post)
    monkeypatch.setattr(app_module.settings, "ai_provider", "ollama")
    monkeypatch.setattr(app_module.settings, "ollama_base_url", "http://localhost:11434")
    monkeypatch.setattr(app_module.settings, "ollama_model", "qwen2.5:3b")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    response = TestClient(app).post(
        "/api/v1/copilot/query",
        headers=headers(DEMO_TENANT_ID, user),
        json={"tenant_id": str(DEMO_TENANT_ID), "question": "Summarize risk"},
    )
    assert response.status_code == 200
    assert "findings" in response.json()["answer"]


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
    assert response.json()["branch_pattern"] == f"pnc/remediation/{response.json()['workflow_id']}"


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
    body = completed_workflow(client, created, headers(DEMO_TENANT_ID, user))
    assert body["status"] == "AWAITING_APPROVAL"
    assert body["evidence"]["classification"]["status"] == "COMPLETED"
    assert body["evidence"]["validation"]["status"] == "PASSED"
    assert len(body["evidence"]["approval"]["required_levels"]) == 3

    other_tenant = client.get(f"/api/v1/engine/workflows/{body['workflow_id']}", headers=headers(uuid4(), user))
    assert other_tenant.status_code == 404


def test_local_scan_reports_custom_sast_scanner(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text("child_process.exec(user_input)\n", encoding="utf-8")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    client = TestClient(app)
    result = completed_scan(client, client.post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    assert result["scanner"] == "Custom Local SAST Scanner"
    assert result["findings"]


def test_local_scan_targets_security_relevant_formats_and_skips_unrelated_files(tmp_path):
    (tmp_path / "unsafe.py").write_text("os.system(user_input)\n", encoding="utf-8")
    (tmp_path / "unsafe.html").write_text("<script>document.write(user_input)</script>\n", encoding="utf-8")
    (tmp_path / "unsafe.js").write_text("child_process.exec(user_input)\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text("<password>hardcoded-secret</password>\n", encoding="utf-8")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    client = TestClient(app)
    result = completed_scan(client, client.post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    finding_files = {finding["file_name"] for finding in result["findings"]}
    assert "unsafe.py" in finding_files
    # Critical findings may stop lower-priority work early; HTML is covered below.
    assert "unsafe.js" not in finding_files
    assert "pom.xml" not in finding_files


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
    source.write_text("child_process.exec(user_input)\n", encoding="utf-8")
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
    (tmp_path / "requirements.txt").write_text("package==1.0\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("token=hardcoded-key\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("password = should_not_be_scanned\n", encoding="utf-8")
    dependency_dir = tmp_path / "node_modules"
    dependency_dir.mkdir()
    (dependency_dir / "third-party.js").write_text("token = 'should_not_be_scanned'\n", encoding="utf-8")

    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    client = TestClient(app)
    response = completed_scan(client, client.post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    finding_files = {finding["file_name"] for finding in response["findings"]}
    assert ".env.example" not in finding_files
    assert all("README.md" not in filename for filename in finding_files)
    assert all("node_modules" not in filename for filename in finding_files)


def test_local_scan_includes_html_when_no_critical_finding_stops_scan(tmp_path):
    (tmp_path / "unsafe.html").write_text("document.write(user_input)\n", encoding="utf-8")
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    result = completed_scan(TestClient(app), TestClient(app).post("/api/v1/mvp/scans", headers=headers(DEMO_TENANT_ID, user), json={"repository_path": str(tmp_path)}), headers(DEMO_TENANT_ID, user))
    assert "unsafe.html" in {finding["file_name"] for finding in result["findings"]}


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
    workflow = completed_workflow(client, created, headers(DEMO_TENANT_ID, user))
    workflow_id = workflow["workflow_id"]
    listed = client.get("/api/v1/engine/workflows", headers=headers(DEMO_TENANT_ID, user))
    assert listed.status_code == 200
    assert any(item["workflow_id"] == workflow_id for item in listed.json())
    assert client.get("/api/v1/engine/workflows", headers=headers(uuid4(), user)).json() == []

    integrations = client.get("/api/v1/engine/integrations", headers=headers(DEMO_TENANT_ID, user))
    assert integrations.status_code == 200
    assert next(item for item in integrations.json() if item["provider"] == "jira")["enabled"] is False


def test_workflow_job_status_is_responsive_while_work_is_running(monkeypatch):
    client = TestClient(app)
    user = DEMO_USERS["analyst@pnc.local"]["user_id"]
    started = threading.Event()
    release = threading.Event()
    original = app_module.engine.create_workflow

    def slow_workflow(*args, **kwargs):
        started.set()
        assert release.wait(timeout=2)
        return original(*args, **kwargs)

    monkeypatch.setattr(app_module.engine, "create_workflow", slow_workflow)
    response = client.post(
        "/api/v1/engine/workflows",
        headers=headers(DEMO_TENANT_ID, user),
        json={"project": "Responsive polling", "repository_path": "local-demo"},
    )
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    assert started.wait(timeout=1)

    began = time.perf_counter()
    status_response = client.get(f"/api/v1/engine/workflow-jobs/{job_id}", headers=headers(DEMO_TENANT_ID, user))
    elapsed = time.perf_counter() - began
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "RUNNING"
    assert elapsed < 0.25
    release.set()
