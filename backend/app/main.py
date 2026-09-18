from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import shutil
import subprocess
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Annotated
from uuid import UUID, uuid4
from urllib.parse import urlparse
from zipfile import BadZipFile, ZipFile

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field, field_validator

from app.auth import AuthResponse, DEMO_TENANT_ID, DEMO_USERS, LoginRequest, ProfileUpdateRequest, RegisterRequest, RoleUpdateRequest, ROLE_PERMISSIONS, authenticate, register, user_response
from app.ai_engine import SecurityRemediationEngine, workflow_payload
from app.domain import ApprovalDecision, ApprovalItem, AuditEvent, BulkRemediationRequest, Confidence, CopilotRequest, CopilotResponse, DashboardMetrics, FindingStatus, RemediationResponse, Severity, Vulnerability
from app.exceptions import register_exception_handlers
from app.repository import VulnerabilityRepository
from app.security import Principal, require_principal, require_role
from app.settings import settings
from app.workflow import RemediationWorkflow
from app.mvp import LocalSecurityMvp
from app import jobs


class ScanImportRequest(BaseModel):
    scanner: str = Field(min_length=2, max_length=80)
    findings: list[Vulnerability] = Field(default_factory=list, max_length=500)


class EngineWorkflowRequest(BaseModel):
    project: str = Field(min_length=1, max_length=255)
    repository_path: str = Field(min_length=1, max_length=1000)
    finding_ids: list[UUID] = Field(default_factory=list, max_length=500)

    @field_validator("project", "repository_path")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value


class LocalScanRequest(BaseModel):
    repository_path: str = Field(min_length=1, max_length=1000)


class GitScanRequest(BaseModel):
    repository_url: str = Field(min_length=8, max_length=2000)

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("repository_url must be an http(s) Git repository URL")
        return value


class FindingActionRequest(BaseModel):
    repository_path: str = Field(min_length=1, max_length=1000)


audit_events: list[AuditEvent] = []
workflow = RemediationWorkflow()
engine = SecurityRemediationEngine()
mvp = LocalSecurityMvp()
demo_mode = settings.app_env == "local" or settings.demo_data_enabled

if demo_mode:
    repository = VulnerabilityRepository()
    audit_repository = audit_events
else:
    from app.sql_repository import SqlAuditRepository, SqlVulnerabilityRepository
    from app.mvp_repository import SqlMvpRepository
    repository = SqlVulnerabilityRepository()
    audit_repository = SqlAuditRepository()
    mvp = LocalSecurityMvp(SqlMvpRepository())


def seed_demo_data() -> None:
    if not settings.demo_data_enabled:
        return
    rows = [
        ("Log4Shell remote code execution", "PME", "WebPortal", "pme-web", Severity.CRITICAL, "CVE-2021-44228", "CWE-502", 10.0),
        ("SQL injection in account search", "PRE", "Payments API", "pre-payments-api", Severity.HIGH, None, "CWE-89", 8.6),
        ("Outdated OpenSSL dependency", "PST", "Treasury Gateway", "pst-treasury", Severity.HIGH, "CVE-2025-1234", "CWE-1104", 7.5),
        ("Missing secure cookie flag", "PME", "WebPortal", "pme-web", Severity.MEDIUM, None, "CWE-614", 5.4),
        ("Verbose error response exposes internals", "PRE", "Payments API", "pre-payments-api", Severity.LOW, None, "CWE-209", 3.7),
    ]
    now = datetime.now(timezone.utc)
    for title, mnemonic, application, repo, severity, cve, cwe, cvss in rows:
        repository.seed(Vulnerability(tenant_id=DEMO_TENANT_ID, mnemonic=mnemonic, application=application, repository=repo, title=title, category="DEPENDENCY" if cve else "SAST", severity=severity, cve=cve, cwe=cwe, cvss=cvss, created_at=now - timedelta(days=2)))


seed_demo_data()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.app_env == "demo":
        from app.database import initialize_demo_database
        initialize_demo_database()
    yield


app = FastAPI(title="PNC Vuln AI API", version="0.3.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1024)
register_exception_handlers(app)


@app.middleware("http")
async def request_timing(request: Request, call_next):
    started = perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-Ms"] = f"{(perf_counter() - started) * 1000:.2f}"
    return response


@app.post("/api/v1/auth/login", response_model=AuthResponse, tags=["authentication"])
def login(payload: LoginRequest) -> AuthResponse:
    result = authenticate(payload)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return result


@app.post("/api/v1/auth/register", response_model=AuthResponse, status_code=201, tags=["authentication"])
def registration(payload: RegisterRequest) -> AuthResponse:
    try:
        return register(payload)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/auth/profile", response_model=AuthResponse, tags=["authentication"])
def profile(principal: Principal = Depends(require_principal)) -> AuthResponse:
    for email, user in DEMO_USERS.items():
        if user["user_id"] == principal.subject:
            return user_response(email, user)
    raise HTTPException(status_code=404, detail="User profile not found")


@app.patch("/api/v1/auth/profile", response_model=AuthResponse, tags=["authentication"])
def update_profile(payload: ProfileUpdateRequest, principal: Principal = Depends(require_principal)) -> AuthResponse:
    for email, user in DEMO_USERS.items():
        if user["user_id"] == principal.subject:
            user["name"] = payload.name.strip()
            return user_response(email, user)
    raise HTTPException(status_code=404, detail="User profile not found")


@app.get("/api/v1/admin/users", response_model=list[AuthResponse], tags=["administration"])
def list_users(principal: Principal = Depends(require_principal)) -> list[AuthResponse]:
    require_role(principal, "PLATFORM_ADMIN")
    return [user_response(email, user) for email, user in DEMO_USERS.items()]


@app.patch("/api/v1/admin/users/{user_id}/role", response_model=AuthResponse, tags=["administration"])
def update_user_role(user_id: UUID, payload: RoleUpdateRequest, principal: Principal = Depends(require_principal)) -> AuthResponse:
    require_role(principal, "PLATFORM_ADMIN")
    if payload.role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=400, detail="Unsupported role")
    for email, user in DEMO_USERS.items():
        if user["user_id"] == user_id:
            user["role"] = payload.role
            return user_response(email, user)
    raise HTTPException(status_code=404, detail="User not found")


@app.get("/health", tags=["platform"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "pnc-vuln-ai-api", "version": app.version}


@app.get("/ready", tags=["platform"])
def readiness() -> dict[str, str]:
    return {"status": "ready", "mode": "demo" if demo_mode else "production"}


def tenant_rows(principal: Principal) -> list[Vulnerability]:
    return repository.list(principal.tenant_id)


@app.get("/api/v1/catalog", tags=["catalog"])
def catalog(principal: Principal = Depends(require_principal)) -> dict[str, list[str]]:
    rows = tenant_rows(principal)
    return {"mnemonics": sorted({row.mnemonic for row in rows}), "applications": sorted({row.application for row in rows}), "repositories": sorted({row.repository for row in rows})}


@app.post("/api/v1/scans/import", status_code=status.HTTP_202_ACCEPTED, tags=["discovery"])
def import_scan(payload: ScanImportRequest, principal: Principal = Depends(require_principal)) -> dict[str, object]:
    for finding in payload.findings:
        if finding.tenant_id != principal.tenant_id:
            raise HTTPException(status_code=403, detail="Finding tenant does not match authenticated context")
        repository.seed(finding)
    scan_id = uuid4()
    audit_repository.append(AuditEvent(event_type="SCAN_IMPORTED", aggregate_id=scan_id, actor_id=principal.subject, tenant_id=principal.tenant_id))
    return {"scan_id": str(scan_id), "scanner": payload.scanner, "imported": len(payload.findings), "status": "COMPLETED"}


@app.get("/api/v1/vulnerabilities", response_model=list[Vulnerability], tags=["vulnerabilities"])
def list_vulnerabilities(severity: Annotated[Severity | None, Query()] = None, finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None, limit: Annotated[int, Query(ge=1, le=500)] = 100, offset: Annotated[int, Query(ge=0)] = 0, principal: Principal = Depends(require_principal)) -> list[Vulnerability]:
    rows = tenant_rows(principal)
    if severity:
        rows = [row for row in rows if row.severity == severity]
    if finding_status:
        rows = [row for row in rows if row.status == finding_status]
    return rows[offset:offset + limit]


@app.post("/api/v1/mvp/scans", status_code=status.HTTP_202_ACCEPTED, tags=["mvp"])
def mvp_scan(payload: LocalScanRequest, principal: Principal = Depends(require_principal)) -> dict:
    repository_path = payload.repository_path.strip()
    root = Path(repository_path).expanduser()
    if not root.exists() or not root.is_dir():
        raise HTTPException(status_code=400, detail="Repository path must be an existing directory visible to the API server")
    job_id = jobs.submit("LOCAL_SCAN", principal.tenant_id, _scan_directory, root, principal)
    return {"scan_id": str(job_id), "job_id": str(job_id), "scanner": "Custom Local SAST Scanner", "status": "QUEUED"}


def _scan_directory(root: Path, principal: Principal) -> dict:
    try:
        application, findings = mvp.scan(principal.tenant_id, str(root), repository)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan_id = uuid4()
    audit_repository.append(AuditEvent(event_type="REPOSITORY_SCAN", aggregate_id=scan_id, actor_id=principal.subject, tenant_id=principal.tenant_id))
    return {"scan_id": str(scan_id), "application": application, "findings": findings, "scanner": "Custom Local SAST Scanner", "status": "COMPLETED"}


@app.get("/api/v1/mvp/jobs/{job_id}", tags=["mvp"])
def mvp_job(job_id: UUID, principal: Principal = Depends(require_principal)) -> dict:
    job = jobs.get(job_id, principal.tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Background job not found")
    if job["status"] == "FAILED":
        raise HTTPException(status_code=400, detail=job.get("error", "Background job failed"))
    return job


@app.post("/api/v1/mvp/scans/git", status_code=status.HTTP_202_ACCEPTED, tags=["mvp"])
def mvp_git_scan(payload: GitScanRequest, principal: Principal = Depends(require_principal)) -> dict:
    job_id = jobs.submit("GIT_SCAN", principal.tenant_id, _git_scan_job, payload.repository_url, principal)
    return {"scan_id": str(job_id), "job_id": str(job_id), "scanner": "Custom Local SAST Scanner", "status": "QUEUED"}


def _git_scan_job(repository_url: str, principal: Principal) -> dict:
    workspace = Path(tempfile.mkdtemp(prefix="pnc-scan-"))
    try:
        result = subprocess.run(["git", "clone", "--depth", "1", repository_url, str(workspace / "repository")], capture_output=True, text=True, timeout=120, check=False)
        if result.returncode != 0:
            raise ValueError((result.stderr.strip() or "Git clone failed")[-500:])
        return _scan_directory(workspace / "repository", principal)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


@app.post("/api/v1/mvp/scans/upload", status_code=status.HTTP_202_ACCEPTED, tags=["mvp"])
def mvp_upload_scan(file: UploadFile = File(...), principal: Principal = Depends(require_principal)) -> dict:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a ZIP archive containing the repository")
    archive_bytes = file.file.read()
    if len(archive_bytes) > settings.max_scan_payload_bytes:
        raise HTTPException(status_code=413, detail="Upload exceeds the configured scan size limit")
    job_id = jobs.submit("UPLOAD_SCAN", principal.tenant_id, _upload_scan_job, archive_bytes, principal)
    return {"scan_id": str(job_id), "job_id": str(job_id), "scanner": "Custom Local SAST Scanner", "status": "QUEUED"}


def _upload_scan_job(archive_bytes: bytes, principal: Principal) -> dict:
    workspace = Path(tempfile.mkdtemp(prefix="pnc-scan-"))
    try:
        archive = workspace / "repository.zip"
        archive.write_bytes(archive_bytes)
        extract_root = workspace / "repository"
        extract_root.mkdir()
        with ZipFile(archive) as zipped:
            members = zipped.infolist()
            if len(members) > 5000 or sum(item.file_size for item in members) > 100 * 1024 * 1024:
                raise ValueError("ZIP archive exceeds the 5,000-file or 100 MB scan limit")
            for item in members:
                target = (extract_root / item.filename).resolve()
                if extract_root not in target.parents:
                    raise ValueError("ZIP archive contains an unsafe path")
            zipped.extractall(extract_root)
        return _scan_directory(extract_root, principal)
    except BadZipFile as exc:
        raise ValueError("Upload is not a valid ZIP archive") from exc
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


@app.get("/api/v1/mvp/vulnerabilities/{finding_id}", tags=["mvp"])
def mvp_finding(finding_id: UUID, principal: Principal = Depends(require_principal)) -> Vulnerability:
    finding = next((row for row in tenant_rows(principal) if row.id == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return finding


@app.post("/api/v1/mvp/vulnerabilities/{finding_id}/fix", tags=["mvp"])
def mvp_fix(finding_id: UUID, payload: FindingActionRequest, principal: Principal = Depends(require_principal)) -> dict:
    finding = mvp_finding(finding_id, principal)
    try:
        record = mvp.generate_fix(finding, payload.repository_path)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Unable to read source file: {exc}") from exc
    audit_repository.append(AuditEvent(event_type="FIX_GENERATION", aggregate_id=record.id, actor_id=principal.subject, tenant_id=principal.tenant_id))
    return {"id": str(record.id), "finding_id": str(record.finding_id), "original_code": record.original_code, "fixed_code": record.fixed_code, "explanation": record.explanation, "status": record.status, "created_at": record.created_at}


@app.post("/api/v1/mvp/vulnerabilities/{finding_id}/jira", tags=["mvp"])
def mvp_jira(finding_id: UUID, principal: Principal = Depends(require_principal)) -> dict:
    finding = mvp_finding(finding_id, principal)
    ticket = {"id": uuid4(), "tenant_id": finding.tenant_id, "finding_id": finding.id, "ticket_number": f"LOCAL-{str(uuid4())[:8].upper()}", "priority": finding.severity.value, "status": "OPEN", "summary": finding.title, "description": finding.description or "Security finding", "application": finding.application, "repository": finding.repository, "affected_files": [finding.file_name] if finding.file_name else []}
    mvp.data.jira[finding_id] = ticket
    mvp._save("jira", ticket["id"], ticket)
    audit_repository.append(AuditEvent(event_type="JIRA_CREATION", aggregate_id=ticket["id"], actor_id=principal.subject, tenant_id=principal.tenant_id))
    return ticket


@app.post("/api/v1/mvp/vulnerabilities/{finding_id}/branch", tags=["mvp"])
def mvp_branch(finding_id: UUID, payload: FindingActionRequest, principal: Principal = Depends(require_principal)) -> dict:
    finding = mvp_finding(finding_id, principal)
    remediation = mvp.remediation_for_finding(finding_id, principal.tenant_id)
    if remediation is None:
        remediation = mvp.generate_fix(finding, payload.repository_path)
    try:
        branch = mvp.create_branch(finding, payload.repository_path, remediation)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_repository.append(AuditEvent(event_type="BRANCH_CREATION", aggregate_id=branch["id"], actor_id=principal.subject, tenant_id=principal.tenant_id))
    return branch


@app.post("/api/v1/mvp/vulnerabilities/{finding_id}/pull-request", tags=["mvp"])
def mvp_pull_request(finding_id: UUID, principal: Principal = Depends(require_principal)) -> dict:
    finding = mvp_finding(finding_id, principal)
    branch = mvp.data.branches.get(finding_id) or mvp.record_for_finding("branch", finding_id, principal.tenant_id)
    if branch is None:
        raise HTTPException(status_code=409, detail="Create a remediation branch before opening a pull request")
    pr = mvp.create_pr(finding, branch)
    audit_repository.append(AuditEvent(event_type="PULL_REQUEST_CREATION", aggregate_id=pr["id"], actor_id=principal.subject, tenant_id=principal.tenant_id))
    return pr


@app.get("/api/v1/mvp/applications", tags=["mvp"])
def mvp_applications(principal: Principal = Depends(require_principal)) -> list[dict]:
    return mvp.records("application", principal.tenant_id)


@app.get("/api/v1/mvp/application-inventory", tags=["mvp"])
def mvp_application_inventory(principal: Principal = Depends(require_principal)) -> list[dict]:
    """Return tenant applications grouped by mnemonic and repository."""
    groups: dict[str, dict] = {}
    rows = tenant_rows(principal)
    application_records = mvp.records("application", principal.tenant_id)

    def group_for(mnemonic: str) -> dict:
        return groups.setdefault(mnemonic, {"mnemonic": mnemonic, "total_findings": 0, "critical_findings": 0, "applications": {}})

    for item in application_records:
        name = str(item["name"])
        group_for("LOCAL")["applications"].setdefault(name, {
            "name": name, "repo_path": item.get("repo_path", ""), "total_findings": 0,
            "critical_findings": 0, "repositories": {},
        })

    for row in rows:
        group = group_for(row.mnemonic)
        application = group["applications"].setdefault(row.application, {
            "name": row.application, "repo_path": row.repository, "total_findings": 0,
            "critical_findings": 0, "repositories": {},
        })
        repo = application["repositories"].setdefault(row.repository, {
            "name": row.repository, "total_findings": 0, "critical_findings": 0,
        })
        repo["total_findings"] += 1
        repo["critical_findings"] += row.severity == Severity.CRITICAL
        application["total_findings"] += 1
        application["critical_findings"] += row.severity == Severity.CRITICAL
        group["total_findings"] += 1
        group["critical_findings"] += row.severity == Severity.CRITICAL

    result = []
    for group in sorted(groups.values(), key=lambda item: item["mnemonic"]):
        group["applications"] = [
            {**application, "repositories": sorted(application["repositories"].values(), key=lambda item: item["name"])}
            for application in sorted(group["applications"].values(), key=lambda item: item["name"])
        ]
        result.append(group)
    return result


@app.get("/api/v1/mvp/remediations", tags=["mvp"])
def mvp_remediations(principal: Principal = Depends(require_principal)) -> list[dict]:
    return mvp.records("remediation", principal.tenant_id)


@app.get("/api/v1/mvp/jira", tags=["mvp"])
def mvp_jira_list(principal: Principal = Depends(require_principal)) -> list[dict]:
    return mvp.records("jira", principal.tenant_id)


@app.get("/api/v1/mvp/branches", tags=["mvp"])
def mvp_branch_list(principal: Principal = Depends(require_principal)) -> list[dict]:
    return mvp.records("branch", principal.tenant_id)


@app.get("/api/v1/mvp/pull-requests", tags=["mvp"])
def mvp_pr_list(principal: Principal = Depends(require_principal)) -> list[dict]:
    return mvp.records("pull_request", principal.tenant_id)


@app.get("/api/v1/mvp/knowledge", tags=["mvp"])
def mvp_knowledge(principal: Principal = Depends(require_principal)) -> list[dict]:
    return mvp.records("knowledge", principal.tenant_id)


@app.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics, tags=["dashboard"])
def dashboard_metrics(principal: Principal = Depends(require_principal)) -> DashboardMetrics:
    rows = tenant_rows(principal)
    total = len(rows)
    remediated = sum(row.status == FindingStatus.REMEDIATED for row in rows)
    applications = mvp.records("application", principal.tenant_id)
    remediations = mvp.records("remediation", principal.tenant_id)
    jira_tickets = mvp.records("jira", principal.tenant_id)
    pull_requests = mvp.records("pull_request", principal.tenant_id)
    branches = mvp.records("branch", principal.tenant_id)
    score = round(max(0, 100 - sum({Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 1}[row.severity] for row in rows if row.status != FindingStatus.REMEDIATED)), 1)
    return DashboardMetrics(total=total, critical=sum(row.severity == Severity.CRITICAL for row in rows), high=sum(row.severity == Severity.HIGH for row in rows), medium=sum(row.severity == Severity.MEDIUM for row in rows), low=sum(row.severity == Severity.LOW for row in rows), open=sum(row.status in {FindingStatus.OPEN, FindingStatus.IN_REVIEW} for row in rows), remediated=remediated, risk_reduction_percent=round(remediated / total * 100, 1) if total else 0, ai_success_rate_percent=96.0 if total else 0, applications_scanned=len(applications), remediations_generated=len(remediations), jira_tickets_created=len(jira_tickets), pull_requests_generated=len(pull_requests), branches_created=len(branches), security_score=score)


@app.post("/api/v1/remediation/bulk", response_model=RemediationResponse, status_code=status.HTTP_202_ACCEPTED, tags=["remediation"])
def request_bulk_remediation(payload: BulkRemediationRequest, principal: Principal = Depends(require_principal)) -> RemediationResponse:
    if payload.tenant_id != principal.tenant_id or payload.requested_by != principal.subject:
        raise HTTPException(status_code=403, detail="Tenant or actor does not match authenticated context")
    matches = workflow.match(tenant_rows(principal), payload)
    for row in matches:
        repository.update_status(row.id, FindingStatus.IN_REVIEW)
    workflow_id = uuid4()
    audit_repository.append(AuditEvent(event_type="REMEDIATION_REQUESTED", aggregate_id=workflow_id, actor_id=principal.subject, tenant_id=principal.tenant_id))
    return RemediationResponse(workflow_id=workflow_id, status="AWAITING_APPROVAL", matched_vulnerabilities=len(matches), branch_pattern="pnc/remediation/{workflow_id}", confidence=Confidence.HIGH if matches else Confidence.LOW, next_step="Validation complete. Review the approval queue to authorize the governed change.")


@app.get("/api/v1/approvals", response_model=list[ApprovalItem], tags=["approvals"])
def list_approvals(principal: Principal = Depends(require_principal)) -> list[ApprovalItem]:
    due_at = datetime.now(timezone.utc) + timedelta(days=2)
    return [ApprovalItem(id=row.id, mnemonic=row.mnemonic, application=row.application, repository=row.repository, title=row.title, level="SECURITY_REVIEW", status="PENDING", due_at=due_at) for row in tenant_rows(principal) if row.status == FindingStatus.IN_REVIEW]


@app.post("/api/v1/approvals/{finding_id}/decision", response_model=ApprovalItem, tags=["approvals"])
def decide_approval(finding_id: UUID, payload: ApprovalDecision, principal: Principal = Depends(require_principal)) -> ApprovalItem:
    require_role(principal, "SECURITY_REVIEWER", "PLATFORM_ADMIN")
    row = next((item for item in tenant_rows(principal) if item.id == finding_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="Approval item not found")
    new_status = FindingStatus.REMEDIATED if payload.decision == "APPROVE" else FindingStatus.ACCEPTED_RISK
    repository.update_status(finding_id, new_status)
    audit_repository.append(AuditEvent(event_type=f"APPROVAL_{payload.decision}", aggregate_id=finding_id, actor_id=principal.subject, tenant_id=principal.tenant_id))
    return ApprovalItem(id=row.id, mnemonic=row.mnemonic, application=row.application, repository=row.repository, title=row.title, level="SECURITY_REVIEW", status=payload.decision, due_at=row.created_at)


@app.post("/api/v1/copilot/query", response_model=CopilotResponse, tags=["copilot"])
def copilot_query(payload: CopilotRequest, principal: Principal = Depends(require_principal)) -> CopilotResponse:
    if payload.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    rows = tenant_rows(principal)
    critical = sum(row.severity == Severity.CRITICAL and row.status != FindingStatus.REMEDIATED for row in rows)
    return CopilotResponse(answer=f"Your tenant has {len(rows)} findings, including {critical} unresolved critical finding(s). The live demo knowledge base includes inventory, remediation workflow, approval, and audit evidence.", evidence=["vulnerability inventory", "remediation workflow state", "audit event store"], confidence=Confidence.HIGH)


@app.get("/api/v1/audit/events", response_model=list[AuditEvent], tags=["audit"])
def list_audit_events(limit: Annotated[int, Query(ge=1, le=500)] = 100, offset: Annotated[int, Query(ge=0)] = 0, principal: Principal = Depends(require_principal)) -> list[AuditEvent]:
    events = [event for event in audit_repository if event.tenant_id == principal.tenant_id] if demo_mode else audit_repository.list(principal.tenant_id, limit=limit, offset=offset)
    return events[offset:offset + limit] if demo_mode else events


@app.get("/api/v1/engine/agents", tags=["ai-engine"])
def list_engine_agents(_: Principal = Depends(require_principal)) -> list[dict[str, str]]:
    return engine.agents()


@app.get("/api/v1/engine/integrations", tags=["ai-engine"])
def list_engine_integrations(_: Principal = Depends(require_principal)) -> list[dict[str, object]]:
    from app.integrations import configured_integrations

    return [{"provider": item.provider, "enabled": item.enabled, "reason": item.reason} for item in configured_integrations()]


@app.post("/api/v1/engine/workflows", status_code=status.HTTP_202_ACCEPTED, tags=["ai-engine"])
def create_engine_workflow(payload: EngineWorkflowRequest, principal: Principal = Depends(require_principal)) -> dict:
    rows = tenant_rows(principal)
    if payload.finding_ids:
        tenant_finding_ids = {row.id for row in rows}
        missing_ids = [finding_id for finding_id in payload.finding_ids if finding_id not in tenant_finding_ids]
        if missing_ids:
            raise HTTPException(status_code=404, detail="One or more findings were not found in the current tenant")
    selected = [row for row in rows if not payload.finding_ids or row.id in payload.finding_ids]
    workflow_state = engine.create_workflow(principal.tenant_id, principal.subject, payload.project, payload.repository_path, selected)
    audit_repository.append(AuditEvent(event_type="ENGINE_WORKFLOW_CREATED", aggregate_id=workflow_state.workflow_id, actor_id=principal.subject, tenant_id=principal.tenant_id))
    return workflow_payload(workflow_state)


@app.get("/api/v1/engine/workflows", tags=["ai-engine"])
def list_engine_workflows(principal: Principal = Depends(require_principal)) -> list[dict]:
    return [workflow_payload(item) for item in engine.list(principal.tenant_id)]


@app.get("/api/v1/engine/workflows/{workflow_id}", tags=["ai-engine"])
def get_engine_workflow(workflow_id: UUID, principal: Principal = Depends(require_principal)) -> dict:
    workflow_state = engine.get(workflow_id, principal.tenant_id)
    if workflow_state is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return workflow_payload(workflow_state)
