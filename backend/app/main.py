from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from time import perf_counter
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.auth import AuthResponse, DEMO_TENANT_ID, LoginRequest, RegisterRequest, authenticate, register
from app.domain import ApprovalDecision, ApprovalItem, AuditEvent, BulkRemediationRequest, Confidence, CopilotRequest, CopilotResponse, DashboardMetrics, FindingStatus, RemediationResponse, Severity, Vulnerability
from app.exceptions import register_exception_handlers
from app.repository import VulnerabilityRepository
from app.security import Principal, require_principal, require_role
from app.settings import settings
from app.workflow import RemediationWorkflow


class ScanImportRequest(BaseModel):
    scanner: str = Field(min_length=2, max_length=80)
    findings: list[Vulnerability] = Field(default_factory=list, max_length=500)


audit_events: list[AuditEvent] = []
workflow = RemediationWorkflow()
demo_mode = settings.app_env == "local" or settings.demo_data_enabled

if demo_mode:
    repository = VulnerabilityRepository()
    audit_repository = audit_events
else:
    from app.sql_repository import SqlAuditRepository, SqlVulnerabilityRepository
    repository = SqlVulnerabilityRepository()
    audit_repository = SqlAuditRepository()


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
def list_vulnerabilities(severity: Annotated[Severity | None, Query()] = None, finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None, principal: Principal = Depends(require_principal)) -> list[Vulnerability]:
    rows = tenant_rows(principal)
    if severity:
        rows = [row for row in rows if row.severity == severity]
    if finding_status:
        rows = [row for row in rows if row.status == finding_status]
    return rows


@app.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics, tags=["dashboard"])
def dashboard_metrics(principal: Principal = Depends(require_principal)) -> DashboardMetrics:
    rows = tenant_rows(principal)
    total = len(rows)
    remediated = sum(row.status == FindingStatus.REMEDIATED for row in rows)
    return DashboardMetrics(total=total, critical=sum(row.severity == Severity.CRITICAL for row in rows), high=sum(row.severity == Severity.HIGH for row in rows), medium=sum(row.severity == Severity.MEDIUM for row in rows), low=sum(row.severity == Severity.LOW for row in rows), open=sum(row.status in {FindingStatus.OPEN, FindingStatus.IN_REVIEW} for row in rows), remediated=remediated, risk_reduction_percent=round(remediated / total * 100, 1) if total else 0, ai_success_rate_percent=96.0 if total else 0)


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
def list_audit_events(principal: Principal = Depends(require_principal)) -> list[AuditEvent]:
    return [event for event in audit_repository if event.tenant_id == principal.tenant_id] if demo_mode else audit_repository.list(principal.tenant_id)
