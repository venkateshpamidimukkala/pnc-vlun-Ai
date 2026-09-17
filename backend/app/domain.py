from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    REMEDIATED = "REMEDIATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Scope(StrEnum):
    REPOSITORY = "REPOSITORY"
    APPLICATION = "APPLICATION"
    MNEMONIC = "MNEMONIC"
    ENTERPRISE = "ENTERPRISE"


class Vulnerability(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    mnemonic: str = Field(min_length=1, max_length=32)
    application: str = Field(min_length=1, max_length=255)
    repository: str = Field(min_length=1, max_length=255)
    title: str
    category: str
    severity: Severity
    cve: str | None = None
    cwe: str | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    status: FindingStatus = FindingStatus.OPEN
    ai_confidence: Confidence = Confidence.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    file_name: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    description: str | None = None
    business_impact: str | None = None
    technical_impact: str | None = None
    risk_score: float | None = Field(default=None, ge=0, le=10)


class BulkRemediationRequest(BaseModel):
    tenant_id: UUID
    scope: Scope
    mnemonic: str | None = None
    application: str | None = None
    repository: str | None = None
    cve: str | None = None
    severity: Severity | None = None
    requested_by: UUID

    @model_validator(mode="after")
    def validate_scope(self):
        required = {
            Scope.MNEMONIC: self.mnemonic,
            Scope.APPLICATION: self.application,
            Scope.REPOSITORY: self.repository,
        }
        if self.scope in required and not required[self.scope]:
            raise ValueError(f"{self.scope.value.lower()} is required for {self.scope.value} scope")
        return self


class RemediationResponse(BaseModel):
    workflow_id: UUID
    status: str
    matched_vulnerabilities: int
    branch_pattern: str
    confidence: Confidence
    next_step: str


class DashboardMetrics(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    open: int
    remediated: int
    risk_reduction_percent: float
    ai_success_rate_percent: float
    applications_scanned: int = 0
    remediations_generated: int = 0
    jira_tickets_created: int = 0
    pull_requests_generated: int = 0
    branches_created: int = 0
    security_score: float = 0


class ApprovalItem(BaseModel):
    id: UUID
    mnemonic: str
    application: str
    repository: str
    title: str
    level: str
    status: str
    due_at: datetime


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern="^(APPROVE|REJECT)$")
    comment: str = Field(default="", max_length=2000)


class AuditEvent(BaseModel):
    event_type: str
    aggregate_id: UUID
    actor_id: UUID
    tenant_id: UUID
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CopilotRequest(BaseModel):
    tenant_id: UUID
    question: str = Field(min_length=3, max_length=2000)


class CopilotResponse(BaseModel):
    answer: str
    evidence: list[str]
    confidence: Confidence
