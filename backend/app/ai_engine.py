"""Provider-neutral AI security remediation orchestration.

The local implementation is deterministic and side-effect free: it prepares
classification, remediation, validation, PR, approval, and knowledge evidence.
Credentialed providers can replace the adapters without changing this contract.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import UUID, uuid4

from app.domain import Vulnerability
from app.remediation import RemediationPlanner
from app.validation import ValidationEngine
from app.vulnerability_classification import VulnerabilityClassifier

AGENT_CATALOG = (
    "classification",
    "remediation",
    "validation",
    "test",
    "git",
    "jira",
    "pull_request",
    "approval",
    "knowledge",
)


@dataclass
class EngineWorkflow:
    workflow_id: UUID
    tenant_id: UUID
    requested_by: UUID
    project: str
    repository_path: str
    status: str
    created_at: datetime
    finding_ids: list[UUID] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


class SecurityRemediationEngine:
    def __init__(self):
        self._workflows: dict[UUID, EngineWorkflow] = {}

    @staticmethod
    def agents() -> list[dict[str, str]]:
        return [{"name": name, "status": "READY", "mode": "DETERMINISTIC_LOCAL"} for name in AGENT_CATALOG]

    def create_workflow(
        self,
        tenant_id: UUID,
        requested_by: UUID,
        project: str,
        repository_path: str,
        findings: Sequence[Vulnerability],
    ) -> EngineWorkflow:
        classifications = VulnerabilityClassifier().classify_batch(findings)
        plans = RemediationPlanner().create_batch(findings, classifications)
        validations = ValidationEngine().validate_batch(findings, plans)
        all_valid = all(result.passed for result in validations)
        workflow = EngineWorkflow(
            workflow_id=uuid4(), tenant_id=tenant_id, requested_by=requested_by,
            project=project, repository_path=repository_path,
            status="AWAITING_APPROVAL" if all_valid else "VALIDATION_BLOCKED",
            created_at=datetime.now(timezone.utc), finding_ids=[finding.id for finding in findings],
            evidence={
                "scan": {"status": "COMPLETED", "finding_count": len(findings), "repository_path": repository_path},
                "classification": {"status": "COMPLETED", "results": [asdict(item) for item in classifications]},
                "remediation": {"status": "COMPLETED", "plans": [asdict(item) for item in plans]},
                "validation": {"status": "PASSED" if all_valid else "BLOCKED", "results": [asdict(item) for item in validations]},
                "test": {"status": "PENDING", "checks": ["unit tests", "integration tests", "security tests", "regression tests"]},
                "git": {"status": "PLANNED", "branch_pattern": "security/fix-{workflow_id}"},
                "jira": {"status": "DISABLED_IN_LOCAL_MODE"},
                "pull_request": {"status": "PENDING_APPROVAL" if all_valid else "BLOCKED"},
                "approval": {"status": "PENDING" if all_valid else "NOT_READY", "required_levels": ["SECURITY_TEAM", "APPLICATION_TEAM", "MANAGER"]},
                "knowledge": {"status": "READY_TO_PERSIST", "records": len(findings)},
            },
        )
        self._workflows[workflow.workflow_id] = workflow
        return workflow

    def get(self, workflow_id: UUID, tenant_id: UUID) -> EngineWorkflow | None:
        workflow = self._workflows.get(workflow_id)
        return workflow if workflow and workflow.tenant_id == tenant_id else None

    def list(self, tenant_id: UUID) -> list[EngineWorkflow]:
        return sorted(
            (workflow for workflow in self._workflows.values() if workflow.tenant_id == tenant_id),
            key=lambda workflow: workflow.created_at,
            reverse=True,
        )


def workflow_payload(workflow: EngineWorkflow) -> dict[str, Any]:
    return asdict(workflow)