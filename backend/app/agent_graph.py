from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from app.remediation import RemediationPlanner
from app.validation import ValidationEngine
from app.vulnerability_classification import VulnerabilityClassifier

AGENT_SEQUENCE = (
    "repository_discovery",
    "vulnerability_classification",
    "root_cause_analysis",
    "auto_remediation",
    "validation",
    "pr_generation",
    "approval",
    "merge",
)


@dataclass
class RemediationState:
    workflow_id: UUID
    vulnerability_ids: list[UUID]
    current_agent: str = "repository_discovery"
    status: str = "QUEUED"
    evidence: dict[str, Any] = field(default_factory=dict)


def build_graph(state: RemediationState, findings: list[Any] | None = None) -> RemediationState:
    """Deterministic LangGraph-compatible state transition.

    Production workers should persist every transition and stop before merge until
    the approval service has recorded all required decisions.
    """
    for agent in AGENT_SEQUENCE[:-1]:
        state.current_agent = agent
        state.evidence[agent] = {"status": "READY", "side_effects": "DISABLED_IN_LOCAL_MODE"}
    if findings:
        classifications = VulnerabilityClassifier().classify_batch(findings)
        plans = RemediationPlanner().create_batch(findings, classifications)
        validations = ValidationEngine().validate_batch(findings, plans)
        state.evidence["vulnerability_classification"] = {
            "status": "COMPLETED", "results": [result.__dict__ for result in classifications]
        }
        state.evidence["auto_remediation"] = {
            "status": "COMPLETED", "plans": [plan.__dict__ for plan in plans]
        }
        state.evidence["validation"] = {
            "status": "PASSED" if all(result.passed for result in validations) else "BLOCKED",
            "results": [result.__dict__ for result in validations],
        }
        if not all(result.passed for result in validations):
            state.current_agent = "validation"
            state.status = "VALIDATION_BLOCKED"
            return state
    state.current_agent = "approval"
    state.status = "AWAITING_APPROVAL"
    return state
