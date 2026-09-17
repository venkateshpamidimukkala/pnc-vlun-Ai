from collections.abc import Sequence
from typing import Any
from uuid import uuid4

from app.agent_graph import RemediationState, build_graph
from app.main_types import BulkRemediationInput, VulnerabilityRecord


class RemediationWorkflow:
    """Deterministic workflow boundary; LangGraph nodes can replace these steps.

    Each node is intentionally side-effect free until approval. Production adapters
    should persist state after every node and publish an outbox event.
    """

    def match(self, findings: Sequence[VulnerabilityRecord], request: BulkRemediationInput) -> list[VulnerabilityRecord]:
        result = [f for f in findings if f.tenant_id == request.tenant_id]
        if request.scope == "MNEMONIC":
            result = [f for f in result if f.mnemonic == request.mnemonic]
        elif request.scope == "APPLICATION":
            result = [f for f in result if f.application == request.application]
        elif request.scope == "REPOSITORY":
            result = [f for f in result if f.repository == request.repository]
        if request.cve:
            result = [f for f in result if f.cve == request.cve]
        if request.severity:
            result = [f for f in result if f.severity == request.severity]
        return result

    def graph_definition(self) -> dict[str, Any]:
        return {"nodes": ["discover", "classify", "root_cause", "remediate", "validate", "pr", "approve", "merge"], "approval_gate": "approve"}

    def execute(self, findings: Sequence[VulnerabilityRecord]) -> RemediationState:
        """Run classification, remediation planning, and validation before approval."""
        rows = list(findings)
        return build_graph(
            RemediationState(workflow_id=uuid4(), vulnerability_ids=[row.id for row in rows]),
            findings=rows,
        )
