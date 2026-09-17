from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentResult:
    agent: str
    status: str
    evidence: dict[str, Any]


AGENTS = (
    "repository_discovery",
    "vulnerability_classification",
    "root_cause_analysis",
    "auto_remediation",
    "validation",
    "pr_generation",
    "approval",
    "merge",
)


def run_safe_agent(agent: str, context: dict[str, Any]) -> AgentResult:
    if agent not in AGENTS:
        raise ValueError(f"Unknown agent: {agent}")
    return AgentResult(agent=agent, status="READY", evidence={"input_keys": sorted(context)})
