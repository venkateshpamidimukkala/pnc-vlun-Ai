from dataclasses import dataclass
from typing import Any
from pathlib import Path
import re
from app.performance import timed
from app.scanners import BanditScanner, SemgrepScanner
from app.settings import settings


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


SCAN_AGENTS = ("repository_discovery", "security_prioritization", "static_analysis", "llm_analysis", "reporting")
_RISK_TERMS = re.compile(r"auth|login|jwt|token|api|controller|repository|database|secret|credential", re.I)


def run_scan_agents(root: Path, candidate_files: list[Path], findings: list[Any], *, max_llm_files: int) -> dict[str, Any]:
    """Execute bounded, provider-neutral scan stages for observability."""
    with timed("agent.repository_discovery"):
        discovered = [str(path.relative_to(root)) for path in candidate_files]
    with timed("agent.security_prioritization"):
        ranked = sorted(candidate_files, key=lambda path: (len(_RISK_TERMS.findall(path.name)), path.name), reverse=True)
        prioritized = [str(path.relative_to(root)) for path in ranked]
    with timed("agent.static_analysis"):
        static = ([scanner.scan(root) for scanner in (BanditScanner(), SemgrepScanner())]
                  if settings.enable_external_scanners else
                  [{"scanner": "external", "status": "SKIPPED", "reason": "disabled by configuration"}])
    with timed("agent.llm_analysis"):
        llm_candidates = prioritized[:max_llm_files]
    with timed("agent.reporting"):
        report = {"finding_count": len(findings), "risk_score": min(100, len(findings) * 10)}
    return {
        "stages": SCAN_AGENTS,
        "discovery": {"candidate_files": len(discovered)},
        "prioritization": {"prioritized_files": prioritized[:max_llm_files]},
        "static_analysis": static,
        "llm_analysis": {"eligible_files": llm_candidates, "max_files": max_llm_files, "executed": False},
        "report": report,
    }
