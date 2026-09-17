"""Secure remediation plan generation.

The planner generates an auditable plan and patch intent. It does not write to a
repository or merge code. Those side effects belong behind source-control adapters
and the approval gate.
"""
from dataclasses import dataclass
from typing import Sequence

from app.domain import Confidence, Vulnerability
from app.vulnerability_classification import ClassificationResult


@dataclass(frozen=True)
class RemediationPlan:
    vulnerability_id: str
    branch_name: str
    strategy: str
    files_or_dependencies: tuple[str, ...]
    required_tests: tuple[str, ...]
    confidence: Confidence
    requires_human_review: bool


class RemediationPlanner:
    def create_plan(self, finding: Vulnerability, classification: ClassificationResult) -> RemediationPlan:
        category = finding.category.upper()
        if category in {"DEPENDENCY", "DEPENDENCY_VULNERABILITY"}:
            strategy = "Upgrade the vulnerable dependency to the first supported non-vulnerable version and regenerate the lockfile."
            targets = ("dependency manifest", "lockfile")
            tests = ("dependency resolution", "unit tests", "SCA scan", "regression tests")
        elif category in {"SQL_INJECTION", "COMMAND_INJECTION", "SSRF", "RCE"}:
            strategy = "Replace string-built execution with parameterized or allow-listed APIs and add negative security tests."
            targets = ("identified vulnerable source file", "security regression test")
            tests = ("unit tests", "API tests", "SAST", "DAST", "regression tests")
        elif category in {"XSS", "CROSS_SITE_SCRIPTING", "CSRF"}:
            strategy = "Apply framework-supported output encoding/request forgery protection and add browser security tests."
            targets = ("identified web source file", "security regression test")
            tests = ("unit tests", "Playwright/Cypress", "DAST", "regression tests")
        else:
            strategy = "Apply the approved remediation template after root-cause confirmation and attach security evidence."
            targets = ("identified vulnerable source file",)
            tests = ("build", "unit tests", "SAST", "SCA", "regression tests")
        return RemediationPlan(
            vulnerability_id=str(finding.id),
            branch_name=f"feature/VULN-{finding.id}-AUTOFIX",
            strategy=strategy,
            files_or_dependencies=targets,
            required_tests=tests,
            confidence=classification.confidence,
            requires_human_review=classification.confidence != Confidence.HIGH or classification.risk_score >= 9,
        )

    def create_batch(self, findings: Sequence[Vulnerability], classifications: Sequence[ClassificationResult]) -> list[RemediationPlan]:
        by_id = {result.vulnerability_id: result for result in classifications}
        return [self.create_plan(finding, by_id[str(finding.id)]) for finding in findings]
