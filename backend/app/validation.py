"""Validation gate for generated remediation plans."""
from dataclasses import dataclass
from typing import Sequence

from app.domain import Vulnerability
from app.remediation import RemediationPlan


@dataclass(frozen=True)
class ValidationCheck:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ValidationResult:
    vulnerability_id: str
    passed: bool
    checks: tuple[ValidationCheck, ...]
    blocking_reasons: tuple[str, ...]


class ValidationEngine:
    """Runs policy checks before a plan can enter approval."""

    mandatory_checks = ("build", "unit_tests", "security_scan", "regression_tests")

    def validate(self, finding: Vulnerability, plan: RemediationPlan) -> ValidationResult:
        checks: list[ValidationCheck] = []
        blockers: list[str] = []
        if not plan.files_or_dependencies:
            blockers.append("No source file or dependency target identified")
        if not plan.strategy:
            blockers.append("No remediation strategy generated")
        for check in self.mandatory_checks:
            aliases = {
                "build": ("build", "dependency resolution"),
                "unit_tests": ("unit tests",),
                "security_scan": ("security scan", "sca", "sast", "dast"),
                "regression_tests": ("regression",),
            }[check]
            represented = any(alias in test.lower() for test in plan.required_tests for alias in aliases)
            status = "PASS" if represented else "PENDING"
            detail = "Required validation is represented in the execution plan" if represented else "Validation adapter must execute this check"
            checks.append(ValidationCheck(check, status, detail))
        if finding.severity.value == "CRITICAL" and plan.confidence.value != "HIGH":
            blockers.append("Critical findings require high-confidence classification before approval")
        passed = not blockers and all(check.status == "PASS" for check in checks)
        return ValidationResult(str(finding.id), passed, tuple(checks), tuple(blockers))

    def validate_batch(self, findings: Sequence[Vulnerability], plans: Sequence[RemediationPlan]) -> list[ValidationResult]:
        by_id = {plan.vulnerability_id: plan for plan in plans}
        return [self.validate(finding, by_id[str(finding.id)]) for finding in findings]
