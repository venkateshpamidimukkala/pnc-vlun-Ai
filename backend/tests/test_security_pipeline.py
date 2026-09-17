from datetime import datetime, timezone
from uuid import uuid4

from app.domain import Confidence, Severity, Vulnerability
from app.remediation import RemediationPlanner
from app.validation import ValidationEngine
from app.vulnerability_classification import VulnerabilityClassifier


def finding(category="DEPENDENCY", severity=Severity.HIGH, cve="CVE-2026-0001", cvss=8.2):
    return Vulnerability(tenant_id=uuid4(), mnemonic="PME", application="Portal", repository="api", title="test finding", category=category, severity=severity, cve=cve, cvss=cvss, created_at=datetime.now(timezone.utc))


def test_classifier_prioritizes_known_high_impact_finding():
    result = VulnerabilityClassifier().classify(finding("SQL_INJECTION", Severity.CRITICAL, cvss=9.8))
    assert result.priority == "P0"
    assert result.risk_score == 10.0
    assert "high-impact vulnerability category" in result.rationale


def test_remediation_planner_generates_branch_and_dependency_strategy():
    item = finding()
    classification = VulnerabilityClassifier().classify(item)
    plan = RemediationPlanner().create_plan(item, classification)
    assert plan.branch_name.startswith("feature/VULN-")
    assert "dependency" in plan.strategy.lower()
    assert "SCA scan" in plan.required_tests


def test_validation_blocks_low_confidence_critical_finding():
    item = finding("RCE", Severity.CRITICAL, cve=None, cvss=None)
    classification = VulnerabilityClassifier().classify(item)
    plan = RemediationPlanner().create_plan(item, classification)
    result = ValidationEngine().validate(item, plan)
    assert result.passed is False
    assert any("high-confidence" in reason for reason in result.blocking_reasons)


def test_validation_passes_high_confidence_dependency_plan():
    item = finding()
    classification = VulnerabilityClassifier().classify(item)
    assert classification.confidence == Confidence.HIGH
    plan = RemediationPlanner().create_plan(item, classification)
    result = ValidationEngine().validate(item, plan)
    assert result.passed is True
