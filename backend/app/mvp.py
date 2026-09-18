"""Small, provider-safe vertical slice for local vulnerability remediation."""
from __future__ import annotations

import os
import ast
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from app.domain import Severity, Vulnerability
from app.vulnerability_classification import VulnerabilityClassifier
from app.scanners import detect_stack

_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".cs",
    ".json", ".yaml", ".yml", ".properties", ".env",
}
_SPECIAL_FILES = {"pom.xml", "build.gradle", "build.gradle.kts", "dockerfile", ".env"}
_SKIP = {".git", ".idea", ".angular", "node_modules", "dist", "build", "target", ".venv", "venv", "__pycache__", ".pytest_cache"}
_MAX_SCAN_FILES = 2_000
_MAX_SCAN_FILE_BYTES = 1_000_000
_KNOWN_MNEMONICS = {"PME", "PRT", "PSE", "DAL", "PRE"}


@dataclass
class RemediationRecord:
    id: UUID
    finding_id: UUID
    original_code: str
    fixed_code: str
    explanation: str
    tenant_id: UUID | None = None
    cwe: str | None = None
    confidence: str = "MEDIUM"
    status: str = "PENDING"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class MvpRecord:
    applications: dict[UUID, dict] = field(default_factory=dict)
    remediations: dict[UUID, RemediationRecord] = field(default_factory=dict)
    jira: dict[UUID, dict] = field(default_factory=dict)
    branches: dict[UUID, dict] = field(default_factory=dict)
    prs: dict[UUID, dict] = field(default_factory=dict)
    knowledge: dict[UUID, dict] = field(default_factory=dict)


class LocalSecurityMvp:
    def __init__(self, store=None) -> None:
        self.data = MvpRecord()
        self.store = store

    def _save(self, record_type: str, record_id: UUID, payload: dict) -> None:
        if self.store:
            self.store.save(payload["tenant_id"], record_type, record_id, payload)

    def records(self, record_type: str, tenant_id: UUID) -> list[dict]:
        if self.store:
            return self.store.list(tenant_id, record_type)
        values = {
            "application": self.data.applications.values(),
            "remediation": (self._remediation_payload(item) for item in self.data.remediations.values()),
            "jira": self.data.jira.values(), "branch": self.data.branches.values(),
            "pull_request": self.data.prs.values(), "knowledge": self.data.knowledge.values(),
        }[record_type]
        return [item for item in values if item.get("tenant_id") == tenant_id]

    def _remediation_payload(self, item: RemediationRecord) -> dict:
        return {"id": item.id, "finding_id": item.finding_id, "original_code": item.original_code,
                "fixed_code": item.fixed_code, "explanation": item.explanation, "tenant_id": item.tenant_id,
                "cwe": item.cwe, "confidence": item.confidence, "status": item.status, "created_at": item.created_at}

    def remediation_for_finding(self, finding_id: UUID, tenant_id: UUID) -> RemediationRecord | None:
        for item in self.records("remediation", tenant_id):
            if UUID(str(item["finding_id"])) == finding_id:
                return RemediationRecord(**item, id=UUID(str(item["id"])), finding_id=finding_id,
                    tenant_id=tenant_id, created_at=datetime.fromisoformat(str(item["created_at"])))
        return next((item for item in self.data.remediations.values() if item.finding_id == finding_id and item.tenant_id == tenant_id), None)

    def record_for_finding(self, record_type: str, finding_id: UUID, tenant_id: UUID) -> dict | None:
        return next((item for item in self.records(record_type, tenant_id)
                     if str(item.get("finding_id")) == str(finding_id)), None)

    def scan(self, tenant_id: UUID, repo_path: str, repository) -> tuple[dict, list[Vulnerability]]:
        root = Path(repo_path).expanduser().resolve()
        if not root.is_dir():
            raise ValueError("Repository path must point to an existing directory")
        app_id = uuid4()
        name = root.name or str(root)
        app = {"id": app_id, "tenant_id": tenant_id, "name": name, "repo_path": str(root), "technology_stack": detect_stack(root), "created_date": datetime.now(timezone.utc), "last_scan_date": datetime.now(timezone.utc)}
        findings = self._scanner_findings(root, tenant_id, name, self._infer_mnemonic(root))
        for finding in findings:
            repository.seed(finding)
        app["total_vulnerabilities"] = len(findings)
        app["critical_issues"] = sum(f.severity == Severity.CRITICAL for f in findings)
        self.data.applications[app_id] = app
        self._save("application", app_id, app)
        return app, findings

    @staticmethod
    def _infer_mnemonic(root: Path) -> str:
        """Use a known mnemonic present in the selected path, with a safe fallback."""
        tokens = re.split(r"[^A-Za-z0-9]+", str(root).upper())
        return next((token for token in tokens if token in _KNOWN_MNEMONICS), "LOCAL")

    def _scanner_findings(self, root: Path, tenant_id: UUID, app_name: str, mnemonic: str = "LOCAL") -> list[Vulnerability]:
        findings: list[Vulnerability] = []
        for path in self._scan_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rules = [
                (r"(SELECT\s+.+\s+FROM|execute\s*\(.*%|cursor\.execute\s*\(.*\+)", "SQL_INJECTION", Severity.HIGH, "User-controlled input may reach a SQL query without parameterization.", "CWE-89"),
                (r"(innerHTML\s*=|document\.write\s*\()", "XSS", Severity.HIGH, "Untrusted content is written to an HTML sink.", "CWE-79"),
                (r"(?i)(password|secret|api[_-]?key|token)\s*(?:=|:)\s*['\"]?(?!.*(?:env|config))[^'\"\s<]+['\"]?", "SECRETS_EXPOSURE", Severity.CRITICAL, "A credential-like value is hardcoded in source or configuration.", "CWE-798"),
                (r"(?i)<(password|secret|api[_-]?key|token)>\s*[^<\s]+\s*</\1>", "SECRETS_EXPOSURE", Severity.CRITICAL, "A credential-like value is hardcoded in source or configuration.", "CWE-798"),
                (r"(os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(.*\+|child_process\.exec\s*\()", "COMMAND_INJECTION", Severity.CRITICAL, "External command execution uses potentially tainted input.", "CWE-78"),
            ]
            for number, line in enumerate(text.splitlines(), 1):
                for pattern, category, severity, description, cwe in rules:
                    if re.search(pattern, line):
                        classification = VulnerabilityClassifier().classify(Vulnerability(tenant_id=tenant_id, mnemonic=mnemonic, application=app_name, repository=str(root), title=category.replace("_", " "), category=category, severity=severity, cwe=cwe))
                        findings.append(Vulnerability(tenant_id=tenant_id, mnemonic=mnemonic, application=app_name, repository=str(root), title=f"{category.replace('_', ' ').title()} in {path.name}", category=category, severity=severity, cwe=cwe, cvss=classification.risk_score, description=description, file_name=str(path.relative_to(root)), line_number=number, business_impact="May expose customer data or compromise application integrity.", technical_impact=description, risk_score=classification.risk_score))
                        break
        return findings

    def _scan_files(self, root: Path):
        """Yield only bounded, security-relevant text files from a repository."""
        yielded = 0
        for current, directories, filenames in os.walk(root, topdown=True):
            directories[:] = sorted(directory for directory in directories if directory not in _SKIP)
            for filename in sorted(filenames):
                path = Path(current) / filename
                if path.name.lower() not in _SPECIAL_FILES and path.suffix.lower() not in _EXTENSIONS:
                    continue
                try:
                    if path.stat().st_size > _MAX_SCAN_FILE_BYTES:
                        continue
                except OSError:
                    continue
                yield path
                yielded += 1
                if yielded >= _MAX_SCAN_FILES:
                    return

    def generate_fix(self, finding: Vulnerability, repo_path: str) -> RemediationRecord:
        path = Path(repo_path).resolve() / (finding.file_name or "")
        original = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else "Source unavailable"
        fixed = original
        if finding.category == "SQL_INJECTION":
            fixed = original.replace(" + user_input", ", (user_input,)")
        elif finding.category == "XSS":
            fixed = original.replace("innerHTML", "textContent")
        elif finding.category == "SECRETS_EXPOSURE":
            fixed = re.sub(
                r"(?i)((?:['\"])?(?:password|secret|api[_-]?key|token)(?:['\"])?\s*(?:=|:)\s*)(['\"])[^'\"]+\2",
                r"\1os.environ.get('SECRET_NAME', '')",
                original,
            )
        elif finding.category == "COMMAND_INJECTION":
            fixed = original.replace("os.system", "subprocess.run")
        if path.suffix.lower() == ".py" and fixed != original:
            try:
                ast.parse(fixed, filename=str(path))
            except SyntaxError:
                fixed = original
        record = RemediationRecord(uuid4(), finding.id, original, fixed, "Use parameterized APIs, trusted encoders, environment-backed secrets, or allow-listed process arguments.", finding.tenant_id, finding.cwe, "MEDIUM")
        self.data.remediations[record.id] = record
        self._save("remediation", record.id, self._remediation_payload(record))
        knowledge = {"id": record.id, "tenant_id": finding.tenant_id, "vulnerability_pattern": finding.category, "cwe": finding.cwe, "description": finding.description or finding.title, "root_cause": finding.technical_impact or "Unsafe input handling", "remediation_guidance": record.explanation, "code_example": record.fixed_code, "date_added": record.created_at}
        self.data.knowledge[record.id] = knowledge
        self._save("knowledge", record.id, knowledge)
        return record

    def create_branch(self, finding: Vulnerability, repo_path: str, remediation: RemediationRecord) -> dict:
        root = Path(repo_path).resolve()
        if not (root / ".git").exists():
            raise ValueError("Repository is not a Git working tree")
        branch = f"security/{finding.cwe or finding.category}"
        result = subprocess.run(["git", "-C", str(root), "switch", "-c", branch], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0 and "already exists" not in result.stderr:
            raise ValueError(result.stderr.strip() or "Unable to create Git branch")
        if finding.file_name and remediation.fixed_code != remediation.original_code:
            target = root / finding.file_name
            target.write_text(remediation.fixed_code, encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", str(finding.file_name)], timeout=30, check=False)
            subprocess.run(["git", "-C", str(root), "commit", "-m", f"Security fix: {finding.title}"], capture_output=True, text=True, timeout=30, check=False)
        item = {"id": uuid4(), "tenant_id": finding.tenant_id, "finding_id": finding.id, "branch_name": branch, "commit_message": f"Security Remediation: {finding.title}", "status": "CREATED", "files_changed": [finding.file_name] if finding.file_name else []}
        self.data.branches[finding.id] = item
        self._save("branch", item["id"], item)
        return item

    def create_pr(self, finding: Vulnerability, branch: dict) -> dict:
        pr = {"id": uuid4(), "tenant_id": finding.tenant_id, "finding_id": finding.id, "pr_number": f"LOCAL-{str(uuid4())[:8].upper()}", "title": f"Security fix: {finding.title}", "description": "AI-generated remediation pending human review.", "branch_name": branch["branch_name"], "files_changed": branch["files_changed"], "status": "OPEN", "created_date": datetime.now(timezone.utc)}
        self.data.prs[finding.id] = pr
        self._save("pull_request", pr["id"], pr)
        return pr