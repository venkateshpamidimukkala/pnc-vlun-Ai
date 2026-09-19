"""Small, provider-safe vertical slice for local vulnerability remediation."""
from __future__ import annotations

import os
import ast
import hashlib
import re
import subprocess
import logging
from time import perf_counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from app.domain import Severity, Vulnerability
from app.vulnerability_classification import VulnerabilityClassifier
from app.scanners import detect_stack
from app.performance import current_timeline, timed, timed_function
from app.settings import settings
from app.agents import run_scan_agents

_EXTENSIONS = {".py", ".ts", ".html"}
_SPECIAL_FILES = {"requirements.txt", "package.json", "pyproject.toml", "angular.json", "dockerfile"}
_SKIP = {"node_modules", "venv", ".venv", "__pycache__", "dist", "build", "coverage", ".git", ".angular", "tmp", "logs"}
_SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".tar", ".gz", ".exe", ".dll", ".pdf", ".docx", ".log"}
_MAX_SCAN_FILES = 2_000
_MAX_SCAN_FILE_BYTES = 1_000_000
_SCAN_WORKERS = min(8, max(2, (os.cpu_count() or 2)))
_RISK_TERMS = ("auth", "login", "permission", "role", "api", "route", "endpoint", "db", "database", "sql", "upload", "jwt", "token", "secret", "credential", "validate", "exec", "command")
logger = logging.getLogger("pnc.scan")
_SCAN_CACHE: dict[str, dict[str, tuple[str, list[dict[str, object]]]]] = {}
_KNOWN_MNEMONICS = {"PME", "PRT", "PSE", "DAL", "PRE"}
_SCAN_RULES = (
    (re.compile(r"(SELECT\s+.+\s+FROM|execute\s*\(.*%|cursor\.execute\s*\(.*\+)"), "SQL_INJECTION", Severity.HIGH, "User-controlled input may reach a SQL query without parameterization.", "CWE-89"),
    (re.compile(r"(innerHTML\s*=|document\.write\s*\()"), "XSS", Severity.HIGH, "Untrusted content is written to an HTML sink.", "CWE-79"),
    (re.compile(r"(?i)(password|secret|api[_-]?key|token)\s*(?:=|:)\s*['\"]?(?!.*(?:env|config))[^'\"\s<]+['\"]?"), "SECRETS_EXPOSURE", Severity.CRITICAL, "A credential-like value is hardcoded in source or configuration.", "CWE-798"),
    (re.compile(r"(?i)<(password|secret|api[_-]?key|token)>\s*[^<\s]+\s*</\1>"), "SECRETS_EXPOSURE", Severity.CRITICAL, "A credential-like value is hardcoded in source or configuration.", "CWE-798"),
    (re.compile(r"(os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(.*\+|child_process\.exec\s*\()"), "COMMAND_INJECTION", Severity.CRITICAL, "External command execution uses potentially tainted input.", "CWE-78"),
)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _read_text_with_hash(path: Path) -> tuple[str | None, str | None]:
    """Read once for worker scanning, returning the cache hash from the same bytes."""
    try:
        content = path.read_bytes()
        return content.decode("utf-8", errors="ignore"), hashlib.sha256(content).hexdigest()
    except OSError:
        return None, None


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

    @timed_function("mvp.scan")
    def scan(self, tenant_id: UUID, repo_path: str, repository, progress=None, force_mock: bool = False) -> tuple[dict, list[Vulnerability]]:
        logger.info("================================\nSCAN STARTED\n================================\nRepository: %s", repo_path)
        with timed("scan.validate_repository"):
            root = Path(repo_path).expanduser().resolve()
            if not root.is_dir():
                raise ValueError("Repository path must point to an existing directory")
        app_id = uuid4()
        name = root.name or str(root)
        with timed("repository.discovery"):
            stack = detect_stack(root)
        logger.info("================================\nSTEP 1 - Repository Discovery\n================================\nFiles Found: pending filtering\nTechnology Stack: %s", ", ".join(stack))
        app = {"id": app_id, "tenant_id": tenant_id, "name": name, "repo_path": str(root), "technology_stack": stack, "created_date": datetime.now(timezone.utc), "last_scan_date": datetime.now(timezone.utc)}
        with timed("security.analysis"):
            if force_mock:
                findings = self._mock_findings(root, tenant_id, name, self._infer_mnemonic(root))
                scan_metadata = {
                    "scan_mode": "MOCK_DEMO",
                    "fallback_reason": "Explicit mock scan requested for demo data",
                    "files_analyzed_before_fallback": 0,
                }
                logger.info("Scan mock mode activated: mode=mock reason=explicit demo request")
                if progress:
                    progress(phase="Demo Findings Generated", files_discovered=0, files_scanned=0, vulnerabilities_found=len(findings), completion_percentage=100.0)
            else:
                findings, scan_metadata = self._scanner_findings(root, tenant_id, name, self._infer_mnemonic(root), progress=progress)
        logger.info("================================\nSTEP 3 - Static Analysis\n================================\nFindings: %d", len(findings))
        with timed("agent.pipeline", detail=f"{len(findings)} findings"):
            agent_report = run_scan_agents(root, self._prioritized_scan_files(root), findings,
                                           max_llm_files=settings.llm_max_files)
        with timed("report.generation", detail=f"{len(findings)} findings"):
            app["total_vulnerabilities"] = len(findings)
            app["critical_issues"] = sum(f.severity == Severity.CRITICAL for f in findings)
            app["scan_mode"] = scan_metadata["scan_mode"]
            app["scan_metadata"] = scan_metadata
            app["performance"] = {"agent_pipeline": agent_report}
        with timed("database.save", detail=f"{len(findings)} findings"):
            seed_many = getattr(repository, "seed_many", None)
            if seed_many is not None:
                seed_many(findings)
            else:
                for finding in findings:
                    repository.seed(finding)
            self.data.applications[app_id] = app
            self._save("application", app_id, app)
        self._log_performance_report()
        return app, findings

    @staticmethod
    def _log_performance_report() -> None:
        timeline = current_timeline()
        if not timeline:
            return
        report = timeline.report()
        logger.info("================================\nSCAN PERFORMANCE REPORT\n================================")
        for stage in report["stages"]:
            logger.info("%s: %.2f sec", stage["operation"], float(stage["duration_ms"]) / 1000)
        logger.info("TOTAL: %.2f sec", float(report["total_ms"]) / 1000)
        logger.info("================================\nTOP BOTTLENECKS\n================================\n%s", "\n".join(f"{item['rank']}. {item['operation']}" for item in report["top_bottlenecks"]))

    @staticmethod
    def _infer_mnemonic(root: Path) -> str:
        """Use a known mnemonic present in the selected path, with a safe fallback."""
        tokens = re.split(r"[^A-Za-z0-9]+", str(root).upper())
        return next((token for token in tokens if token in _KNOWN_MNEMONICS), "LOCAL")

    def _scanner_findings(self, root: Path, tenant_id: UUID, app_name: str, mnemonic: str = "LOCAL", progress=None) -> tuple[list[Vulnerability], dict[str, object]]:
        started = perf_counter()
        budget = settings.scan_time_budget_seconds

        def budget_exceeded() -> bool:
            return settings.scan_mock_fallback_enabled and budget > 0 and perf_counter() - started >= budget

        def fallback(files_analyzed: int) -> tuple[list[Vulnerability], dict[str, object]]:
            reason = f"Repository analysis exceeded the configured {budget:.2f}s demo time budget"
            logger.warning("Scan fallback activated: mode=mock files_analyzed=%d reason=%s", files_analyzed, reason)
            if progress:
                progress(phase="Demo Findings Generated", files_scanned=files_analyzed, vulnerabilities_found=3, completion_percentage=100.0)
            return self._mock_findings(root, tenant_id, app_name, mnemonic), {
                "scan_mode": "MOCK_FALLBACK",
                "fallback_reason": reason,
                "files_analyzed_before_fallback": files_analyzed,
            }

        classifier = VulnerabilityClassifier()
        classifications: dict[tuple[str, Severity, str], object] = {}
        with timed("file.enumeration"):
            paths = self._prioritized_scan_files(root)
        if budget_exceeded():
            return fallback(0)
        if progress:
            progress(phase="Files Discovered", files_discovered=len(paths), files_scanned=0, vulnerabilities_found=0)
        logger.info("================================\nSTEP 2 - File Filtering\n================================\nFiles After Filtering: %d", len(paths))
        with timed("git.change_detection"):
            changed = {item.as_posix() for item in self._git_changed_files(root)} if settings.scan_incremental else set()
        relative_paths = {str(path.relative_to(root)): path for path in paths}
        cache = _SCAN_CACHE.setdefault(str(root), {})
        if progress:
            progress(files_discovered=len(paths), files_scanned=0, vulnerabilities_found=0)

        def scan_path(path: Path) -> tuple[str, list[dict[str, object]]]:
            with timed("file.content_loading", detail=str(path)):
                text, fingerprint = _read_text_with_hash(path)
            if text is None:
                return "", []
            matches: list[dict[str, object]] = []
            with timed("vulnerability.detection", detail=str(path)):
                for number, line in enumerate(text.splitlines(), 1):
                    for pattern, category, severity, description, cwe in _SCAN_RULES:
                        if pattern.search(line):
                            matches.append({"category": category, "severity": severity, "description": description, "cwe": cwe, "file_name": str(path.relative_to(root)), "line_number": number, "vulnerable_code": line.strip(), "recommended_fix": self._recommendation(category)})
                            break
            return fingerprint or "", matches

        raw_findings: list[dict[str, object]] = []
        reusable: list[dict[str, object]] = []
        to_scan: list[Path] = []
        with timed("file.filtering"):
          for relative, path in relative_paths.items():
            entry = cache.get(relative)
            should_rescan = bool(changed) and relative.replace("\\", "/") in changed
            fingerprint = self._fingerprint(path) if entry else None
            if entry and entry[0] == fingerprint and not should_rescan:
                reusable.extend(entry[1])
            else:
                # Git marks a path as changed even when a previous scan cached it;
                # rescan it to avoid relying on Git metadata alone.
                to_scan.append(path)
        raw_findings.extend(reusable)
        if progress:
            progress(phase="Security Analysis Started", files_scanned=len(paths) - len(to_scan), vulnerabilities_found=len(raw_findings))
        scanned_count = len(paths) - len(to_scan)
        executor = ThreadPoolExecutor(max_workers=settings.scan_workers or _SCAN_WORKERS, thread_name_prefix="pnc-file-read")
        fallback_triggered = False
        try:
            future_paths = {executor.submit(scan_path, path): path for path in to_scan}
            pending = set(future_paths)
            while pending:
                completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    fingerprint, result = future.result()
                    relative = str(future_paths[future].relative_to(root))
                    cache[relative] = (fingerprint, result)
                    raw_findings.extend(result)
                    scanned_count += 1
                    if progress:
                        progress(phase="Vulnerabilities Found", files_scanned=scanned_count, vulnerabilities_found=len(raw_findings))
                    if budget_exceeded():
                        for pending_future in pending:
                            pending_future.cancel()
                        fallback_triggered = True
                        return fallback(scanned_count)
                    if scanned_count == 1 or scanned_count == len(paths) or scanned_count % max(1, len(paths) // 10) == 0:
                        current = future_paths[future].parent.name
                        logger.info("Scanning: %s\nProgress: %d/%d files\n%.1f%%", current, scanned_count, len(paths), scanned_count / len(paths) * 100 if paths else 100)
                if any(item["severity"] == Severity.CRITICAL for item in raw_findings):
                    for future in pending:
                        future.cancel()
                    break
        finally:
            executor.shutdown(wait=not fallback_triggered, cancel_futures=True)

        if budget_exceeded():
            return fallback(scanned_count)
        findings: list[Vulnerability] = []
        with timed("security.classification"):
          for item in raw_findings:
            category = str(item["category"])
            severity = Severity(item["severity"])
            cwe = str(item["cwe"])
            cache_key = (category, severity, cwe)
            classification = classifications.get(cache_key)
            if classification is None:
                classification = classifier.classify(Vulnerability(tenant_id=tenant_id, mnemonic=mnemonic, application=app_name, repository=str(root), title=category.replace("_", " "), category=category, severity=severity, cwe=cwe))
                classifications[cache_key] = classification
            findings.append(Vulnerability(tenant_id=tenant_id, mnemonic=mnemonic, application=app_name, repository=str(root), title=f"{category.replace('_', ' ').title()} in {Path(str(item['file_name'])).name}", category=category, severity=severity, cwe=cwe, cvss=classification.risk_score, description=str(item["description"]), file_name=str(item["file_name"]), line_number=int(item["line_number"]), business_impact="May expose customer data or compromise application integrity.", technical_impact=str(item["description"]), risk_score=classification.risk_score, vulnerable_code=str(item["vulnerable_code"]), recommended_fix=str(item["recommended_fix"])))
        if progress:
            progress(phase="Report Generated", files_scanned=scanned_count, vulnerabilities_found=len(raw_findings), completion_percentage=100.0)
        logger.info("================================\nSTEP 4 - AI Analysis\n================================\nFiles Sent To LLM: %d\nCurrent File: n/a\nLLM Duration: deterministic local analysis", 0)
        return findings, {"scan_mode": "LIVE", "files_analyzed_before_fallback": scanned_count}

    @staticmethod
    def _mock_findings(root: Path, tenant_id: UUID, app_name: str, mnemonic: str) -> list[Vulnerability]:
        """Return safe, deterministic representative findings for a time-limited demo scan."""
        samples = (
            ("SQL_INJECTION", Severity.HIGH, "CWE-89", "Database query uses concatenated user input.", "db/query.py", 42, "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"),
            ("SECRETS_EXPOSURE", Severity.CRITICAL, "CWE-798", "A credential-like value is hardcoded in configuration.", "config/settings.py", 18, "API_TOKEN = 'demo-placeholder-secret'"),
            ("XSS", Severity.HIGH, "CWE-79", "Untrusted content is written to an HTML sink.", "web/profile.html", 27, "element.innerHTML = profile.display_name"),
        )
        return [Vulnerability(
            tenant_id=tenant_id, mnemonic=mnemonic, application=app_name, repository=str(root),
            title=f"{category.replace('_', ' ').title()} in {Path(file_name).name}", category=category,
            severity=severity, cwe=cwe, cvss=8.2 if severity == Severity.HIGH else 9.1,
            description=description, file_name=file_name, line_number=line_number,
            business_impact="Representative demo finding; validate against the complete repository scan before remediation.",
            technical_impact=description, risk_score=8.2 if severity == Severity.HIGH else 9.1,
            vulnerable_code=code, recommended_fix="Use the secure remediation guidance and validate with a complete scan.",
        ) for category, severity, cwe, description, file_name, line_number, code in samples]

    @staticmethod
    def _fingerprint(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _recommendation(category: str) -> str:
        return {"SQL_INJECTION": "Use parameterized queries and never concatenate user input.", "XSS": "Use contextual output encoding or safe text binding.", "SECRETS_EXPOSURE": "Move the secret to a managed environment secret and rotate it.", "COMMAND_INJECTION": "Use an allowlist and subprocess argument arrays without shell interpolation."}.get(category, "Validate input and use a security-reviewed API.")

    def _prioritized_scan_files(self, root: Path) -> list[Path]:
        with timed("repository.file_filtering"):
            paths = list(self._scan_files(root))
        paths = sorted(paths, key=lambda path: (not any(term in str(path).lower() for term in _RISK_TERMS), str(path).lower()))
        return paths[:settings.fast_demo_max_files] if settings.fast_demo_mode else paths

    @staticmethod
    def _git_changed_files(root: Path) -> set[Path]:
        try:
            result = subprocess.run(["git", "-C", str(root), "diff", "--name-only"], capture_output=True, text=True, timeout=5, check=False)
            if result.returncode != 0:
                return set()
            changed = {Path(line.strip()) for line in result.stdout.splitlines() if line.strip()}
            untracked = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"], capture_output=True, text=True, timeout=5, check=False)
            if untracked.returncode == 0:
                changed.update(Path(line.strip()) for line in untracked.stdout.splitlines() if line.strip())
            return changed
        except (OSError, subprocess.SubprocessError):
            return set()

    def _scan_files(self, root: Path):
        """Yield only bounded, security-relevant text files from a repository."""
        yielded = 0
        max_files = settings.scan_max_files or _MAX_SCAN_FILES
        max_bytes = settings.scan_max_file_bytes or _MAX_SCAN_FILE_BYTES
        for current, directories, filenames in os.walk(root, topdown=True):
            directories[:] = sorted(directory for directory in directories if directory not in _SKIP)
            for filename in sorted(filenames):
                path = Path(current) / filename
                if path.suffix.lower() in _SKIP_EXTENSIONS:
                    continue
                if path.name.lower() not in _SPECIAL_FILES and path.suffix.lower() not in _EXTENSIONS:
                    continue
                try:
                    if path.stat().st_size > max_bytes:
                        logger.info("Skipped repository scan file larger than limit: %s (%d bytes)", path, path.stat().st_size)
                        continue
                except OSError:
                    continue
                yield path
                yielded += 1
                if yielded >= max_files:
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