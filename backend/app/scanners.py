"""Provider-neutral local scanner ports for the Phase 1 MVP.

External Bandit/Semgrep execution can be added behind these adapters without
changing the normalized vulnerability contract used by the API.
"""
from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess
import logging
from app.performance import timed_function, timed
from typing import Protocol

logger = logging.getLogger("pnc.scanners")


class BaseScanner(Protocol):
    name: str

    def scan(self, root: Path) -> list[dict[str, object]]: ...


class BanditScanner:
    name = "Bandit"

    @timed_function("scanner.bandit")
    def scan(self, root: Path) -> list[dict[str, object]]:
        return _run_json_tool("bandit", ["-r", str(root), "-f", "json"], root)


class SemgrepScanner:
    name = "Semgrep"

    @timed_function("scanner.semgrep")
    def scan(self, root: Path) -> list[dict[str, object]]:
        return _run_json_tool("semgrep", ["scan", "--config", "auto", "--json", str(root)], root)


def _run_json_tool(command: str, args: list[str], root: Path) -> list[dict[str, object]]:
    """Run an optional scanner without making it a hard dependency of the MVP."""
    if shutil.which(command) is None:
        logger.info("Scanner %s skipped: executable not installed", command)
        return [{"scanner": command, "status": "SKIPPED", "reason": "executable not installed"}]
    try:
        with timed(f"scanner.{command}", detail=str(root)):
            result = subprocess.run([command, *args], cwd=root, capture_output=True,
                                    text=True, timeout=30, check=False)
        if not result.stdout.strip():
            return [{"scanner": command, "status": "FAILED", "reason": result.stderr.strip()[:500]}]
        payload = json.loads(result.stdout)
        record: dict[str, object] = {"scanner": command, "status": "COMPLETED", "result": payload, "exit_code": result.returncode}
        logger.info("Scanner %s completed: exit_code=%s findings=%s", command, result.returncode, len(payload.get("results", [])) if isinstance(payload, dict) else "unknown")
        if result.returncode != 0 and result.stderr.strip():
            record["warning"] = result.stderr.strip()[:500]
        return [record]
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return [{"scanner": command, "status": "FAILED", "reason": str(exc)}]


def detect_stack(root: Path) -> list[str]:
    markers = {
        "Python": {"pyproject.toml", "requirements.txt", "setup.py"},
        "NodeJS": {"package.json"},
        "React": {"vite.config.ts", "next.config.js"},
        "Angular": {"angular.json"},
        "Java / Spring Boot": {"pom.xml", "build.gradle", "build.gradle.kts"},
        ".NET": {"*.csproj", "*.sln"},
    }
    files = {item.name for item in root.iterdir() if item.is_file()}
    stack = [name for name, expected in markers.items() if any((root / marker).exists() or marker in files for marker in expected)]
    return stack or ["Unknown"]