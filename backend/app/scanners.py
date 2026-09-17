"""Provider-neutral local scanner ports for the Phase 1 MVP.

External Bandit/Semgrep execution can be added behind these adapters without
changing the normalized vulnerability contract used by the API.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol


class BaseScanner(Protocol):
    name: str

    def scan(self, root: Path) -> list[dict[str, object]]: ...


class BanditScanner:
    name = "Bandit"

    def scan(self, root: Path) -> list[dict[str, object]]:
        return []


class SemgrepScanner:
    name = "Semgrep"

    def scan(self, root: Path) -> list[dict[str, object]]:
        return []


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