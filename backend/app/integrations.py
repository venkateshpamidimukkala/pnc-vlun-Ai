from dataclasses import dataclass
from typing import Protocol

import httpx

from app.settings import settings


class SourceControlProvider(Protocol):
    def create_branch(self, repository: str, branch: str) -> str: ...
    def create_pull_request(self, repository: str, branch: str, title: str, body: str) -> str: ...


class TicketingProvider(Protocol):
    def create_change(self, summary: str, evidence: dict) -> str: ...
    def update_ticket(self, external_id: str, evidence: dict) -> None: ...


class JiraCloudProvider:
    """Jira Cloud ticket adapter using credentials supplied by the secret manager."""

    provider_name = "jira"

    def __init__(self, client: httpx.Client | None = None):
        if not settings.enable_external_integrations:
            raise RuntimeError("External integrations are disabled")
        if not settings.jira_email or not settings.jira_api_token:
            raise RuntimeError("Jira credentials are not configured")
        self.base_url = settings.jira_base_url.rstrip("/")
        self.client = client or httpx.Client(
            base_url=f"{self.base_url}/rest/api/3",
            auth=(settings.jira_email, settings.jira_api_token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=settings.jira_timeout_seconds,
        )

    def create_change(self, summary: str, evidence: dict) -> str:
        response = self.client.post(
            "/issue",
            json={
                "fields": {
                    "project": {"key": settings.jira_project_key},
                    "summary": summary,
                    "description": self._description(evidence),
                    "issuetype": {"name": settings.jira_issue_type},
                }
            },
        )
        response.raise_for_status()
        issue_key = response.json()["key"]
        return f"{self.base_url}/browse/{issue_key}"

    def update_ticket(self, external_id: str, evidence: dict) -> None:
        issue_key = external_id.rsplit("/", 1)[-1]
        response = self.client.put(
            f"/issue/{issue_key}",
            json={"fields": {"description": self._description(evidence)}},
        )
        response.raise_for_status()

    @staticmethod
    def _description(evidence: dict) -> dict:
        """Return Jira's Atlassian Document Format without executing model output."""
        import json

        content = json.dumps(evidence, indent=2, sort_keys=True, default=str)
        return {
            "type": "doc",
            "version": 1,
            "content": [{"type": "codeBlock", "attrs": {"language": "json"}, "content": [{"type": "text", "text": content}]}],
        }


@dataclass(frozen=True)
class IntegrationStatus:
    provider: str
    enabled: bool
    reason: str


def configured_integrations() -> list[IntegrationStatus]:
    jira_ready = settings.enable_external_integrations and bool(settings.jira_email and settings.jira_api_token)
    return [
        IntegrationStatus("github", False, "credentialed adapter required"),
        IntegrationStatus("gitlab", False, "credentialed adapter required"),
        IntegrationStatus("azure-devops", False, "credentialed adapter required"),
        IntegrationStatus("servicenow", False, "credentialed adapter required"),
        IntegrationStatus("jira", jira_ready, "configured" if jira_ready else "Jira URL, email, and API token required"),
    ]
