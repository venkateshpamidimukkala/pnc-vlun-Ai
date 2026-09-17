import httpx
import pytest

from app.integrations import JiraCloudProvider, configured_integrations
from app.settings import settings


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, path, **kwargs):
        self.calls.append(("POST", path, kwargs))
        return self.response

    def put(self, path, **kwargs):
        self.calls.append(("PUT", path, kwargs))
        return self.response


def test_jira_configuration_is_disabled_without_credentials(monkeypatch):
    monkeypatch.setattr(settings, "enable_external_integrations", False)
    assert next(item for item in configured_integrations() if item.provider == "jira").enabled is False


def test_jira_creates_and_updates_issue(monkeypatch):
    monkeypatch.setattr(settings, "enable_external_integrations", True)
    monkeypatch.setattr(settings, "jira_email", "automation@example.com")
    monkeypatch.setattr(settings, "jira_api_token", "test-token")
    response = httpx.Response(201, json={"key": "KAN-42"}, request=httpx.Request("POST", "https://jira.example/issue"))
    client = FakeClient(response)
    provider = JiraCloudProvider(client=client)

    url = provider.create_change("Patch vulnerable dependency", {"cve": "CVE-2021-44228"})
    provider.update_ticket(url, {"status": "validated"})

    assert url == "https://pncilab-team.atlassian.net/browse/KAN-42"
    assert client.calls[0][0:2] == ("POST", "/issue")
    assert client.calls[1][0:2] == ("PUT", "/issue/KAN-42")


def test_jira_rejects_missing_credentials(monkeypatch):
    monkeypatch.setattr(settings, "enable_external_integrations", True)
    monkeypatch.setattr(settings, "jira_email", None)
    monkeypatch.setattr(settings, "jira_api_token", None)
    with pytest.raises(RuntimeError, match="credentials"):
        JiraCloudProvider(client=FakeClient(httpx.Response(200)))