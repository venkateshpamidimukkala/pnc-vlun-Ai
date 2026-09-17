from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "local"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://postgres:admin@localhost:5432/pnc_vuln_ai"
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:4200"])
    database_pool_size: int = 10
    database_max_overflow: int = 20
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    redis_url: str = "redis://localhost:6379/0"
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672//"
    environment_name: str = "local"
    enable_external_integrations: bool = False
    demo_data_enabled: bool = False
    max_scan_payload_bytes: int = 10_000_000
    jira_base_url: str = "https://pncilab-team.atlassian.net"
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str = "KAN"
    jira_issue_type: str = "Task"
    jira_timeout_seconds: float = 10.0
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
