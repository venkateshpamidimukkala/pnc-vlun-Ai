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
    scan_workers: int = Field(default=8, ge=1, le=32)
    scan_max_files: int = Field(default=2_000, ge=1, le=100_000)
    scan_max_file_bytes: int = Field(default=1_000_000, ge=1)
    fast_demo_mode: bool = False
    fast_demo_max_files: int = Field(default=200, ge=1, le=10_000)
    # Optional local-demo guardrail. Zero disables the time budget.
    scan_time_budget_seconds: float = Field(default=0.0, ge=0)
    scan_mock_fallback_enabled: bool = False
    scan_always_mock_in_demo: bool = False
    llm_max_files: int = Field(default=30, ge=1, le=50)
    enable_external_scanners: bool = False
    read_cache_ttl_seconds: float = Field(default=60.0, ge=0)
    scan_incremental: bool = True
    jira_base_url: str = "https://pncilab-team.atlassian.net"
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str = "KAN"
    jira_issue_type: str = "Task"
    jira_timeout_seconds: float = 10.0
    ai_provider: str = "ollama"
    # Ollama is optional; the deterministic local fallback is always available.
    ai_timeout_seconds: float = 2.0
    ai_max_tokens: int = 240
    ai_cache_ttl_seconds: float = 30.0
    ai_cache_max_entries: int = 256
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
