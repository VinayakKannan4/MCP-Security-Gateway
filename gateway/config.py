from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://gateway:gateway@localhost:5432/gateway"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # LLM
    anthropic_api_key: str = ""
    llm_model: str = "claude-sonnet-4-6"
    llm_timeout_seconds: float = 10.0
    llm_max_retries: int = 2

    # Policy
    policy_dir: str = "policies"
    policy_file: str = "default.yaml"

    # Approval
    approval_token_ttl_seconds: int = 3600  # 1 hour

    # Observability
    otel_endpoint: str = "http://localhost:4317"
    otel_enabled: bool = False

    # Security
    admin_api_key: str = ""  # separate key for admin endpoints


settings = Settings()
