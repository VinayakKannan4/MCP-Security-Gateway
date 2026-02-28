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

    # LLM — provider selection
    # "anthropic": uses AsyncAnthropic + anthropic_api_key
    # "openai_compat": uses AsyncOpenAI with custom base_url + llm_api_key (Groq, Ollama, etc.)
    llm_provider: Literal["anthropic", "openai_compat"] = "openai_compat"
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: str = ""  # Groq / Ollama / other OpenAI-compat key
    anthropic_api_key: str = ""  # kept for anthropic provider
    llm_model: str = "llama-3.3-70b-versatile"  # default; agents override per-agent
    llm_timeout_seconds: float = 10.0
    llm_max_retries: int = 2

    # Per-agent model overrides
    # RiskClassifierAgent: needs nuanced semantic reasoning → 70B
    risk_classifier_model: str = "llama-3.3-70b-versatile"
    # ArgumentGuardAgent: PII/pattern detection → fast 8B (14,400 RPD vs 1,000 RPD for 70B)
    argument_guard_model: str = "llama-3.1-8b-instant"

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
