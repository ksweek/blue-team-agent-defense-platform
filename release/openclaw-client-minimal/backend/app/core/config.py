from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent
DEFAULT_DATABASE_PATH = BACKEND_DIR / "data" / "app.db"
DEFAULT_APP_ENV = "development"
DEFAULT_BOOTSTRAP_MODE = "auto"
DEFAULT_JWT_SECRET = "blue-team-dev-secret"
DEFAULT_SERVICE_TOKEN = "blue-team-runtime-token"
DEFAULT_BOOTSTRAP_ADMIN_PASSWORD = "admin123"
DEFAULT_BOOTSTRAP_ANALYST_PASSWORD = "analyst123"
LOCAL_CORS_ORIGINS = [
    "http://localhost:4173",
    "http://localhost:5173",
    "http://127.0.0.1:4173",
    "http://127.0.0.1:5173",
]
LOCAL_CORS_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"

# Load root `.env` for Compose/local startup, then allow backend-specific overrides.
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(BACKEND_DIR / ".env", override=True)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_str(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value.strip()
    return default


def env_csv(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or default


def current_app_env() -> str:
    return env_str("APP_ENV", "ENVIRONMENT", default=DEFAULT_APP_ENV).strip().lower() or DEFAULT_APP_ENV


def default_bootstrap_mode() -> str:
    if current_app_env() == "production":
        return "validate"
    return DEFAULT_BOOTSTRAP_MODE


def default_seed_sample_data() -> bool:
    return current_app_env() in {"development", "dev", "local", "test"}


def mask_database_url(url: str) -> str:
    if "://" not in url or "@" not in url:
        return url

    scheme, remainder = url.split("://", 1)
    credentials, host = remainder.rsplit("@", 1)

    if ":" not in credentials:
        return url

    username, _password = credentials.split(":", 1)
    return f"{scheme}://{username}:***@{host}"


class Settings(BaseModel):
    app_name: str = "Blue Team Defense Platform"
    app_version: str = "0.1.0"
    app_env: str = Field(default_factory=current_app_env)
    bootstrap_mode: str = Field(default_factory=lambda: env_str("BOOTSTRAP_MODE", default=default_bootstrap_mode()).lower())
    log_level: str = Field(default_factory=lambda: env_str("APP_LOG_LEVEL", "LOG_LEVEL", default="INFO").upper())
    cors_origins: list[str] = Field(
        default_factory=lambda: env_csv("CORS_ORIGINS", LOCAL_CORS_ORIGINS)
    )
    cors_origin_regex: str = Field(default_factory=lambda: env_str("CORS_ORIGIN_REGEX", default=LOCAL_CORS_ORIGIN_REGEX))
    database_url: str = Field(
        default_factory=lambda: env_str("DATABASE_URL", default=f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}")
    )
    database_echo: bool = Field(default_factory=lambda: env_bool("DATABASE_ECHO", False))
    database_pool_pre_ping: bool = Field(default_factory=lambda: env_bool("DATABASE_POOL_PRE_PING", True))
    jwt_secret: str = Field(default_factory=lambda: env_str("JWT_SECRET", default=DEFAULT_JWT_SECRET))
    jwt_expire_minutes: int = Field(default_factory=lambda: int(os.getenv("JWT_EXPIRE_MINUTES", "480")))
    gateway_api_token: str = Field(default_factory=lambda: env_str("GATEWAY_API_TOKEN", default=DEFAULT_SERVICE_TOKEN))
    ai_provider: str = Field(default_factory=lambda: env_str("AI_PROVIDER", default="disabled").lower())
    ai_base_url: str = Field(
        default_factory=lambda: env_str("AI_BASE_URL", "OPENAI_BASE_URL", default="https://api.openai.com/v1")
    )
    ai_api_key: str = Field(default_factory=lambda: env_str("AI_API_KEY", "OPENAI_API_KEY", default=""))
    ai_model: str = Field(default_factory=lambda: env_str("AI_MODEL", "OPENAI_MODEL", default=""))
    ai_timeout_seconds: float = Field(default_factory=lambda: float(os.getenv("AI_TIMEOUT_SECONDS", "60")))
    ai_temperature: float = Field(default_factory=lambda: float(os.getenv("AI_TEMPERATURE", "0")))
    ai_max_tokens: int = Field(default_factory=lambda: int(os.getenv("AI_MAX_TOKENS", "1200")))
    seed_sample_data: bool = Field(default_factory=lambda: env_bool("SEED_SAMPLE_DATA", default_seed_sample_data()))
    bootstrap_admin_password: str = Field(
        default_factory=lambda: env_str("BOOTSTRAP_ADMIN_PASSWORD", default=DEFAULT_BOOTSTRAP_ADMIN_PASSWORD)
    )
    bootstrap_analyst_password: str = Field(
        default_factory=lambda: env_str("BOOTSTRAP_ANALYST_PASSWORD", default=DEFAULT_BOOTSTRAP_ANALYST_PASSWORD)
    )
    task_worker_embedded: bool = Field(default_factory=lambda: env_bool("TASK_WORKER_EMBEDDED", True))
    task_worker_concurrency: int = Field(default_factory=lambda: int(os.getenv("TASK_WORKER_CONCURRENCY", "1")))
    task_worker_poll_interval: float = Field(default_factory=lambda: float(os.getenv("TASK_WORKER_POLL_INTERVAL", "0.5")))
    task_worker_recovery_limit: int = Field(default_factory=lambda: int(os.getenv("TASK_WORKER_RECOVERY_LIMIT", "200")))
    task_worker_heartbeat_interval: float = Field(default_factory=lambda: float(os.getenv("TASK_WORKER_HEARTBEAT_INTERVAL", "5")))
    task_worker_stale_seconds: int = Field(default_factory=lambda: int(os.getenv("TASK_WORKER_STALE_SECONDS", "180")))
    task_worker_retry_delay_seconds: int = Field(default_factory=lambda: int(os.getenv("TASK_WORKER_RETRY_DELAY_SECONDS", "10")))
    task_worker_max_attempts: int = Field(default_factory=lambda: int(os.getenv("TASK_WORKER_MAX_ATTEMPTS", "3")))
    skill_scan_provider: str = Field(default_factory=lambda: env_str("SKILL_SCAN_PROVIDER", default="local").lower())
    skill_scan_agent_scan_bin: str = Field(default_factory=lambda: env_str("SKILL_SCAN_AGENT_SCAN_BIN", default="agent-scan"))
    skill_scan_timeout_seconds: float = Field(default_factory=lambda: float(os.getenv("SKILL_SCAN_TIMEOUT_SECONDS", "120")))
    skill_scan_max_files: int = Field(default_factory=lambda: int(os.getenv("SKILL_SCAN_MAX_FILES", "80")))
    skill_scan_max_file_bytes: int = Field(default_factory=lambda: int(os.getenv("SKILL_SCAN_MAX_FILE_BYTES", "262144")))
    email_digest_worker_poll_interval: float = Field(
        default_factory=lambda: float(os.getenv("EMAIL_DIGEST_WORKER_POLL_INTERVAL", "30"))
    )

    @property
    def database_backend(self) -> str:
        lowered = self.database_url.lower()
        if lowered.startswith("sqlite"):
            return "sqlite"
        if lowered.startswith("postgresql"):
            return "postgresql"
        return lowered.split(":", 1)[0]

    @property
    def database_summary(self) -> str:
        return mask_database_url(self.database_url)

    @property
    def ai_provider_configured(self) -> bool:
        if self.ai_provider == "disabled":
            return False
        return bool(self.ai_base_url and self.ai_model)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
