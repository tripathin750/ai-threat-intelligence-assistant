"""Application configuration loaded from environment variables.

The project uses PostgreSQL in deployment.  A local SQLite database is the
safe default for a first run so the dashboard and test suite work without a
database server; set ``DATABASE_URL`` to the PostgreSQL URL in
``backend/.env`` to use PostgreSQL.
"""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")


def _csv_setting(name: str, default: str) -> tuple[str, ...]:
    value = os.getenv(name, default)
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _normalize_database_url(url: str) -> str:
    """Upgrade a bare ``postgres(ql)://`` URL to the psycopg (v3) driver.

    Managed Postgres providers (Neon, Render, etc.) hand out plain
    ``postgresql://`` connection strings. Without an explicit driver,
    SQLAlchemy defaults the "postgresql" scheme to the psycopg2 dialect —
    but only psycopg (v3) is installed (see requirements.txt) — so a raw
    provider URL would fail at startup with "No module named 'psycopg2'".
    Rewriting the scheme here means any provider URL can be pasted in as-is.
    """
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_key: str | None
    allowed_origins: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    rate_limit_per_minute: int
    enable_scheduler: bool
    sync_interval_minutes: int
    anthropic_api_key: str | None
    llm_model: str
    enable_llm_analysis: bool


def get_settings() -> Settings:
    default_database = f"sqlite:///{(BACKEND_DIR / 'threat_intelligence.db').as_posix()}"
    return Settings(
        database_url=_normalize_database_url(os.getenv("DATABASE_URL", default_database)),
        api_key=os.getenv("API_KEY") or None,
        allowed_origins=_csv_setting(
            "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ),
        allowed_hosts=_csv_setting("ALLOWED_HOSTS", "*"),
        rate_limit_per_minute=max(1, int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))),
        enable_scheduler=os.getenv("ENABLE_SCHEDULER", "false").lower()
        in {"1", "true", "yes"},
        sync_interval_minutes=max(5, int(os.getenv("SYNC_INTERVAL_MINUTES", "60"))),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
        # claude-opus-5 per this project's default model policy; override via
        # LLM_MODEL if a different Claude model is preferred.
        llm_model=os.getenv("LLM_MODEL", "claude-opus-5"),
        # Defaults to OFF: this project is meant to run at zero cost, and the
        # Anthropic API is paid per token (unlike everything else in this
        # stack). Getting a real LLM call requires BOTH setting
        # ANTHROPIC_API_KEY AND explicitly opting in here with
        # ENABLE_LLM_ANALYSIS=true - a single accidental env var is never
        # enough to start incurring charges.
        enable_llm_analysis=os.getenv("ENABLE_LLM_ANALYSIS", "false").lower()
        in {"1", "true", "yes"},
    )


settings = get_settings()
