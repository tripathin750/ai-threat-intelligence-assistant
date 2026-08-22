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


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_key: str | None
    allowed_origins: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    rate_limit_per_minute: int
    enable_scheduler: bool
    sync_interval_minutes: int


def get_settings() -> Settings:
    default_database = f"sqlite:///{(BACKEND_DIR / 'threat_intelligence.db').as_posix()}"
    return Settings(
        database_url=os.getenv("DATABASE_URL", default_database),
        api_key=os.getenv("API_KEY") or None,
        allowed_origins=_csv_setting(
            "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ),
        allowed_hosts=_csv_setting("ALLOWED_HOSTS", "*"),
        rate_limit_per_minute=max(1, int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))),
        enable_scheduler=os.getenv("ENABLE_SCHEDULER", "false").lower()
        in {"1", "true", "yes"},
        sync_interval_minutes=max(5, int(os.getenv("SYNC_INTERVAL_MINUTES", "60"))),
    )


settings = get_settings()
