from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = PACKAGE_DIR / "data" / "model.json"


def _split(value):
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UNHOOK_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./unhook.db"
    redis_url: str = "redis://localhost:6379/0"
    # Run Celery tasks inline. Handy for tests and for trying things out without Redis.
    eager: bool = False

    # Empty token means the API is open. Fine on localhost, not fine anywhere else.
    api_token: str = ""
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]

    # The organisation's own domains and the people attackers like to impersonate.
    org_domains: Annotated[list[str], NoDecode] = []
    protected_names: Annotated[list[str], NoDecode] = []

    # Passive lookups only talk to third-party databases, never to the suspicious link.
    rdap_enabled: bool = True
    urlhaus_auth_key: str = ""
    urlhaus_feed_path: Path | None = None
    bazaar_auth_key: str = ""

    # Active link tracing. Leave empty unless the sandbox profile is running.
    sandbox_url: str = ""

    model_path: Path = DEFAULT_MODEL_PATH
    eval_report_path: Path = Path("eval/reports/latest.json")

    # "template" is deterministic and offline. "anthropic" asks an LLM, then checks its work.
    case_note_provider: str = "template"
    llm_model: str = "claude-haiku-5-5"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "unhook@localhost"

    imap_host: str = ""
    imap_user: str = ""
    imap_password: str = ""
    imap_folder: str = "INBOX"
    imap_poll_seconds: int = 30

    # Used by the dashboard's "analyst minutes saved" figure.
    manual_review_minutes: float = 8.0

    @field_validator("cors_origins", "org_domains", "protected_names", mode="before")
    @classmethod
    def _csv(cls, value):
        return _split(value)


@lru_cache
def get_settings() -> Settings:
    return Settings()
