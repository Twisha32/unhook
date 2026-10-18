from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    create_engine,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from .settings import get_settings

Json = JSON().with_variant(JSONB(), "postgresql")


def now() -> datetime:
    return datetime.now(UTC)


class UtcDateTime(TypeDecorator):
    """Always timezone-aware UTC in Python. SQLite drops the offset on the way back
    out, which otherwise leaves a mix of naive and aware values in one session."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC) if value is not None else None

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


class Base(DeclarativeBase):
    pass


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=now, index=True)
    subject: Mapped[str] = mapped_column(Text, default="")
    sender: Mapped[str] = mapped_column(String(320), default="")
    sender_domain: Mapped[str] = mapped_column(String(255), default="")
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open | in_review | resolved | auto_closed
    resolution: Mapped[str | None] = mapped_column(String(24), nullable=True)  # confirmed_phish | false_positive | spam | benign
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    analyst_minutes: Mapped[float] = mapped_column(Float, default=0.0)
    report_count: Mapped[int] = mapped_column(Integer, default=1)
    top_finding: Mapped[str] = mapped_column(String(160), default="")
    resolved_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    analysis: Mapped[dict] = mapped_column(Json)
    note: Mapped[dict | None] = mapped_column(Json, nullable=True)

    reports: Mapped[list["Report"]] = relationship(back_populates="case")
    indicators: Mapped[list["Indicator"]] = relationship(back_populates="case", cascade="all, delete-orphan")

    @property
    def ref(self) -> str:
        return f"UH-{self.id:05d}"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=now, index=True)
    reporter: Mapped[str] = mapped_column(String(320), default="")
    raw: Mapped[bytes] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(12), default="queued")  # queued | done | failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reply_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    reply_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)

    case: Mapped[Case | None] = relationship(back_populates="reports")


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    kind: Mapped[str] = mapped_column(String(12))  # domain | url | ip | sha256
    value: Mapped[str] = mapped_column(Text, index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[str] = mapped_column(String(12), default="pending")  # pending | active | dismissed
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=now)

    case: Mapped[Case] = relationship(back_populates="indicators")


_engine = None
_session_factory = None

# Arbitrary, but the same in every process that shares a database.
_SCHEMA_LOCK = 0x554E4B48


def create_schema(engine) -> None:
    """Create any missing tables.

    The API, the worker and the mailbox poller all start together, and on a brand new
    Postgres database they would each try to create the same tables at once. Postgres
    doesn't make that safe (one of them dies with a duplicate-key error), so they take
    turns on an advisory lock that is released when the transaction ends.
    """
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _SCHEMA_LOCK})
            Base.metadata.create_all(conn)
    else:
        Base.metadata.create_all(engine)


def configure(url: str | None = None):
    """(Re)build the engine. Tests call this with an in-memory SQLite URL."""
    global _engine, _session_factory
    url = url or get_settings().database_url
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    _engine = create_engine(url, pool_pre_ping=True, **kwargs)
    _session_factory = sessionmaker(_engine, expire_on_commit=False)
    create_schema(_engine)
    return _engine


def session_factory():
    if _session_factory is None:
        configure()
    return _session_factory


@contextmanager
def session_scope():
    session = session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db():
    with session_scope() as session:
        yield session
