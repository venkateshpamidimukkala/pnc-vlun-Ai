"""SQLAlchemy persistence primitives for production PostgreSQL deployments."""
from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.settings import settings
from app.performance import current_timeline, timed
import logging
from time import perf_counter

logger = logging.getLogger("pnc.database")
SLOW_QUERY_MS = 100.0


_engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    future=True,
)
SessionFactory = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
engine = _engine


@event.listens_for(_engine, "before_cursor_execute")
def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany) -> None:
    conn.info.setdefault("pnc_query_started", []).append(perf_counter())


@event.listens_for(_engine, "after_cursor_execute")
def _after_cursor_execute(conn, cursor, statement, parameters, context, executemany) -> None:
    started = conn.info.get("pnc_query_started", []).pop() if conn.info.get("pnc_query_started") else None
    if started is None:
        return
    duration_ms = (perf_counter() - started) * 1000
    detail = " ".join(statement.split())[:240]
    timeline = current_timeline()
    if timeline:
        timeline.mark("database.query", duration_ms, detail=detail)
    if duration_ms >= SLOW_QUERY_MS:
        logger.warning("[SLOW-QUERY] %.2f ms: %s", duration_ms, detail)


@contextmanager
def transaction(tenant_id: UUID) -> Generator[Session, None, None]:
    """Open a transaction and set the PostgreSQL RLS tenant context."""
    session = SessionFactory()
    try:
        with timed("database.set_tenant_context"):
            session.execute(text("select set_config('app.tenant_id', :tenant_id, true)"), {"tenant_id": str(tenant_id)})
        yield session
        with timed("database.commit"):
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_database() -> bool:
    with _engine.connect() as connection:
        connection.execute(text("select 1"))
    return True
