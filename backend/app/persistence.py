"""SQLAlchemy persistence primitives for production PostgreSQL deployments."""
from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.settings import settings
from app.performance import timed


_engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    future=True,
)
SessionFactory = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
engine = _engine


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
