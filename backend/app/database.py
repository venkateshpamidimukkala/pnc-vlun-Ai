"""Database initialization for the local PostgreSQL demo environment."""
from pathlib import Path

from sqlalchemy import text

from app.persistence import engine

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = PROJECT_ROOT / "database" / "001_initial_schema.sql"
SEED_FILE = PROJECT_ROOT / "database" / "002_demo_seed.sql"
ENTERPRISE_FILE = PROJECT_ROOT / "database" / "003_enterprise_capabilities.sql"
MVP_FILE = PROJECT_ROOT / "database" / "004_mvp_read_models.sql"


def initialize_demo_database() -> None:
    """Create the schema and deterministic demo data on first demo startup."""
    try:
        with engine.begin() as connection:
            schema_exists = connection.execute(
                text("select exists (select 1 from information_schema.schemata where schema_name = 'pnc')")
            ).scalar_one()
            if not schema_exists:
                connection.exec_driver_sql(SCHEMA_FILE.read_text(encoding="utf-8"))
            connection.exec_driver_sql(ENTERPRISE_FILE.read_text(encoding="utf-8"))
            connection.exec_driver_sql(MVP_FILE.read_text(encoding="utf-8"))
            connection.exec_driver_sql(SEED_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(
            "PostgreSQL is required for APP_ENV=demo. Start PostgreSQL with database "
            "'pnc_vuln_ai', user 'postgres', password 'admin', then restart the API."
        ) from exc