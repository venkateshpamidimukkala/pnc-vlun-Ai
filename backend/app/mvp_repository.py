"""Persistence adapters for the MVP Operations read models."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text

from app.persistence import transaction
from app.performance import timed


class SqlMvpRepository:
    """Store provider-neutral MVP records in PostgreSQL JSONB."""

    def save(self, tenant_id: UUID, record_type: str, record_id: UUID, payload: dict[str, Any]) -> None:
        with timed("database.mvp_save", detail=record_type):
            with transaction(tenant_id) as session:
                session.execute(text("""
                insert into pnc.mvp_read_models (id, tenant_id, record_type, payload)
                values (:id, :tenant_id, :record_type, cast(:payload as jsonb))
                on conflict (id) do update set payload = excluded.payload, modified_at = now()
                where pnc.mvp_read_models.tenant_id = excluded.tenant_id
                """), {"id": str(record_id), "tenant_id": str(tenant_id), "record_type": record_type,
                        "payload": _json_dumps(payload)})

    def list(self, tenant_id: UUID, record_type: str) -> list[dict[str, Any]]:
        with timed("database.mvp_list", detail=record_type):
            with transaction(tenant_id) as session:
                rows = session.execute(text("""
                select payload from pnc.mvp_read_models
                where tenant_id = :tenant_id and record_type = :record_type
                order by modified_at desc
                """), {"tenant_id": str(tenant_id), "record_type": record_type}).mappings()
                return [_restore_json(row["payload"]) for row in rows]


def _json_dumps(value: Any) -> str:
    import json
    return json.dumps(value, default=lambda item: str(item) if isinstance(item, (UUID, datetime)) else item)


def _restore_json(value: Any) -> dict[str, Any]:
    # PostgreSQL returns JSONB as a decoded dict. UUID/datetime values are kept
    # as strings because the HTTP read models already serialize them as strings.
    return dict(value)