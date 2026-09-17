from collections.abc import Iterable
from uuid import UUID

from app.domain import FindingStatus, Vulnerability


class VulnerabilityRepository:
    """Persistence port. Replace this adapter with SQLAlchemy in production."""

    def __init__(self, initial: Iterable[Vulnerability] = ()):
        self._rows = list(initial)

    def list(self, tenant_id: UUID) -> list[Vulnerability]:
        return [row for row in self._rows if row.tenant_id == tenant_id]

    def seed(self, row: Vulnerability) -> None:
        self._rows.append(row)

    def count(self, tenant_id: UUID) -> int:
        return len(self.list(tenant_id))

    def update_status(self, finding_id: UUID, status: FindingStatus) -> Vulnerability | None:
        for index, row in enumerate(self._rows):
            if row.id == finding_id:
                updated = row.model_copy(update={"status": status})
                self._rows[index] = updated
                return updated
        return None
