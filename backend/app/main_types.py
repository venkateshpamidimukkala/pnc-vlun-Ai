from typing import Protocol
from uuid import UUID


class BulkRemediationInput(Protocol):
    tenant_id: UUID
    scope: str
    mnemonic: str | None
    repository: str | None
    cve: str | None
    severity: str | None


class VulnerabilityRecord(Protocol):
    tenant_id: UUID
    mnemonic: str
    repository: str
    cve: str | None
    severity: str
