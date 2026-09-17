"""PostgreSQL vulnerability and audit repositories.

All queries include tenant_id even though PostgreSQL RLS is also enabled. This
provides defense in depth and makes authorization intent explicit in application code.
"""
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import text

from app.domain import AuditEvent, FindingStatus, Severity, Vulnerability
from app.persistence import transaction


class SqlVulnerabilityRepository:
    def list(self, tenant_id: UUID, limit: int = 1000) -> list[Vulnerability]:
        with transaction(tenant_id) as session:
            rows = session.execute(text("""
                select v.id, v.tenant_id, v.fingerprint, v.title, v.category, v.severity, v.cve, v.cwe, v.cvss,
                       v.status, v.ai_confidence, v.created_at, m.code as mnemonic,
                       a.name as application, r.name as repository
                from pnc.vulnerabilities v
                join pnc.repositories r on r.id = v.repository_id
                join pnc.applications a on a.id = r.application_id
                join pnc.mnemonics m on m.id = a.mnemonic_id
                where v.tenant_id = :tenant_id and v.deleted_at is null
                order by v.created_at desc limit :limit
            """), {"tenant_id": str(tenant_id), "limit": limit}).mappings()
            return [self._model(row) for row in rows]

    def get(self, tenant_id: UUID, vulnerability_id: UUID) -> Vulnerability | None:
        with transaction(tenant_id) as session:
            row = session.execute(text("""
                select v.id, v.tenant_id, v.fingerprint, v.title, v.category, v.severity, v.cve, v.cwe, v.cvss,
                       v.status, v.ai_confidence, v.created_at, m.code as mnemonic,
                       a.name as application, r.name as repository
                from pnc.vulnerabilities v
                join pnc.repositories r on r.id = v.repository_id
                join pnc.applications a on a.id = r.application_id
                join pnc.mnemonics m on m.id = a.mnemonic_id
                where v.tenant_id = :tenant_id and v.id = :id and v.deleted_at is null
                order by v.discovered_at desc limit 1
            """), {"tenant_id": str(tenant_id), "id": str(vulnerability_id)}).mappings().first()
            return self._model(row) if row else None

    def create(self, finding: Vulnerability, actor_id: UUID) -> Vulnerability:
        with transaction(finding.tenant_id) as session:
            session.execute(text("""
                insert into pnc.vulnerabilities
                (id, tenant_id, repository_id, fingerprint, title, category, cve, cwe, cvss,
                 severity, status, ai_confidence, created_by, modified_by)
                values (:id, :tenant_id, :repository_id, :fingerprint, :title, :category, :cve,
                        :cwe, :cvss, :severity, :status, :confidence, :actor, :actor)
            """), {"id": str(finding.id), "tenant_id": str(finding.tenant_id),
                    "repository_id": str(UUID(int=0)), "fingerprint": f"manual:{finding.id}",
                    "title": finding.title, "category": finding.category, "cve": finding.cve,
                    "cwe": finding.cwe, "cvss": finding.cvss, "severity": finding.severity.value,
                    "status": finding.status.value, "confidence": finding.ai_confidence.value,
                    "actor": str(actor_id)})
        return finding

    def update(self, finding: Vulnerability, actor_id: UUID) -> Vulnerability:
        with transaction(finding.tenant_id) as session:
            session.execute(text("""
                update pnc.vulnerabilities set title=:title, category=:category, severity=:severity,
                  cve=:cve, cwe=:cwe, cvss=:cvss, status=:status, ai_confidence=:confidence,
                  modified_by=:actor, modified_at=now()
                where tenant_id=:tenant_id and id=:id and deleted_at is null
            """), {"id": str(finding.id), "tenant_id": str(finding.tenant_id), "title": finding.title,
                    "category": finding.category, "severity": finding.severity.value, "cve": finding.cve,
                    "cwe": finding.cwe, "cvss": finding.cvss, "status": finding.status.value,
                    "confidence": finding.ai_confidence.value, "actor": str(actor_id)})
        return finding

    def delete(self, tenant_id: UUID, vulnerability_id: UUID, actor_id: UUID) -> bool:
        with transaction(tenant_id) as session:
            result = session.execute(text("""
                update pnc.vulnerabilities set deleted_at=now(), modified_by=:actor, modified_at=now()
                where tenant_id=:tenant_id and id=:id and deleted_at is null
            """), {"tenant_id": str(tenant_id), "id": str(vulnerability_id), "actor": str(actor_id)})
            return result.rowcount == 1

    @staticmethod
    def _model(row) -> Vulnerability:
        return Vulnerability(id=row["id"], tenant_id=row["tenant_id"], mnemonic=row["mnemonic"],
            application=row["application"], repository=row["repository"], title=row["title"], category=row["category"],
            severity=Severity(row["severity"]), cve=row["cve"], cwe=row["cwe"], cvss=float(row["cvss"]) if row["cvss"] is not None else None,
            status=FindingStatus(row["status"]), ai_confidence=row["ai_confidence"], created_at=row["created_at"])


class SqlAuditRepository:
    def append(self, event: AuditEvent) -> None:
        with transaction(event.tenant_id) as session:
            session.execute(text("""
                insert into pnc.audit_events(tenant_id, event_type, aggregate_type, aggregate_id,
                  actor_user_id, payload, occurred_at)
                values (:tenant_id, :event_type, 'vulnerability', :aggregate_id, :actor, '{}'::jsonb, :occurred_at)
            """), {"tenant_id": str(event.tenant_id), "event_type": event.event_type,
                    "aggregate_id": str(event.aggregate_id), "actor": str(event.actor_id),
                    "occurred_at": event.occurred_at or datetime.now(timezone.utc)})

    def list(self, tenant_id: UUID) -> list[AuditEvent]:
        with transaction(tenant_id) as session:
            rows = session.execute(text("""
                select event_type, aggregate_id, actor_user_id, tenant_id, occurred_at
                from pnc.audit_events
                where tenant_id = :tenant_id
                order by occurred_at desc
                limit 1000
            """), {"tenant_id": str(tenant_id)}).mappings()
            return [AuditEvent(event_type=row["event_type"], aggregate_id=row["aggregate_id"],
                actor_id=row["actor_user_id"], tenant_id=row["tenant_id"], occurred_at=row["occurred_at"])
                for row in rows]
