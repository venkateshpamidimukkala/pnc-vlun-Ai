# Security Governance database architecture

This is an isolated, SQL Server-first design for the requested audit/history platform. It does **not** modify the existing FastAPI or Angular changes in this working tree.

## Installation

Run `database/sqlserver/001_SecurityGovernanceDB.sql` with a deployment identity that can create databases and schemas. The script creates `SecurityGovernanceDB`, the required schemas, core entities, history tables, audit log, indexes, views, stored procedures, and database-level row-image audit triggers.

## Non-negotiable transaction contract

Every command handler must execute one SQL transaction:

1. Authenticate and authorize the actor.
2. Call `audit.SetContext` on the same SQL connection.
3. Append the domain history/event row with previous and new state.
4. Update only the current-state projection, if one is required for query performance.
5. Append semantic audit event with `audit.AppendEvent`.
6. Commit. On failure, roll back the entire operation.

The API must never use an in-memory dictionary as the source of truth. Background scans, notifications, exports, and workflow workers are system actors and must use the same context/audit contract.

## Event sourcing and versioning

`history.*` tables are append-only event streams. `dbo.*` and `workflow.*` tables are query projections. `VersionNo` is optimistic concurrency metadata. A command must include the expected version and reject stale writes. Deletes are soft deletes; hard deletion is reserved for controlled retention procedures and must itself be audited.

## API/UI integration contract

The current backend is FastAPI/SQLAlchemy and the current frontend is Angular. The next integration increment should add a SQL-backed unit-of-work/repository layer, not alter the existing application UI files:

- `POST /api/v1/audit/events` for explicit UI events (`COMMENT`, `EXPORT`, `DOWNLOAD`, `UPLOAD`, etc.).
- `GET /api/v1/{entity}/{id}/history` backed by `audit.vw_UnifiedTimeline` and domain history tables.
- `GET /api/v1/search` with tenant, entity, user, severity, status, and UTC date-range filters.
- Command endpoints for scans, finding transitions, remediation generation, PR actions, approval decisions, and workflow transitions. Each endpoint must use the transaction contract above.
- Angular route-level history tabs should consume the history endpoint; components must not synthesize timelines from local state.

## Security and compliance controls

- Use least-privilege SQL users: runtime read/write, migration owner, and read-only audit/reporting roles.
- Deny `UPDATE` and `DELETE` on `audit` and `history` schemas to the runtime role.
- Protect `BeforeCode`, `AfterCode`, evidence URIs, and audit records with encryption-at-rest, restricted access, and retention policy.
- Use row-level security or tenant predicates when multi-tenancy is enabled.
- Export jobs must persist a `UserActivity` row, an `AuditLog` `EXPORT` event, filter criteria, and content hash before returning the file.
- Use UTC timestamps, correlation/session IDs, and immutable content hashes for evidence and code changes.

## Relationship summary

`Applications 1--N Repositories 1--N ScanJobs 1--N ScanResults`; findings link Application, Repository, and ScanJob. Findings have append-only history, comments, evidence, remediation versions, and code changes. Code changes may produce pull requests. Applications own approval requests; approvals and workflow instances have independent history streams. Compliance controls are assessed per application. All current-state entities are captured in `audit.AuditLog` and exposed through the unified timeline view.