# Security Governance logical ERD

```mermaid
erDiagram
  Applications ||--o{ Repositories : owns
  Repositories ||--o{ ScanJobs : scanned_by
  ScanJobs ||--o{ ScanResults : produces
  Applications ||--o{ Finding : contains
  Repositories ||--o{ Finding : exposes
  ScanJobs ||--o{ Finding : discovers
  Finding ||--o{ FindingHistory : changes
  Finding ||--o{ FindingComments : discusses
  Finding ||--o{ FindingEvidence : proves
  Finding ||--o{ Remediation : remediated_by
  Remediation ||--o{ RemediationHistory : versions
  Repositories ||--o{ CodeChange : changes
  CodeChange ||--o{ CodeChangeHistory : versions
  CodeChange }o--o| Finding : relates_to
  Repositories ||--o{ PullRequest : targets
  PullRequest ||--o{ PullRequestHistory : reviewed_by
  Applications ||--o{ ApprovalRequest : requests
  ApprovalRequest ||--o{ ApprovalHistory : decided_by
  WorkflowInstance ||--o{ WorkflowHistory : transitions
  Finding ||--o{ RiskAcceptance : accepted
  Applications ||--o{ PolicyException : grants
  ComplianceControl ||--o{ ComplianceAssessment : assessed
  Applications ||--o{ ComplianceAssessment : assessed_for
  Applications ||--o{ AuditLog : audited
```

`history.*` is append-only event history; `audit.AuditLog` is the centralized cross-entity audit stream. `dbo.*` and `workflow.*` are current-state projections used for efficient reads. `security.Users` supplies actor identity and is referenced by command records.

## History-screen query model

Every entity history tab should call a server-side endpoint that unions its domain history stream with `audit.vw_UnifiedTimeline`, ordered by UTC timestamp and `AuditId`/history key. The client must not reconstruct history from current API payloads. Timeline entries should include actor, action, reason/comment, previous value, new value, and evidence/change references.

## Reporting model

Reports are read-only projections over the audit/history views. A report request itself is persisted as `UserActivity` plus an `EXPORT` audit event; the generated artifact should be stored outside SQL with a content hash in an evidence or report artifact table in the next migration.