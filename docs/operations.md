# Operations, DR, and Rollback

## Observability

Instrument FastAPI, workers, database calls, queue operations, and integrations with OpenTelemetry. Export metrics to Prometheus/Grafana and structured JSON logs to ELK. Required alerts: API error rate, p95 latency, queue age, worker failures, approval SLA breach, database saturation, replication lag, and scan ingestion lag.

## DR

Use multi-AZ PostgreSQL with PITR and encrypted daily snapshots, replicated object storage for evidence, quorum queues, and versioned deployment manifests. RPO target: 15 minutes; RTO target: 60 minutes. Test failover quarterly and document evidence.

## Rollback

Application: Argo Rollouts blue/green or canary with health and security gates; rollback to the last signed image. Database: backward-compatible expand/contract migrations only; restore to a timestamp for destructive incidents. Remediation: never auto-merge without approval; revert PR, redeploy known-good artifact, close/reconcile ITSM records, and append an audit event.
