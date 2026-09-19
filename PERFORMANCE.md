# Repository scan performance redesign

## Root cause

The HTTP `202` was never the expensive operation. It only enqueues an in-process
job. The expensive path was the worker: recursive traversal, per-file hashing,
file reads, regex analysis, and (in the non-demo profile) persistence. The
separate remediation workflow is deterministic and does not call an LLM. LLM
time is therefore only attributable when the Copilot endpoint is used; it is
now timed independently as `ai.llm_call`.

Every job now exposes `timeline.events` and `timeline.report` through polling.
Events include an operation, duration, timestamp, and (for file operations) the
exact file path. The report aggregates stages and returns the top five
bottlenecks. Completed local scans also include the report in `result.performance`.

## Architecture

```text
Angular UI
   | POST (202) + polling /mvp/jobs/{id} or /jobs/{id}
FastAPI timing middleware (request id, HTTP duration)
   | in-process job registry (replace with Redis/Celery in production)
Background worker + TimingTimeline
   |-- download / ZIP extraction timing
   |-- repository discovery + allowlist filtering
   |-- Git diff/untracked incremental selection
   |-- SHA-256 cache reuse
   |-- prioritized ThreadPoolExecutor file analysis
   |-- deterministic regex detection + classification
   |-- report generation + batched persistence
Progressive job response: phase, files, vulnerabilities, percentage, timeline
```

## Scan policy

Only Python, TypeScript, HTML, and the named project/configuration files are
eligible. Dependency/build/VCS/cache directories are pruned before traversal.
Security-sensitive path terms are sorted first. Git working trees scan changed
and untracked files; unchanged files reuse process-local hash/findings entries.
`FAST_DEMO_MODE=true` limits the prioritized set to 200 files and uses the
configured worker pool (`SCAN_WORKERS`, default 8).

## Expected timing

For the reported 50,000-file / 250 MB repository, the old path can spend minutes
walking irrelevant directories and reading files. With the allowlist, directory
pruning, 1 MB file limit, incremental cache, and eight workers, a warm unchanged
scan should usually be seconds. A cold fast-demo scan is expected to be roughly
5–30 seconds on a developer laptop, but the exact result depends on disk speed,
file sizes, and rule matches. No honest implementation can guarantee `<60s`
without measuring the target repository; the performance report is the source
of truth.

## Production recommendations

1. Move jobs and scan cache to Redis/PostgreSQL (current state is process-local).
2. Keep one scan per repository revision and persist findings with a revision
   key, not append-only duplicates.
3. Keep AI calls out of per-file scanning; batch or defer enrichment after the
   deterministic report.
4. Set a hard worker/job deadline and expose partial results when cancellation
   occurs after a critical finding.
5. Load-test with the real repository and compare `timeline.report` before and
   after each change.

## Read-path optimization

The demo profile now uses a bounded 60-second process-local TTL cache for
dashboard metrics, vulnerabilities, application inventory, and admin users. Mutations invalidate
the affected key. This is safe for a single demo worker only; configure a Redis
adapter before running multiple workers so cache values and invalidation are
shared.

SQLAlchemy cursor hooks record `database.query` timeline events and emit a
`[SLOW-QUERY]` warning for queries at or above 100 ms. Review those statements
with `EXPLAIN (ANALYZE, BUFFERS)` before adding indexes. Recommended PostgreSQL
indexes for the current read paths are:

```sql
create index concurrently if not exists ix_vulnerabilities_tenant_created
  on pnc.vulnerabilities (tenant_id, created_at desc)
  where deleted_at is null;
create index concurrently if not exists ix_vulnerabilities_tenant_status
  on pnc.vulnerabilities (tenant_id, status)
  where deleted_at is null;
create index concurrently if not exists ix_audit_events_tenant_occurred
  on pnc.audit_events (tenant_id, occurred_at desc);
create index concurrently if not exists ix_mvp_read_models_tenant_type_modified
  on pnc.mvp_read_models (tenant_id, record_type, modified_at desc);
```

## Demo and WatchFiles commands

Do not use reload mode for the sub-60-second demo; it adds filesystem watcher
and restart noise to the measured path:

```powershell
cd C:\Users\GCCHackVM\hackthon\PNCAgent\PNCAI\backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level warning
```

For development reloads, exclude `tests`, `logs`, `tmp`, `.git`, `.angular`,
`__pycache__`, `dist`, and `build` from the editor/watch configuration and keep
generated logs outside the source tree. The frontend production check is:

```powershell
cd C:\Users\GCCHackVM\hackthon\PNCAgent\PNCAI\frontend
npm run build
```

The `/api/v1/dashboard/metrics` response includes the normal request timing
headers (`X-Process-Time-Ms`, `X-Request-ID`). Scan polling exposes the live
timeline and completed `performance.report`, which is the authoritative source
for discovery, filtering, reading, analysis, persistence, and bottleneck time.