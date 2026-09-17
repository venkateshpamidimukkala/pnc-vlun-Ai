# PNC Vuln AI

Enterprise autonomous vulnerability detection, classification, remediation, validation, approval, compliance, and deployment platform.

## Repository layout

- `backend/` — FastAPI platform API and agent orchestration foundation.
- `frontend/` — Angular 22 application shell and banking dashboard vertical slice.
- `database/` — PostgreSQL 17 / pgvector schema and seed migrations.
- `deploy/` — Docker Compose and Kubernetes deployment artifacts.
- `docs/` — architecture, security, operations, diagrams, and implementation roadmap.
- `.github/workflows/` — CI quality and security pipeline.

## Local development

```powershell
Copy-Item .env.example .env
docker compose -f deploy/docker-compose.yml up --build
```

API: `http://localhost:8000/docs`  |  Health: `http://localhost:8000/health`

The Docker demo uses PostgreSQL with username `postgres`, password `admin`, and database `pnc_vuln_ai`. The dependency-free `start-app.bat` walkthrough uses the in-memory repository and does not require PostgreSQL.

For the live demo, run `start-app.bat`. It starts the Angular UI at `http://localhost:4200` and the API at `http://localhost:8000` with `APP_ENV=local`, `DEMO_DATA_ENABLED=true`, and external integrations disabled. It seeds PME, PRE, and PST findings and supports scan import, filtering, remediation workflow creation, approvals, audit events, and grounded Copilot responses. Use `reviewer@pnc.local` / `Reviewer@123` to exercise approvals, or `analyst@pnc.local` / `Analyst@123` for analyst workflows.

## Production principles

Identity is delegated to Azure AD/OIDC; services validate JWTs and enforce tenant-aware RBAC. Secrets come from a managed secret store, not environment files. All mutations emit audit events. Deployments use immutable images, database migrations, progressive delivery, and automated rollback gates.
