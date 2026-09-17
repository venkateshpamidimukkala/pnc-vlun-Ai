# Security Architecture

- Azure AD OIDC is the system of record for identity; validate issuer, audience, signature, expiry, nonce, and tenant claims.
- Enforce tenant isolation in API authorization and PostgreSQL RLS (`app.tenant_id`).
- RBAC permissions are action/resource scoped; MFA and privileged step-up authentication are required for merge, deployment, policy, and administration actions.
- Encrypt TLS 1.2+ in transit and managed PostgreSQL encryption at rest. Store credentials/tokens in Azure Key Vault or Kubernetes external secrets.
- Treat repository content and AI output as untrusted. Sandbox clones/builds, disable network by default, redact secrets, scan generated diffs, enforce allowlisted tools, and require human approvals.
- Immutable audit events capture actor, tenant, correlation ID, before/after hashes, evidence URIs, approval decisions, and deployment/rollback references.
- Apply OWASP ASVS controls, SAST/DAST/SCA, dependency pinning, signed images (cosign), SBOMs, admission policies, and network policies.
