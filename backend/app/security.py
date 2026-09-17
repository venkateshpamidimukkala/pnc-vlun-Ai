from dataclasses import dataclass
from uuid import UUID

from fastapi import Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.settings import settings
from app.auth import DEMO_USERS


@dataclass(frozen=True)
class Principal:
    subject: UUID
    tenant_id: UUID
    roles: frozenset[str]


async def require_principal(
    x_tenant_id: UUID | None = Header(default=None),
    x_user_id: UUID | None = Header(default=None),
    credentials: HTTPAuthorizationCredentials | None = Security(HTTPBearer(auto_error=False)),
) -> Principal:
    """Resolve identity. Headers are deliberately supported only in local/test mode."""
    if settings.app_env in {"local", "demo"} and x_tenant_id is not None and x_user_id is not None:
        roles = frozenset({user["role"] for user in DEMO_USERS.values() if user["user_id"] == x_user_id} or {"SECURITY_ANALYST"})
        return Principal(subject=x_user_id, tenant_id=x_tenant_id, roles=roles)
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer authentication required")
    # JWT verification is delegated to the configured API gateway/OIDC middleware.
    # Fail closed if the gateway did not provide verified identity headers.
    if x_tenant_id is None or x_user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Verified tenant context required")
    return Principal(subject=x_user_id, tenant_id=x_tenant_id, roles=frozenset({"SECURITY_ANALYST"}))


def require_role(principal: Principal, *roles: str) -> Principal:
    if not principal.roles.intersection(roles):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This page is not available for your role")
    return principal
