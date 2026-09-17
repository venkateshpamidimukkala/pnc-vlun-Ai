"""Demo authentication records used by the local Angular login flow."""
from uuid import UUID

from pydantic import BaseModel, Field

DEMO_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

DEMO_USERS = {
    "analyst@pnc.local": {"password": "Analyst@123", "user_id": UUID("00000000-0000-0000-0000-000000000001"), "role": "SECURITY_ANALYST", "name": "Demo Security Analyst"},
    "reviewer@pnc.local": {"password": "Reviewer@123", "user_id": UUID("00000000-0000-0000-0000-000000000002"), "role": "SECURITY_REVIEWER", "name": "Demo Security Reviewer"},
    "admin@pnc.local": {"password": "Admin@123", "user_id": UUID("00000000-0000-0000-0000-000000000003"), "role": "PLATFORM_ADMIN", "name": "Demo Platform Administrator"},
}


class LoginRequest(BaseModel):
    email: str = Field(min_length=5)
    password: str = Field(min_length=1)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5)
    password: str = Field(min_length=8)
    role: str = "SECURITY_ANALYST"


class AuthResponse(BaseModel):
    user_id: UUID
    tenant_id: UUID
    name: str
    email: str
    role: str


def authenticate(payload: LoginRequest) -> AuthResponse | None:
    user = DEMO_USERS.get(str(payload.email).lower())
    if not user or user["password"] != payload.password:
        return None
    return AuthResponse(user_id=user["user_id"], tenant_id=DEMO_TENANT_ID, name=user["name"], email=payload.email, role=user["role"])


def register(payload: RegisterRequest) -> AuthResponse:
    email = str(payload.email).lower()
    if email in DEMO_USERS:
        raise ValueError("An account with this email already exists")
    role = payload.role if payload.role in {"SECURITY_ANALYST", "SECURITY_REVIEWER"} else "SECURITY_ANALYST"
    user_id = UUID(int=4 + len(DEMO_USERS))
    DEMO_USERS[email] = {"password": payload.password, "user_id": user_id, "role": role, "name": payload.name}
    return AuthResponse(user_id=user_id, tenant_id=DEMO_TENANT_ID, name=payload.name, email=payload.email, role=role)