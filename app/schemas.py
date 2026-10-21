from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from .models import Role, Severity, Status

Username = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{3,32}$")]
# NIST SP 800-63B: favour length over composition rules.
Password = Annotated[str, StringConstraints(min_length=12, max_length=128)]
Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=120)]
Description = Annotated[str, StringConstraints(max_length=5000)]


class StrictModel(BaseModel):
    """Rejects unknown fields, so clients cannot mass-assign owner_id, role, etc."""

    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type name, not a secret
    expires_in: int


class UserCreate(StrictModel):
    username: Username
    password: Password
    role: Role = Role.ANALYST

    @model_validator(mode="after")
    def _password_not_based_on_username(self) -> "UserCreate":
        if self.username in self.password.lower():
            raise ValueError("password must not contain the username")
        return self


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role


class IncidentCreate(StrictModel):
    title: Title
    description: Description = ""
    severity: Severity


class IncidentUpdate(StrictModel):
    title: Title | None = None
    description: Description | None = None
    severity: Severity | None = None
    status: Status | None = None


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str
    severity: Severity
    status: Status
    owner_id: int
    created_at: datetime
    updated_at: datetime
