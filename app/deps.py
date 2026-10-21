from collections.abc import Iterator

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .audit import audit
from .config import Settings
from .models import Role, User
from .ratelimit import LoginThrottle
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_throttle(request: Request) -> LoginThrottle:
    return request.app.state.login_throttle


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> User:
    if credentials is None:
        raise _UNAUTHORIZED
    try:
        claims = decode_access_token(credentials.credentials, settings)
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, ValueError):
        audit("auth.token", outcome="failure", request=request, reason="invalid_token")
        raise _UNAUTHORIZED from None

    # The role comes from the database, not from the token, so a demotion
    # or account deletion takes effect on the next request.
    user = db.get(User, user_id)
    if user is None:
        audit("auth.token", outcome="failure", request=request, reason="unknown_subject")
        raise _UNAUTHORIZED
    return user


def require_admin(request: Request, user: User = Depends(get_current_user)) -> User:
    if user.role != Role.ADMIN:
        audit("authz.denied", outcome="failure", request=request, actor=user.username)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
