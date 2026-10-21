import math

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings
from ..deps import get_current_user, get_db, get_settings, get_throttle
from ..models import User
from ..ratelimit import LoginThrottle
from ..schemas import LoginRequest, TokenResponse, UserOut
from ..security import create_access_token, hash_password, needs_rehash, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    throttle: LoginThrottle = Depends(get_throttle),
) -> TokenResponse:
    ip = request.client.host if request.client else "unknown"
    username = body.username.strip().lower()

    retry_after = throttle.retry_after(ip, username)
    if retry_after:
        audit("auth.login", outcome="blocked", request=request, username=username)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts, try again later",
            headers={"Retry-After": str(math.ceil(retry_after))},
        )

    user = db.scalar(select(User).where(User.username == username))
    # Always run the hash check, even for unknown users, so timing does not leak them.
    valid = verify_password(body.password, user.password_hash if user else None)
    if user is None or not valid:
        throttle.record_failure(ip, username)
        audit("auth.login", outcome="failure", request=request, username=username)
        # Same message for unknown users and wrong passwords.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    throttle.record_success(username)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
        db.commit()

    token, ttl = create_access_token(subject=str(user.id), settings=settings)
    audit("auth.login", outcome="success", request=request, actor=user.username)
    return TokenResponse(access_token=token, expires_in=ttl)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
