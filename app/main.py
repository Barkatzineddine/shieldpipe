import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from . import __version__
from .audit import audit, configure_audit_logging
from .config import Settings, get_settings
from .db import Base, make_engine
from .middleware import SecurityMiddleware
from .models import Role, User
from .ratelimit import LoginThrottle
from .routers import auth, health, incidents, users
from .schemas import UserCreate
from .security import hash_password

logger = logging.getLogger("shieldpipe")


def _bootstrap_admin(session_factory: sessionmaker[Session], settings: Settings) -> None:
    """Creates the first admin from env vars, only when the user table is empty."""
    if not settings.bootstrap_admin_username or settings.bootstrap_admin_password is None:
        return
    with session_factory() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return
        # Same validation as the API, so the bootstrap password follows the policy too.
        account = UserCreate(
            username=settings.bootstrap_admin_username,
            password=settings.bootstrap_admin_password.get_secret_value(),
            role=Role.ADMIN,
        )
        db.add(
            User(
                username=account.username,
                password_hash=hash_password(account.password),
                role=Role.ADMIN,
            )
        )
        db.commit()
    audit("user.bootstrap", outcome="success", actor="system", target=account.username)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_audit_logging()

    engine = make_engine(settings.database_url)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        Base.metadata.create_all(engine)
        _bootstrap_admin(session_factory, settings)
        yield
        engine.dispose()

    app = FastAPI(
        title="ShieldPipe Incident API",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.expose_openapi else None,
    )
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.login_throttle = LoginThrottle(settings.login_max_attempts, settings.login_window_seconds)

    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_body_bytes)

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        # Log the details server-side, return nothing internal to the client.
        logger.error(
            "unhandled error request_id=%s",
            getattr(request.state, "request_id", None),
            exc_info=exc,
        )
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(incidents.router)
    return app
