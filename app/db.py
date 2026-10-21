from pathlib import Path

from sqlalchemy import Engine, create_engine, make_url
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)

    if url.database in (None, "", ":memory:"):
        # One shared connection, so every session sees the same in-memory database.
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)

    Path(url.database).parent.mkdir(parents=True, exist_ok=True)
    return create_engine(url, connect_args={"check_same_thread": False})
