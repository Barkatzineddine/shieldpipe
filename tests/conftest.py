from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ADMIN_USER = "admin"
ADMIN_PASSWORD = "correct-horse-battery-staple"
JWT_SECRET = "test-only-secret-" + "x" * 40


@pytest.fixture
def settings() -> Settings:
    return Settings(
        jwt_secret=JWT_SECRET,
        database_url="sqlite://",
        bootstrap_admin_username=ADMIN_USER,
        bootstrap_admin_password=ADMIN_PASSWORD,
        login_max_attempts=3,
        login_window_seconds=60,
        max_body_bytes=4096,
        expose_openapi=True,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def admin_headers(client: TestClient) -> dict[str, str]:
    return login(client, ADMIN_USER, ADMIN_PASSWORD)


@pytest.fixture
def make_analyst(client: TestClient, admin_headers: dict[str, str]) -> Callable[[str], dict[str, str]]:
    def _make(username: str) -> dict[str, str]:
        password = "analyst-passphrase-for-tests"
        response = client.post(
            "/api/v1/users",
            json={"username": username, "password": password, "role": "analyst"},
            headers=admin_headers,
        )
        assert response.status_code == 201, response.text
        return login(client, username, password)

    return _make
