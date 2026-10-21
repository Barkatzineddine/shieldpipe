"""Security regression tests. Each test maps to a threat in docs/threat-model.md."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.ratelimit import SlidingWindowLimiter
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, JWT_SECRET


def _claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": "1",
        "iss": "shieldpipe",
        "aud": "shieldpipe-api",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "jti": "test",
    }
    claims.update(overrides)
    return claims


# --- S1 Spoofing: authentication and tokens -------------------------------------------


def test_protected_routes_require_a_token(client: TestClient) -> None:
    for method, path in [
        ("get", "/api/v1/incidents"),
        ("post", "/api/v1/incidents"),
        ("get", "/api/v1/users"),
        ("get", "/api/v1/auth/me"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code == 401, path
        assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "token",
    [
        jwt.encode(_claims(), None, algorithm="none"),  # alg=none
        jwt.encode(_claims(), "wrong-secret-" + "y" * 40, algorithm="HS256"),  # forged
        jwt.encode(_claims(exp=datetime.now(UTC) - timedelta(minutes=1)), JWT_SECRET),  # expired
        jwt.encode(_claims(aud="another-service"), JWT_SECRET),  # wrong audience
        jwt.encode(_claims(iss="evil"), JWT_SECRET),  # wrong issuer
        jwt.encode({k: v for k, v in _claims().items() if k != "jti"}, JWT_SECRET),  # missing claim
        jwt.encode(_claims(sub="999"), JWT_SECRET),  # unknown user
        jwt.encode(_claims(sub="not-a-number"), JWT_SECRET),
        "not.a.jwt",
    ],
    ids=["alg-none", "forged", "expired", "audience", "issuer", "no-jti", "ghost", "bad-sub", "junk"],
)
def test_invalid_tokens_are_rejected(client: TestClient, token: str) -> None:
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_login_does_not_reveal_whether_a_user_exists(client: TestClient) -> None:
    unknown = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "whatever-1234"})
    wrong = client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": "wrong-password-1"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_brute_force_is_throttled(client: TestClient) -> None:
    for _ in range(3):
        bad = client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": "guess-guess-1"})
        assert bad.status_code == 401

    blocked = client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert blocked.status_code == 429  # locked even with the right password
    assert int(blocked.headers["retry-after"]) > 0


def test_password_spraying_is_throttled_per_ip(client: TestClient) -> None:
    # 3 attempts per account, 12 per IP: spraying 12 different accounts gets blocked.
    for i in range(12):
        client.post("/api/v1/auth/login", json={"username": f"user{i}", "password": "Winter2026!!"})
    blocked = client.post("/api/v1/auth/login", json={"username": "fresh-user", "password": "x" * 12})
    assert blocked.status_code == 429


def test_sliding_window_expires() -> None:
    now = [0.0]
    limiter = SlidingWindowLimiter(max_events=2, window_seconds=10, clock=lambda: now[0])
    limiter.hit("k")
    limiter.hit("k")
    assert limiter.retry_after("k") == pytest.approx(10)
    now[0] = 10.5
    assert limiter.retry_after("k") == 0


@pytest.mark.parametrize(
    ("password", "reason"),
    [("short-pass", "too short"), ("frank-and-more-text", "contains username")],
)
def test_password_policy(
    client: TestClient, admin_headers: dict[str, str], password: str, reason: str
) -> None:
    response = client.post(
        "/api/v1/users", json={"username": "frank", "password": password}, headers=admin_headers
    )
    assert response.status_code == 422, reason


def test_service_refuses_short_jwt_secret() -> None:
    with pytest.raises(ValueError, match="at least 32 characters"):
        Settings(jwt_secret="too-short", database_url="sqlite://")


# --- E Elevation of privilege / broken access control ----------------------------------


def test_analyst_cannot_read_or_edit_another_analysts_incident(client: TestClient, make_analyst) -> None:
    alice, mallory = make_analyst("alice"), make_analyst("mallory")
    incident = client.post(
        "/api/v1/incidents", json={"title": "Alice's case", "severity": "low"}, headers=alice
    ).json()
    url = f"/api/v1/incidents/{incident['id']}"

    # IDOR: same 404 as a non-existent ID, so IDs cannot be probed.
    assert client.get(url, headers=mallory).status_code == 404
    assert client.patch(url, json={"status": "resolved"}, headers=mallory).status_code == 404
    assert client.get("/api/v1/incidents", headers=mallory).json() == []


def test_analyst_cannot_use_admin_endpoints(client: TestClient, make_analyst) -> None:
    analyst = make_analyst("grace")
    incident = client.post(
        "/api/v1/incidents", json={"title": "Own case", "severity": "low"}, headers=analyst
    ).json()

    assert client.delete(f"/api/v1/incidents/{incident['id']}", headers=analyst).status_code == 403
    assert client.get("/api/v1/users", headers=analyst).status_code == 403
    escalation = client.post(
        "/api/v1/users",
        json={"username": "grace2", "password": "a-very-long-password", "role": "admin"},
        headers=analyst,
    )
    assert escalation.status_code == 403


@pytest.mark.parametrize("extra", [{"owner_id": 1}, {"id": "x"}, {"status": "resolved"}])
def test_mass_assignment_is_rejected(client: TestClient, make_analyst, extra: dict) -> None:
    analyst = make_analyst("heidi")
    body = {"title": "Valid title", "severity": "low", **extra}
    assert client.post("/api/v1/incidents", json=body, headers=analyst).status_code == 422


# --- T Tampering / injection ---------------------------------------------------------


@pytest.mark.parametrize("payload", ["' OR 1=1 --", "%", "_", "\\", "'; DROP TABLE incidents; --"])
def test_search_is_not_injectable(
    client: TestClient, admin_headers: dict[str, str], make_analyst, payload: str
) -> None:
    client.post("/api/v1/incidents", json={"title": "Admin only", "severity": "high"}, headers=admin_headers)
    analyst = make_analyst("ivan")
    client.post("/api/v1/incidents", json={"title": "Ivan case", "severity": "low"}, headers=analyst)

    response = client.get("/api/v1/incidents", params={"q": payload}, headers=analyst)
    assert response.status_code == 200
    assert response.json() == []  # no data from other users, wildcards are literal
    # The table still exists and still holds both incidents.
    assert len(client.get("/api/v1/incidents", headers=admin_headers).json()) == 2


def test_stored_xss_payload_is_returned_as_inert_json(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    payload = "<script>alert(document.cookie)</script>"
    response = client.post(
        "/api/v1/incidents", json={"title": payload, "severity": "low"}, headers=admin_headers
    )
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert response.json()["title"] == payload


def test_invalid_incident_id_is_rejected(client: TestClient, admin_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/incidents/../../etc/passwd", headers=admin_headers)
    assert response.status_code in (404, 422)
    assert client.get("/api/v1/incidents/not-a-uuid", headers=admin_headers).status_code == 422


# --- D Denial of service ---------------------------------------------------------------


def test_oversized_body_is_rejected(client: TestClient, admin_headers: dict[str, str]) -> None:
    body = {"title": "Big", "severity": "low", "description": "A" * 10_000}
    response = client.post("/api/v1/incidents", json=body, headers=admin_headers)
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"


def test_oversized_streamed_body_is_rejected(client: TestClient, admin_headers: dict[str, str]) -> None:
    def chunks():
        yield b'{"title": "Big", "severity": "low", "description": "'
        for _ in range(10):
            yield b"A" * 1000
        yield b'"}'

    headers = {**admin_headers, "Content-Type": "application/json"}
    response = client.post("/api/v1/incidents", content=chunks(), headers=headers)
    assert response.status_code == 413


def test_pagination_is_capped(client: TestClient, admin_headers: dict[str, str]) -> None:
    assert client.get("/api/v1/incidents", params={"limit": 1000}, headers=admin_headers).status_code == 422


# --- I Information disclosure ----------------------------------------------------------


def test_security_headers_on_every_response(client: TestClient) -> None:
    for path in ["/healthz", "/does-not-exist"]:
        headers = client.get(path).headers
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["cache-control"] == "no-store"
        assert "strict-transport-security" in headers
        assert "server" not in headers


def test_request_id_is_propagated_or_generated(client: TestClient) -> None:
    echoed = client.get("/healthz", headers={"X-Request-ID": "trace-12345678"})
    assert echoed.headers["x-request-id"] == "trace-12345678"

    replaced = client.get("/healthz", headers={"X-Request-ID": "<script>bad id</script>"})
    assert replaced.headers["x-request-id"] != "<script>bad id</script>"


def test_openapi_and_docs_hidden_by_default(settings: Settings) -> None:
    production = settings.model_copy(update={"expose_openapi": False})
    with TestClient(create_app(production)) as client:
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404


def test_unhandled_errors_do_not_leak_details(settings: Settings) -> None:
    app = create_app(settings)

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("secret internal detail")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/boom")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "secret" not in response.text


# --- R Repudiation: audit trail --------------------------------------------------------


def test_security_events_are_audited(client: TestClient, capsys: pytest.CaptureFixture[str]) -> None:
    client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": "wrong-password-1"})
    client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    out = capsys.readouterr().out

    assert '"event": "auth.login", "outcome": "failure"' in out
    assert '"event": "auth.login", "outcome": "success"' in out
    assert ADMIN_PASSWORD not in out  # secrets never reach the logs
