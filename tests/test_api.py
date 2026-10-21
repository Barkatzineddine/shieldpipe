"""Functional behaviour of the API."""

from fastapi.testclient import TestClient

from tests.conftest import ADMIN_USER


def test_health_and_readiness(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}


def test_me_returns_current_user(client: TestClient, admin_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/auth/me", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["username"] == ADMIN_USER
    assert response.json()["role"] == "admin"


def test_incident_lifecycle(client: TestClient, make_analyst) -> None:
    analyst = make_analyst("alice")
    created = client.post(
        "/api/v1/incidents",
        json={"title": "Phishing campaign on finance", "severity": "high"},
        headers=analyst,
    )
    assert created.status_code == 201
    incident = created.json()
    assert incident["status"] == "open"

    updated = client.patch(
        f"/api/v1/incidents/{incident['id']}",
        json={"status": "investigating", "description": "IOC sent to the SIEM"},
        headers=analyst,
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"

    fetched = client.get(f"/api/v1/incidents/{incident['id']}", headers=analyst)
    assert fetched.json()["description"] == "IOC sent to the SIEM"


def test_list_filters_and_search(client: TestClient, make_analyst) -> None:
    analyst = make_analyst("bob")
    for title, severity in [
        ("Brute force on VPN", "high"),
        ("Malware on laptop", "critical"),
        ("Brute force on SSH", "low"),
    ]:
        client.post("/api/v1/incidents", json={"title": title, "severity": severity}, headers=analyst)

    by_search = client.get("/api/v1/incidents", params={"q": "brute"}, headers=analyst).json()
    assert {i["title"] for i in by_search} == {"Brute force on VPN", "Brute force on SSH"}

    by_severity = client.get("/api/v1/incidents", params={"severity": "critical"}, headers=analyst)
    assert [i["title"] for i in by_severity.json()] == ["Malware on laptop"]

    by_status = client.get("/api/v1/incidents", params={"status": "resolved"}, headers=analyst)
    assert by_status.json() == []


def test_admin_can_delete_incident(client: TestClient, admin_headers: dict[str, str], make_analyst) -> None:
    analyst = make_analyst("carol")
    incident = client.post(
        "/api/v1/incidents", json={"title": "Ransomware note", "severity": "critical"}, headers=analyst
    ).json()

    assert client.delete(f"/api/v1/incidents/{incident['id']}", headers=admin_headers).status_code == 204
    assert client.get(f"/api/v1/incidents/{incident['id']}", headers=admin_headers).status_code == 404


def test_admin_lists_users(client: TestClient, admin_headers: dict[str, str], make_analyst) -> None:
    make_analyst("dave")
    usernames = [u["username"] for u in client.get("/api/v1/users", headers=admin_headers).json()]
    assert usernames == [ADMIN_USER, "dave"]


def test_duplicate_username_is_rejected(
    client: TestClient, admin_headers: dict[str, str], make_analyst
) -> None:
    make_analyst("erin")
    response = client.post(
        "/api/v1/users",
        json={"username": "erin", "password": "another-long-password-1"},
        headers=admin_headers,
    )
    assert response.status_code == 409
