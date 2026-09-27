"""Health endpoint tests."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_returns_healthy(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()

    assert body["success"] is True
    assert body["error"] is None
    assert body["data"]["status"] == "healthy"
    assert body["data"]["database"] == "connected"
    assert body["data"]["version"]


def test_root_identifies_application(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "IPsec Sentinel"
