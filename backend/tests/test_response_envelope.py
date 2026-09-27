"""API response envelope structure tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def test_envelope_shape_on_list(client: TestClient, db_session: Session) -> None:
    response = client.get("/api/v1/captures")
    assert response.status_code == 200
    body = response.json()

    assert set(body.keys()) == {"success", "data", "error", "meta"}
    assert body["success"] is True
    assert body["error"] is None
    assert body["data"]["items"] == []
    assert body["data"]["pagination"]["total"] == 0
    assert body["data"]["pagination"]["total_pages"] == 1


def test_dashboard_stats_default_to_zero(client: TestClient) -> None:
    response = client.get("/api/v1/stats/dashboard")
    assert response.status_code == 200
    data = response.json()["data"]

    assert data["captures"] == 0
    assert data["analysis_jobs"] == 0
    assert data["pending_jobs"] == 0
    assert data["analyses"] == 0
    assert data["security_findings"] == 0
    assert data["reports"] == 0


def test_unknown_route_returns_404(client: TestClient) -> None:
    response = client.get("/api/v1/nope")
    assert response.status_code == 404
