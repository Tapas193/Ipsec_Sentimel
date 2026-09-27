"""Phase 3 API tests: assessment, findings CRUD-ish reads, idempotency."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Analysis, AnalysisStatus
from tests.synthetic_pcap import build_ipsec_pcap, build_plaintext_pcap

EXPECTED_IPSEC_RULES = {"IPSEC-CRYPTO-001", "IPSEC-IKE-001", "IPSEC-META-001"}


def _analyze(client: TestClient, path: str) -> str:
    with open(path, "rb") as fh:
        client.post(
            "/api/v1/captures",
            files={"file": ("capture.pcap", fh, "application/octet-stream")},
        )
    capture_id = client.get("/api/v1/captures").json()["data"]["items"][0]["capture_id"]
    client.post(f"/api/v1/captures/{capture_id}/analyze")
    for _ in range(200):
        jobs = client.get("/api/v1/analysis-jobs").json()["data"]["items"]
        if not jobs:
            time.sleep(0.02)
            continue
        job = jobs[0]
        if job["status"] in ("completed", "failed", "partial"):
            break
        time.sleep(0.02)
    assert job["status"] == "completed", job["error_message"]
    analyses = client.get("/api/v1/analyses").json()["data"]["items"]
    assert analyses and analyses[0]["status"] == "completed"
    analysis_id = analyses[0]["analysis_id"]
    assert isinstance(analysis_id, str)
    return analysis_id


@pytest.fixture()
def ipsec_analysis_key(client: TestClient, tmp_path: object) -> str:
    path = f"{tmp_path}/ipsec.pcap"
    build_ipsec_pcap(include_ah=True, ike_count=4, esp_count=10).write(path)
    return _analyze(client, path)


@pytest.fixture()
def plaintext_analysis_key(client: TestClient, tmp_path: object) -> str:
    path = f"{tmp_path}/plain.pcap"
    build_plaintext_pcap().write(path)
    return _analyze(client, path)


class TestAssessEndpoint:
    def test_assess_creates_expected_findings(
        self, client: TestClient, ipsec_analysis_key: str
    ) -> None:
        response = client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess")
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        result = body["data"]
        assert result["analysis_id"] == ipsec_analysis_key
        assert result["rule_version"].count(".") == 2
        assert result["rules_run"] == 10
        assert result["created"] >= len(EXPECTED_IPSEC_RULES)
        assert result["duration_ms"] >= 0
        assert result["completed_at"]
        rule_ids_run = {r["rule_id"] for r in result["rules"]}
        assert EXPECTED_IPSEC_RULES.issubset(rule_ids_run)

    def test_assess_is_idempotent(self, client: TestClient, ipsec_analysis_key: str) -> None:
        first = client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess").json()["data"]
        second = client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess").json()["data"]
        assert second["created"] == 0
        assert second["total_findings"] == first["total_findings"]

    def test_assess_plaintext_capture_yields_no_findings(
        self, client: TestClient, plaintext_analysis_key: str
    ) -> None:
        result = client.post(f"/api/v1/analyses/{plaintext_analysis_key}/assess").json()["data"]
        assert result["created"] == 0
        assert result["total_findings"] == 0

    def test_assess_rejects_non_completed_analysis(
        self, db_session: Session, client: TestClient
    ) -> None:
        analysis = Analysis(status=AnalysisStatus.FAILED, capture_id="capture-fake-2")
        analysis.analysis_id = "ANL-NOT-COMPLETE-000001"
        db_session.add(analysis)
        db_session.commit()
        response = client.post("/api/v1/analyses/ANL-NOT-COMPLETE-000001/assess")
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "ANALYSIS_NOT_ASSESSABLE"

    def test_assess_unknown_analysis_returns_404(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyses/ANL-999999/assess")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"


class TestFindingsEndpoint:
    def test_list_findings(self, client: TestClient, ipsec_analysis_key: str) -> None:
        client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess")
        response = client.get(f"/api/v1/analyses/{ipsec_analysis_key}/findings")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["pagination"]["total"] >= len(EXPECTED_IPSEC_RULES)
        items = data["items"]
        assert items, "expected at least one finding"
        first = items[0]
        internal_analysis_id = client.get(f"/api/v1/analyses/{ipsec_analysis_key}").json()["data"][
            "analysis"
        ]["id"]
        assert first["analysis_id"] == internal_analysis_id
        assert first["rule_id"]
        assert first["finding_id"].startswith("SEC-")
        assert first["severity"]
        assert first["confidence"]
        assert first["status"] == "open"
        assert first["evidence"] is not None
        assert first["evidence"]["items"]
        assert isinstance(first["evidence"]["packet_ids"], list)

    def test_get_finding_by_human_id(self, client: TestClient, ipsec_analysis_key: str) -> None:
        client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess")
        items = client.get(f"/api/v1/analyses/{ipsec_analysis_key}/findings").json()["data"][
            "items"
        ]
        finding = items[0]
        response = client.get(
            f"/api/v1/analyses/{ipsec_analysis_key}/findings/{finding['finding_id']}"
        )
        assert response.status_code == 200
        assert response.json()["data"]["id"] == finding["id"]

    def test_get_finding_by_uuid(self, client: TestClient, ipsec_analysis_key: str) -> None:
        client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess")
        items = client.get(f"/api/v1/analyses/{ipsec_analysis_key}/findings").json()["data"][
            "items"
        ]
        response = client.get(f"/api/v1/analyses/{ipsec_analysis_key}/findings/{items[0]['id']}")
        assert response.status_code == 200

    def test_get_finding_unknown_rule(self, client: TestClient, ipsec_analysis_key: str) -> None:
        response = client.get(f"/api/v1/analyses/{ipsec_analysis_key}/findings/SEC-999999")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "FINDING_NOT_FOUND"

    def test_findings_unknown_analysis(self, client: TestClient) -> None:
        response = client.get("/api/v1/analyses/ANL-999999/findings")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"


class TestAssessmentUnits:
    def test_secret_ids_are_sequential(self, client: TestClient, ipsec_analysis_key: str) -> None:
        client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess")
        items = client.get(f"/api/v1/analyses/{ipsec_analysis_key}/findings").json()["data"][
            "items"
        ]
        suffix = [int(item["finding_id"].split("-")[1]) for item in items]
        assert suffix == sorted(suffix)
        assert suffix[0] == 1

    def test_rule_version_stamped_on_analysis(
        self, client: TestClient, ipsec_analysis_key: str
    ) -> None:
        client.post(f"/api/v1/analyses/{ipsec_analysis_key}/assess")
        analysis = client.get(f"/api/v1/analyses/{ipsec_analysis_key}").json()["data"]["analysis"]
        assert analysis["rule_version"].count(".") == 2
