"""End-to-end API tests: upload → analyze → poll → sub-resources → exports."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.analyzers.packet_analyzer.protocols.ike import parse_sa_proposals
from tests.synthetic_pcap import (
    build_ipsec_pcap,
    ikev2_sa_init_payload,
)


def _write_ipsec_pcap(tmp_path: object) -> str:
    path = str(tmp_path) + "/ipsec.pcap"
    build_ipsec_pcap(include_ah=True, ike_count=4, esp_count=10).write(path)
    return path


@pytest.fixture()
def ipsec_path(tmp_path: object) -> str:
    return _write_ipsec_pcap(tmp_path)


class TestCaptureWorkflow:
    def test_upload_analyze_and_summary(
        self, client: TestClient, ipsec_path: str, monkeypatch: object
    ) -> None:
        with open(ipsec_path, "rb") as fh:
            upload = client.post(
                "/api/v1/captures", files={"file": ("ipsec.pcap", fh, "application/octet-stream")}
            )
        assert upload.status_code == 200
        payload = upload.json()
        assert payload["success"] is True
        capture = payload["data"]
        assert capture["capture_id"].startswith("CAP-")
        assert capture["capture_format"] == "pcap"
        assert capture["status"] == "valid"

        triggered = client.post(f"/api/v1/captures/{capture['capture_id']}/analyze")
        assert triggered.status_code == 200

        jobs = client.get("/api/v1/analysis-jobs").json()["data"]["items"]
        assert jobs
        job_id = jobs[0]["id"]
        for _ in range(100):
            job = client.get(f"/api/v1/analysis-jobs/{job_id}").json()["data"]
            if job["status"] in ("completed", "failed", "partial"):
                break
            time.sleep(0.02)
        assert job["status"] == "completed"

        analyses = client.get("/api/v1/analyses").json()["data"]["items"]
        assert analyses
        analysis = analyses[0]
        assert analysis["status"] == "completed"
        assert analysis["protocol_detected"] == "yes"
        assert analysis["protocol_confidence"] == "high"
        assert analysis["ike_detected"] is True
        assert analysis["esp_detected"] is True
        assert analysis["ah_detected"] is True

        summary = client.get(f"/api/v1/analyses/{analysis['analysis_id']}").json()["data"]
        assert summary["ike_message_count"] == 4
        assert summary["esp_packet_count"] == 10
        assert summary["ah_packet_count"] == 3
        assert summary["flow_count"] >= 1
        assert "ike" in summary["protocol_observations"]

    def test_ike_proposal_details(self, client: TestClient, ipsec_path: str) -> None:
        with open(ipsec_path, "rb") as fh:
            client.post(
                "/api/v1/captures", files={"file": ("ipsec.pcap", fh, "application/octet-stream")}
            )
        capture_id = client.get("/api/v1/captures").json()["data"]["items"][0]["capture_id"]
        client.post(f"/api/v1/captures/{capture_id}/analyze")
        for _ in range(100):
            job = client.get("/api/v1/analysis-jobs").json()["data"]["items"][0]
            if job["status"] in ("completed", "failed", "partial"):
                break
            time.sleep(0.02)
        analysis_id = client.get("/api/v1/analyses").json()["data"]["items"][0]["analysis_id"]

        messages = client.get(f"/api/v1/analyses/{analysis_id}/ike-messages").json()["data"][
            "items"
        ]
        assert messages
        first = messages[0]
        assert first["version"] == "IKEv2"
        assert first["exchange_name"] == "IKE_SA_INIT"
        assert first["payload_types"] == ["SA"]
        assert first["proposals"]
        proposal = first["proposals"][0]
        assert proposal["encryption"] == "AES_GCM_16"
        assert proposal["key_length"] == 256
        assert proposal["dh_group"] == 19

    def test_flows_and_features(self, client: TestClient, ipsec_path: str) -> None:
        with open(ipsec_path, "rb") as fh:
            client.post(
                "/api/v1/captures", files={"file": ("ipsec.pcap", fh, "application/octet-stream")}
            )
        capture_id = client.get("/api/v1/captures").json()["data"]["items"][0]["capture_id"]
        client.post(f"/api/v1/captures/{capture_id}/analyze")
        for _ in range(100):
            job = client.get("/api/v1/analysis-jobs").json()["data"]["items"][0]
            if job["status"] in ("completed", "failed", "partial"):
                break
            time.sleep(0.02)
        analysis_id = client.get("/api/v1/analyses").json()["data"]["items"][0]["analysis_id"]

        flows = client.get(f"/api/v1/analyses/{analysis_id}/flows").json()["data"]["items"]
        esp_flows = [f for f in flows if f["esp_packets"] > 0]
        assert esp_flows
        assert esp_flows[0]["spi"] == "deadbeef"

        features = client.get(f"/api/v1/analyses/{analysis_id}/features").json()["data"]["items"]
        assert features
        feature_keys = set(features[0]["features"].keys())
        assert {
            "packet_count",
            "byte_count",
            "duration_seconds",
            "packets_per_second",
        } <= feature_keys

    def test_exports(self, client: TestClient, ipsec_path: str) -> None:
        with open(ipsec_path, "rb") as fh:
            client.post(
                "/api/v1/captures", files={"file": ("ipsec.pcap", fh, "application/octet-stream")}
            )
        capture_id = client.get("/api/v1/captures").json()["data"]["items"][0]["capture_id"]
        client.post(f"/api/v1/captures/{capture_id}/analyze")
        for _ in range(100):
            job = client.get("/api/v1/analysis-jobs").json()["data"]["items"][0]
            if job["status"] in ("completed", "failed", "partial"):
                break
            time.sleep(0.02)
        analysis_id = client.get("/api/v1/analyses").json()["data"]["items"][0]["analysis_id"]

        flows_csv = client.get(f"/api/v1/analyses/{analysis_id}/export/flows")
        assert flows_csv.status_code == 200
        assert "text/csv" in flows_csv.headers["content-type"]
        assert "flow_id" in flows_csv.text

        features_json = client.get(f"/api/v1/analyses/{analysis_id}/export/features")
        assert features_json.status_code == 200
        assert "application/json" in features_json.headers["content-type"]
        assert '"features"' in features_json.text

    def test_delete_capture(self, client: TestClient, ipsec_path: str) -> None:
        with open(ipsec_path, "rb") as fh:
            client.post(
                "/api/v1/captures", files={"file": ("ipsec.pcap", fh, "application/octet-stream")}
            )
        capture_id = client.get("/api/v1/captures").json()["data"]["items"][0]["capture_id"]
        deleted = client.delete(f"/api/v1/captures/{capture_id}")
        assert deleted.status_code == 200
        remaining = client.get("/api/v1/captures").json()["data"]["items"]
        assert all(c["capture_id"] != capture_id for c in remaining)

    def test_capture_not_found(self, client: TestClient) -> None:
        response = client.get("/api/v1/captures/CAP-999999")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "CAPTURE_NOT_FOUND"


def test_sa_parsing_offered_status_heuristic() -> None:
    body = ikev2_sa_init_payload()[4:]
    proposals = parse_sa_proposals(body, "IKEv2")
    assert proposals[0].status == "OFFERED"
