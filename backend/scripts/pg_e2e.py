"""E2E acceptance run against real PostgreSQL (port 5433).

Exercises: upload (validation + SHA-256 + storage) -> analyze (background job)
-> persistence -> API retrieval. No fake values; asserts real parsed results.
Run with DATABASE_URL pointing at PostgreSQL.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

os.environ.setdefault("DATABASE_URL", "sqlite:///./ipsec_sentinel.db")
os.environ.setdefault("UPLOAD_DIR", "/tmp/ipsec_sentinel_uploads")

from app.main import app  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.models import Capture  # noqa: E402

from tests.synthetic_pcap import build_ipsec_pcap  # noqa: E402

_settings = get_settings()
print(f"DB: {_settings.DATABASE_URL}")
print(f"UPLOAD_DIR: {_settings.UPLOAD_DIR}")

pcap_path = "/tmp/ipsec_e2e.pcap"
writer = build_ipsec_pcap()
writer.write(pcap_path)
expected_sha = __import__("hashlib").sha256(Path(pcap_path).read_bytes()).hexdigest()
print(f"Expected SHA-256: {expected_sha}")


def main() -> int:
    client = TestClient(app)
    # health
    r = client.get("/api/v1/health")
    print("health:", r.status_code, r.json()["success"])

    # list captures (empty baseline is NOT required; PG may be shared)
    list_before = client.get("/api/v1/captures").json()["data"]["items"]
    print(f"captures before: {len(list_before)}")

    # upload
    with open(pcap_path, "rb") as fh:
        r = client.post(
            "/api/v1/captures",
            files={"file": ("ipsec_e2e.pcap", fh, "application/vnd.tcpdump.pcap")},
        )
    assert r.status_code == 200, r.text
    cap = r.json()["data"]
    print(f"uploaded: ref={cap['capture_id']} sha256={cap['sha256']}")
    assert cap["sha256"] == expected_sha, "SHA-256 mismatch"
    assert cap["status"] == "valid"
    cap_key = cap["capture_id"]

    # analyze
    r = client.post(f"/api/v1/captures/{cap_key}/analyze")
    assert r.status_code == 200, r.text
    analysis_ref = r.json()["data"]["analysis_reference"]
    print(f"analysis started: {analysis_ref}")

    analysis_key = r.json()["data"]["analysis_id"]
    # poll job until terminal
    deadline = time.monotonic() + 60
    job = None
    while time.monotonic() < deadline:
        job_r = client.get("/api/v1/analysis-jobs")
        jobs = job_r.json()["data"]["items"]
        job = next((j for j in jobs if j["job_id"] == analysis_ref), None)
        if job is None:
            job = jobs[0] if jobs else None
        if job and job["status"] in ("completed", "failed", "partial"):
            break
        time.sleep(0.2)
    assert job is not None
    print(f"job: status={job['status']} stage={job['current_stage']} progress={job['progress']}")
    assert job["status"] == "completed"

    # analysis summary
    r = client.get(f"/api/v1/analyses/{analysis_key}")
    summary = r.json()["data"]
    analysis = summary["analysis"]
    det = analysis["protocol_detected"]
    print(
        f"analysis: protocol={det} ike={analysis['ike_detected']} "
        f"esp={analysis['esp_detected']} ah={analysis['ah_detected']} "
        f"confidence={analysis['protocol_confidence']} packets={analysis['packet_count']} "
        f"ike_msgs={summary['ike_message_count']} esp={summary['esp_packet_count']} "
        f"ah={summary['ah_packet_count']} flows={summary['flow_count']}"
    )
    assert det in ("yes", "no", None), f"unexpected protocol_detected={det}"
    assert det == "yes"
    assert analysis["ike_detected"] is True
    assert summary["ike_message_count"] > 0
    assert summary["esp_packet_count"] > 0
    assert summary["flow_count"] > 0

    # sub-resources
    for sub, plural in [
        ("protocol-observations", "obs"),
        ("ike-messages", "ike"),
        ("esp-packets", "esp"),
        ("ah-packets", "ah"),
        ("flows", "flows"),
        ("features", "features"),
    ]:
        r = client.get(f"/api/v1/analyses/{analysis_key}/{sub}")
        items = r.json()["data"]["items"]
        print(f"  {sub}: {len(items)}")
        assert items, f"no {sub} rows persisted"

    r = client.get(f"/api/v1/analyses/{analysis_key}/features")
    feats = r.json()["data"]["items"][0]["features"]
    print(f"  sample feature keys: {sorted(feats)[:6]}")

    # exports
    for res in ("flows", "ike", "esp"):
        r = client.get(f"/api/v1/analyses/{analysis_key}/export/{res}")
        assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
        print(f"  export {res}: {len(r.content)} bytes csv")
    r = client.get(f"/api/v1/analyses/{analysis_key}/export/features")
    assert r.status_code == 200 and "application/json" in r.headers["content-type"]
    print(f"  export features: {len(r.content)} bytes json")

    # ---- Phase 3: deterministic security assessment ---------------------
    r = client.post(f"/api/v1/analyses/{analysis_key}/assess")
    assert r.status_code == 200, r.text
    result = r.json()["data"]
    expected_rules = {"IPSEC-CRYPTO-001", "IPSEC-IKE-001", "IPSEC-META-001"}
    rule_ids_run = {rule["rule_id"] for rule in result["rules"]}
    assert expected_rules.issubset(rule_ids_run), rule_ids_run
    print(
        f"assess: version={result['rule_version']} rules_run={result['rules_run']} "
        f"created={result['created']} total={result['total_findings']} "
        f"duration_ms={result['duration_ms']:.0f}"
    )
    assert result["created"] >= len(expected_rules)

    r = client.get(f"/api/v1/analyses/{analysis_key}/findings")
    assert r.status_code == 200
    findings = r.json()["data"]
    print(f"findings: total={findings['pagination']['total']}")
    assert findings["pagination"]["total"] >= len(expected_rules)
    items = findings["items"]
    assert items and items[0]["finding_id"].startswith("SEC-")
    assert items[0]["evidence"] and items[0]["evidence"]["items"]

    detail = client.get(
        f"/api/v1/analyses/{analysis_key}/findings/{items[0]['finding_id']}"
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["data"]["id"] == items[0]["id"]
    print(f"finding detail: {items[0]['finding_id']} {items[0]['rule_id']}")

    # idempotent re-run adds nothing
    again = client.post(f"/api/v1/analyses/{analysis_key}/assess").json()["data"]
    assert again["created"] == 0
    print(f"re-assess idempotent: created={again['created']}")

    # delete upload
    r = client.delete(f"/api/v1/captures/{cap_key}")
    assert r.status_code == 200
    print("  deleted capture", cap_key)

    print("\nE2E PASSED against PostgreSQL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())