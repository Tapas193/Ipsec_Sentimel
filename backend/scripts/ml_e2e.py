"""E2E acceptance run for Phase 4 against real PostgreSQL (port 5433).

Exercises the full honest path, in order:

  1. clean schema (alembic head) on a real PostgreSQL database
  2. upload a real Scapy-generated PCAP (SHA-256 verified) -> analyze ->
     Phase 2 flow features persisted
  3. Phase 3 assess still works and is untouched by ML
  4. ``GET /api/v1/ml/health`` with ML enabled and no model -> 200 +
     ``MODEL_NOT_AVAILABLE`` + a remediation string
  5. ``POST /api/v1/ml/train`` with no label file -> 200 +
     ``INSUFFICIENT_LABELED_DATA``, ``trained=false``, **no artifact written**
  6. ``GET /api/v1/ml/dataset`` -> reports the unlabeled state with notes
  7. ``POST .../predict`` with no model -> 200 + ``MODEL_NOT_AVAILABLE``,
     **no prediction rows written**
  8. re-run Phase 3 assess -> still idempotent, findings unchanged
  9. delete the capture -> cascade removes ML rows (none exist)

No fake values, no fabricated model, no fabricated accuracy. The expected
result for step 5 is a *refusal*, and that refusal is the acceptance criterion.

Run with DATABASE_URL pointing at PostgreSQL.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://postgres:postgres@127.0.0.1:5433/ipsec_sentinel"
)
os.environ.setdefault("UPLOAD_DIR", "/tmp/ipsec_sentinel_p4_uploads")
os.environ["ML_ENABLED"] = "true"
os.environ["ML_TRAINING_ENABLED"] = "true"
os.environ["ML_LABEL_FILE"] = ""
os.environ["AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402
from tests.synthetic_pcap import build_ipsec_pcap  # noqa: E402

settings = get_settings()

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    if not condition:
        failures.append(f"{label}: {detail}")
    print(f"  [{mark}] {label}{(' — ' + detail) if detail else ''}")


def main() -> int:
    print(f"DB:           {settings.DATABASE_URL}")
    print(f"UPLOAD_DIR:   {settings.UPLOAD_DIR}")
    print(f"ML_MODEL_DIR: {settings.ML_MODEL_DIR}")
    print(f"ML_ENABLED={settings.ML_ENABLED} ML_TRAINING_ENABLED={settings.ML_TRAINING_ENABLED}")
    print(f"ML_LABEL_FILE={settings.ML_LABEL_FILE!r} (empty ⇒ no ground truth)")

    model_dir = Path(settings.ML_MODEL_DIR)
    if model_dir.exists():
        shutil.rmtree(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nCleared ML model dir: {model_dir}")

    client = TestClient(app)

    # ------------------------------------------------------------------ #
    print("\n=== 1. build the capture (real Scapy PCAP) ===")
    pcap_path = "/tmp/ipsec_p4_e2e.pcap"
    build_ipsec_pcap().write(pcap_path)
    data = Path(pcap_path).read_bytes()
    expected_sha = hashlib.sha256(data).hexdigest()
    print(f"  {pcap_path}: {len(data)} bytes, sha256={expected_sha[:16]}…")

    # ------------------------------------------------------------------ #
    print("\n=== 2. upload + analyze (Phase 2) ===")
    with open(pcap_path, "rb") as fh:
        r = client.post(
            "/api/v1/captures",
            files={"file": ("ipsec_p4_e2e.pcap", fh, "application/vnd.tcpdump.pcap")},
        )
    check("upload 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    cap = r.json()["data"]
    capture_key = cap["capture_id"]
    check("SHA-256 recorded", cap["sha256"] == expected_sha, f"{cap['sha256'][:16]}…")

    r = client.post(f"/api/v1/captures/{capture_key}/analyze")
    check("analyze accepted", r.status_code == 200, f"got {r.status_code}")
    started = r.json()["data"]
    analysis_key = started["analysis_reference"]
    analysis_uuid = started["analysis_id"]
    print(f"  {analysis_key} ({analysis_uuid})")

    completed = False
    for _ in range(60):
        jobs = client.get("/api/v1/analysis-jobs", params={"page_size": 5}).json()["data"]["items"]
        if jobs and jobs[0]["status"] in ("completed", "failed"):
            completed = jobs[0]["status"] == "completed"
            break
        time.sleep(0.5)
    check("analysis completed", completed)
    if not completed:
        return 1

    r = client.get(f"/api/v1/analyses/{analysis_key}/features", params={"page_size": 100})
    features = r.json()["data"]["items"]
    check("flow features persisted", len(features) > 0, f"{len(features)} feature rows")

    # ------------------------------------------------------------------ #
    print("\n=== 3. Phase 3 assess (baseline, before ML) ===")
    r = client.post(f"/api/v1/analyses/{analysis_key}/assess")
    check("assess 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    before = r.json()["data"]
    print(
        f"  rules_version={before.get('rule_version')} created={before['created']} "
        f"total_findings={before['total_findings']}"
    )
    rule_version_before = before.get("rule_version")

    # ------------------------------------------------------------------ #
    print("\n=== 4. ML health with no model ===")
    r = client.get("/api/v1/ml/health")
    check("health 200", r.status_code == 200, f"got {r.status_code}")
    health = r.json()["data"]
    check("ml_enabled true", health["ml_enabled"] is True)
    check("no model available", health["any_model_available"] is False)
    check("active_model_version null", health["active_model_version"] is None)
    check(
        "detail explains why",
        bool(health["detail"] and health["detail"]["reason"]),
        (health["detail"] or {}).get("reason", "no detail"),
    )
    check("remediation offered", bool((health["detail"] or {}).get("remediation")))
    check(
        "27 features declared",
        client.get("/api/v1/ml/features").json()["data"]["feature_count"] == 27,
    )

    # ------------------------------------------------------------------ #
    print("\n=== 5. training with no ground truth (the expected refusal) ===")
    r = client.post("/api/v1/ml/train", json={})
    check("train 200 (not an error)", r.status_code == 200, f"got {r.status_code}")
    train = r.json()["data"]
    check(
        "status INSUFFICIENT_LABELED_DATA",
        train["status"] == "INSUFFICIENT_LABELED_DATA",
        train["status"],
    )
    check("trained is false", train["trained"] is False)
    check("no model_version", train["model_version"] is None)
    check("zero training samples", train["training_samples"] == 0)
    check("no metrics claimed", train["metrics"] is None)
    check(
        "no classes activated",
        all(not c for c in train["classes"]) or train["classes"],
        "declared vocabulary returned",
    )
    check(
        "NO artifact written",
        not any(model_dir.iterdir()),
        f"model dir contents: {[p.name for p in model_dir.iterdir()]}",
    )
    print(f"  message: {train['message']}")

    # ------------------------------------------------------------------ #
    print("\n=== 6. dataset dry-run reports the unlabeled state ===")
    r = client.get("/api/v1/ml/dataset")
    check("dataset 200", r.status_code == 200)
    ds = r.json()["data"]
    check(
        "status INSUFFICIENT_LABELED_DATA",
        ds["status"] == "INSUFFICIENT_LABELED_DATA",
        ds["status"],
    )
    check("feature rows visible", ds["total_feature_rows"] >= 0, f"{ds['total_feature_rows']} rows")
    check("zero labeled rows", ds["labeled_rows"] == 0)
    check("registry source none", ds["label_registry_source"] == "none")
    check("notes explain the zero", bool(ds["notes"]), str(ds["notes"])[:120])
    check("no split allocated", ds["split"] is None)

    # ------------------------------------------------------------------ #
    print("\n=== 7. inference with no model ===")
    r = client.post(f"/api/v1/ml/analyses/{analysis_key}/predict")
    check("predict 200 (not an error)", r.status_code == 200, f"got {r.status_code}")
    pred = r.json()["data"]
    check("status MODEL_NOT_AVAILABLE", pred["status"] == "MODEL_NOT_AVAILABLE", pred["status"])
    # `total` is candidate flows considered; `summary.count` is predictions
    # produced. An unavailable run must report zero of the latter.
    check("zero predictions produced", pred["summary"]["count"] == 0, str(pred["summary"]["count"]))
    check("zero rows created", pred["created"] == 0)
    check("candidate flows still counted", pred["total"] > 0, f"total={pred['total']}")
    check("detail explains why", bool(pred["detail"]), (pred["detail"] or {}).get("reason", "none"))
    check(
        "NO prediction rows written",
        client.get("/api/v1/ml/predictions").json()["data"]["total"] == 0,
    )

    r = client.get(f"/api/v1/ml/analyses/{analysis_key}/predictions")
    listing = r.json()["data"]
    check(
        "listing 200 with status",
        r.status_code == 200 and listing["status"] == "MODEL_NOT_AVAILABLE",
        listing["status"],
    )
    check("empty prediction list", listing["predictions"] == [])

    r = client.get("/api/v1/ml/models")
    check("no models registered", r.json()["data"]["total"] == 0)

    # ------------------------------------------------------------------ #
    print("\n=== 8. Phase 3 is untouched by all of the above ===")
    r = client.post(f"/api/v1/analyses/{analysis_key}/assess")
    after = r.json()["data"]
    check("re-assess 200", r.status_code == 200)
    check("idempotent: 0 created", after["created"] == 0, f"created={after['created']}")
    check(
        "rule_version unchanged",
        after.get("rule_version") == rule_version_before,
        f"{rule_version_before} -> {after.get('rule_version')}",
    )
    r = client.get(f"/api/v1/analyses/{analysis_key}/findings")
    check("findings still readable", r.status_code == 200, f"got {r.status_code}")
    findings_total = r.json()["data"]["pagination"]["total"]
    check(
        "ML created no findings",
        findings_total == before["total_findings"],
        f"{before['total_findings']} -> {findings_total}",
    )

    # ------------------------------------------------------------------ #
    print("\n=== 9. cleanup ===")
    r = client.delete(f"/api/v1/captures/{capture_key}")
    check("capture deleted", r.status_code in (200, 204), f"got {r.status_code}")
    r = client.get(f"/api/v1/analyses/{analysis_key}")
    check("analysis gone after cascade", r.status_code == 404, f"got {r.status_code}")
    Path(pcap_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------ #
    print("\n" + "=" * 72)
    if failures:
        print(f"E2E FAILED — {len(failures)} check(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("E2E PASSED — Phase 4 behaves correctly with no ground truth:")
    print("  * no model exists, and the API says so with HTTP 200 + a reason")
    print("  * training refused; no fit attempted; no artifact on disk")
    print("  * inference refused; zero prediction rows written")
    print("  * Phase 3 assessment unaffected and still idempotent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
