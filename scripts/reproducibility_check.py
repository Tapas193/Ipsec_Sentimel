"""Phase 4 readiness gate: end-to-end reproducibility.

Re-analyses the same synthetic capture N times and diffs every output.

Two classes of output are checked separately:

* **Deterministic** - must be byte-identical across runs: packet/byte/flow
  counts, protocol observations, IKE messages and proposals, ESP/AH packets,
  flow features, `rule_version`, `rules_run`, finding content, finding
  evidence, and assessment idempotency.
* **Ephemeral by design** - generated per row on every analysis and therefore
  expected to differ: `uuid4` primary keys, the `CAP-`/`ANL-`/`JOB-`/`SEC-`
  per-row id sequences, wall-clock timestamps, and float epoch subtraction.

`evidence.message_ids` is tracked separately: it references `ike_messages.id`,
a `uuid4` surrogate key, so it differs across runs. It is asserted to be the
*only* substantive evidence variance and to resolve to real IKE message rows
of the same analysis that map 1:1 onto the stable `evidence.packet_ids`.

Usage:
    python scripts/reproducibility_check.py
    REPRO_RUNS=5 python scripts/reproducibility_check.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

BASE = os.environ.get("IPSEC_API", "http://localhost:8000/api/v1")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "fixtures")
RUNS = int(os.environ.get("REPRO_RUNS", "3"))
FIXTURE_NAME = "ipsec-demo.pcap"

# Fields that are ephemeral by design and excluded from determinism checks.
EPHEMERAL_FINDING_FIELDS = frozenset({"id", "analysis_id", "finding_id", "created_at"})

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def call(method: str, path: str, data: bytes | None = None, ctype: str | None = None) -> dict:
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get(path: str) -> dict:
    return call("GET", path)["data"]


def upload_and_analyze(filename: str) -> str:
    with open(os.path.join(FIXTURE, FIXTURE_NAME), "rb") as fh:
        content = fh.read()
    boundary = b"----repro"
    disposition = b'Content-Disposition: form-data; name="file"; filename="' + filename.encode() + b'"'
    body = b"".join([
        b"--", boundary, b"\r\n",
        disposition, b"\r\n",
        b"Content-Type: application/octet-stream\r\n\r\n",
        content, b"\r\n",
        b"--", boundary, b"--\r\n",
    ])
    capture = call("POST", "/captures", body, "multipart/form-data; boundary=----repro")["data"]
    started = call("POST", f"/captures/{capture['capture_id']}/analyze")["data"]
    analysis_key = started["analysis_reference"]
    for _ in range(600):
        job = get("/analysis-jobs?page_size=1")["items"]
        if job and job[0]["status"] in ("completed", "failed", "partial"):
            break
        time.sleep(0.1)
    return analysis_key


FLOW_FIELDS = (
    "flow_id", "source_ip", "destination_ip", "source_port", "destination_port",
    "protocol", "transport", "ip_version", "duration", "packet_count", "byte_count",
    "upstream_packets", "downstream_packets", "upstream_bytes", "downstream_bytes",
    "direction", "spi", "ike_packets", "esp_packets", "ah_packets",
)


def deterministic_snapshot(key: str) -> dict:
    """Every Phase 2 output that must be identical across re-analyses."""
    analysis = get(f"/analyses/{key}")["analysis"]
    ike = get(f"/analyses/{key}/ike-messages")["items"]
    esp = get(f"/analyses/{key}/esp-packets")["items"]
    ah = get(f"/analyses/{key}/ah-packets")["items"]

    return {
        "packet_count": analysis["packet_count"],
        "byte_count": analysis["byte_count"],
        "flow_count": analysis["flow_count"],
        "protocol_detected": analysis["protocol_detected"],
        "protocol_confidence": analysis["protocol_confidence"],
        "analyzer_version": analysis["analyzer_version"],
        "parser_version": analysis["parser_version"],
        "ike_messages": [
            {k: m[k] for k in ("packet_id", "version", "exchange_name", "message_id",
                               "initiator_spi", "responder_spi", "direction", "length",
                               "payload_types")}
            for m in ike
        ],
        "ike_proposals": [
            {k: p[k] for k in ("proposal_number", "protocol_id", "protocol_name", "encryption",
                               "key_length", "integrity", "prf", "dh_group", "esn", "status",
                               "transform_confidence")}
            for m in ike for p in m.get("proposals", [])
        ],
        "esp_packets": [
            {k: p[k] for k in ("packet_id", "spi", "sequence_number", "length",
                               "direction", "encryption_algorithm")}
            for p in esp
        ],
        "ah_packets": [
            {k: p[k] for k in ("packet_id", "spi", "sequence_number", "length",
                               "direction", "next_header")}
            for p in ah
        ],
        "protocol_observations": sorted(
            (o["protocol"], o["packet_count"], o["byte_count"], o["confidence"])
            for o in get(f"/analyses/{key}/protocol-observations")["items"]
        ),
        "flows": sorted(
            ({k: f[k] for k in FLOW_FIELDS} for f in get(f"/analyses/{key}/flows")["items"]),
            key=lambda f: f["flow_id"],
        ),
        "flow_features": sorted(
            ((f["flow_key"], f["feature_schema_version"], f["features"])
             for f in get(f"/analyses/{key}/features")["items"]),
            key=lambda t: (t[0] or ""),
        ),
    }


def rule_snapshot(key: str) -> dict:
    first = call("POST", f"/analyses/{key}/assess")["data"]
    second = call("POST", f"/analyses/{key}/assess")["data"]
    findings = get(f"/analyses/{key}/findings?page_size=500")["items"]
    return {
        "rule_version": first["rule_version"],
        "rules_run": first["rules_run"],
        "created": first["created"],
        "skipped": first["skipped"],
        "total_findings": first["total_findings"],
        "idempotent_second_run": (
            second["created"] == 0
            and second["skipped"] == second["total_findings"]
            and second["total_findings"] == first["total_findings"]
        ),
        "per_rule": sorted((r["rule_id"], r["created"], r["skipped"]) for r in first["rules"]),
        # Stable projection: excludes ephemeral identity/timestamp fields and
        # evidence.message_ids (tracked separately below).
        "findings": sorted(
            (
                f["rule_id"], f["severity"], f["confidence"], f["finding_type"],
                f["category"], f["title"], f["description"], f["observed_value"],
                f["expected_value"],
                {k: v for k, v in f["evidence"].items() if k != "message_ids"},
            )
            for f in findings
        ),
    }


def message_id_stability(key: str) -> tuple[bool, str]:
    """Assert message_ids are the only variance and that they stay truthful."""
    findings = get(f"/analyses/{key}/findings?page_size=500")["items"]
    ike = get(f"/analyses/{key}/ike-messages?page_size=500")["items"]
    known = {m["id"]: m["packet_id"] for m in ike}
    ok = True
    notes = []
    for f in findings:
        refs = f["evidence"].get("message_ids")
        if not refs:
            continue
        resolves = all(r in known for r in refs)
        aligns = sorted(known[r] for r in refs if r in known) == sorted(f["evidence"]["packet_ids"])
        ok = ok and resolves and aligns
        notes.append(f"{f['rule_id']}:{len(refs)} refs, resolves={resolves}, aligns_to_packet_ids={aligns}")
    return ok, "; ".join(notes) or "no message_ids referenced"


def main() -> int:
    print(f"Reproducibility gate: analysing {FIXTURE_NAME} {RUNS}x against {BASE}\n")

    det_runs, rule_runs, keys = [], [], []
    for i in range(1, RUNS + 1):
        key = upload_and_analyze(f"TEST-FIXTURE-repro-{i}.pcap")
        keys.append(key)
        det_runs.append(deterministic_snapshot(key))
        rule_runs.append(rule_snapshot(key))
        d, r = det_runs[-1], rule_runs[-1]
        print(f"  run {i}  {key}  packets={d['packet_count']} ike={len(d['ike_messages'])} "
              f"esp={len(d['esp_packets'])} ah={len(d['ah_packets'])} flows={len(d['flows'])} "
              f"rules_run={r['rules_run']} findings={r['total_findings']}")

    print("\nPhase 2 - deterministic outputs (must be identical across all runs)")
    base = json.dumps(det_runs[0], sort_keys=True)
    check("all Phase 2 outputs byte-identical",
          all(json.dumps(s, sort_keys=True) == base for s in det_runs))
    d = det_runs[0]
    check("packet/byte/flow counts stable",
          len({(s["packet_count"], s["byte_count"], s["flow_count"]) for s in det_runs}) == 1,
          f"packets={d['packet_count']} bytes={d['byte_count']} flows={len(d['flows'])}")
    check("IKE/ESP/AH message sets stable",
          len({json.dumps([s["ike_messages"], s["ike_proposals"], s["esp_packets"],
                           s["ah_packets"], s["protocol_observations"]], sort_keys=True)
               for s in det_runs}) == 1)
    check("flow features stable",
          len({json.dumps(s["flow_features"], sort_keys=True) for s in det_runs}) == 1,
          f"{len(d['flow_features'])} flow feature rows")
    check("analyzer/parser versions stable",
          len({(s["analyzer_version"], s["parser_version"]) for s in det_runs}) == 1,
          f"analyzer={d['analyzer_version']} parser={d['parser_version']}")

    print("\nPhase 3 - rule outcomes and finding content (must be identical across all runs)")
    rbase = json.dumps(rule_runs[0], sort_keys=True)
    check("rule outcomes and finding content byte-identical",
          all(json.dumps(s, sort_keys=True) == rbase for s in rule_runs))
    r = rule_runs[0]
    check("rule_version and rules_run stable",
          len({(s["rule_version"], s["rules_run"]) for s in rule_runs}) == 1,
          f"rule_version={r['rule_version']} rules_run={r['rules_run']}")
    check("finding count stable", len({s["total_findings"] for s in rule_runs}) == 1,
          f"findings={r['total_findings']}")
    check("re-assessment is idempotent on every run",
          all(s["idempotent_second_run"] for s in rule_runs),
          "second assess call created=0")
    check("per-rule breakdown stable",
          len({json.dumps(s["per_rule"], sort_keys=True) for s in rule_runs}) == 1,
          ", ".join(f"{rid}:{c} created" for rid, c, _ in r["per_rule"] if c))

    print("\nTracked variance - evidence.message_ids (ike_messages uuid4 surrogate keys)")
    msg_notes = [message_id_stability(k) for k in keys]
    check("message_ids resolve to real IKE rows matching stable packet_ids",
          all(ok for ok, _ in msg_notes), msg_notes[0][1])

    print("\nEphemeral by design (expected to differ across runs)")
    print("  * uuid4 primary keys: captures.id, analyses.id, flows.id,")
    print("    flow_features.id, security_findings.id")
    print("  * per-row id sequences: CAP-, ANL-, JOB-, SEC-")
    print("  * wall-clock: created_at, uploaded_at, completed_at")
    print("  * float epoch subtraction in duration / duration_seconds")
    print("  * assessment duration_ms (machine load)")

    print()
    if failures:
        print(f"RESULT: NOT REPRODUCIBLE - {len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("RESULT: REPRODUCIBLE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
