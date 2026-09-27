"""Phase 4 readiness: control-fixture behaviour.

Analyses the two non-demo fixtures to confirm the rule engine reacts to what
is actually in the capture and does not invent conclusions:

* `ipsec-ikev1.pcap` - IKEv1 only, no ESP/AH. IKEv1-specific rules should fire
  and ESP/AH-scoped rules must stay silent rather than guessing.
* `plaintext-only.pcap` - no IPsec at all. No cryptographic, key-exchange or
  security-association finding may be raised from absent evidence; at most the
  metadata/visibility rules that describe the absence may fire.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

BASE = os.environ.get("IPSEC_API", "http://localhost:8000/api/v1")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures")


def call(method: str, path: str, data: bytes | None = None, ctype: str | None = None) -> dict:
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get(path: str) -> dict:
    return call("GET", path)["data"]


def run(fixture: str) -> dict:
    with open(os.path.join(FIXTURES, fixture), "rb") as fh:
        content = fh.read()
    boundary = b"----ctrl"
    disposition = b'Content-Disposition: form-data; name="file"; filename="' + fixture.encode() + b'"'
    body = b"".join([
        b"--", boundary, b"\r\n", disposition, b"\r\n",
        b"Content-Type: application/octet-stream\r\n\r\n", content, b"\r\n",
        b"--", boundary, b"--\r\n",
    ])
    capture = call("POST", "/captures", body, "multipart/form-data; boundary=----ctrl")["data"]
    started = call("POST", f"/captures/{capture['capture_id']}/analyze")["data"]
    key = started["analysis_reference"]
    for _ in range(600):
        job = get("/analysis-jobs?page_size=1")["items"]
        if job and job[0]["status"] in ("completed", "failed", "partial"):
            break
        time.sleep(0.1)
    call("POST", f"/analyses/{key}/assess")
    analysis = get(f"/analyses/{key}")["analysis"]
    ike = get(f"/analyses/{key}/ike-messages")["items"]
    esp = get(f"/analyses/{key}/esp-packets")["items"]
    ah = get(f"/analyses/{key}/ah-packets")["items"]
    findings = get(f"/analyses/{key}/findings?page_size=500")["items"]
    return {
        "key": key, "analysis": analysis, "ike": ike, "esp": esp, "ah": ah,
        "findings": findings,
    }


failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))
    if not ok:
        failures.append(label)


print("Control fixture: ipsec-ikev1.pcap")
r1 = run("ipsec-ikev1.pcap")
versions = {m["version"] for m in r1["ike"]}
rule_ids = [f["rule_id"] for f in r1["findings"]]
print(f"  packets={r1['analysis']['packet_count']} ike={len(r1['ike'])} esp={len(r1['esp'])} "
      f"ah={len(r1['ah'])} versions={sorted(versions)}")
for f in r1["findings"]:
    print(f"    {f['rule_id']:<18} {f['severity']:<6} conf={f['confidence']:<7} {f['title']}")
check("IKEv1 detected", versions == {"IKEv1"}, f"versions={sorted(versions)}")
check("analysis completed", r1["analysis"]["status"] == "completed",
      f"status={r1['analysis']['status']}")
# The IKEv1 fixture deliberately proposes a weak algorithm, so the weak-crypto
# rule must fire, and the plaintext traffic in the same capture must trip the
# metadata rule. Both are genuine observations, not fabrications.
check("weak-crypto rule fires on the weak IKEv1 proposal",
      "IPSEC-CRYPTO-002" in rule_ids, f"rules={rule_ids}")
check("metadata rule fires on the plaintext traffic in the capture",
      "IPSEC-META-001" in rule_ids, f"rules={rule_ids}")
check("no ESP/AH-scoped finding when no ESP/AH present",
      not any(r in rule_ids for r in ("IPSEC-REPLAY-001", "IPSEC-COMPOSITE-001")),
      f"esp={len(r1['esp'])} ah={len(r1['ah'])}")

print("\nControl fixture: plaintext-only.pcap")
r2 = run("plaintext-only.pcap")
rule_ids2 = [f["rule_id"] for f in r2["findings"]]
print(f"  packets={r2['analysis']['packet_count']} ike={len(r2['ike'])} esp={len(r2['esp'])} "
      f"ah={len(r2['ah'])} protocol={r2['analysis']['protocol_detected']}")
for f in r2["findings"]:
    print(f"    {f['rule_id']:<18} {f['severity']:<6} conf={f['confidence']:<7} {f['title']}")
check("no IKE/ESP/AH rows for a plaintext capture",
      not r2["ike"] and not r2["esp"] and not r2["ah"])
fabricated = [f["rule_id"] for f in r2["findings"]
              if f["category"] in {"CRYPTOGRAPHY", "KEY_EXCHANGE", "PFS", "SECURITY_ASSOCIATION"}]
check("no crypto/kex/pfs/sa finding from absent evidence", not fabricated,
      f"offending={fabricated}")
check("no rule claims a strong or weak posture it could not observe",
      all("UNKNOWN" not in (f["observed_value"] or "") for f in r2["findings"] if f["rule_id"] == "IPSEC-CRYPTO-002"),
      "IPSEC-CRYPTO-002 must stay silent on a plaintext capture")

print()
if failures:
    print(f"RESULT: {len(failures)} check(s) failed:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("RESULT: control fixtures behave as expected")
