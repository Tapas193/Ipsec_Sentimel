"""Phase 4 readiness: security posture probe.

Exercises the upload surface and the read APIs against path traversal,
extension and magic-byte spoofing, oversized query parameters, and SQL
injection in every identifier-taking endpoint. Read-only apart from the probe
uploads it creates, which it deletes again.

The application answers validation problems with HTTP 400
(``INVALID_CAPTURE`` / ``UNSUPPORTED_FORMAT``) and out-of-range query
parameters with HTTP 422 via FastAPI, so those are the codes asserted here.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("IPSEC_API", "http://localhost:8000/api/v1")
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
VALID_CAPTURE = PCAP_MAGIC + b"\x00" * 40

failures: list[str] = []
created: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def request(method: str, path: str, data: bytes | None = None, ctype: str | None = None):
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"raw": body[:200].decode("utf-8", "replace")}


def upload(name: str, content: bytes) -> tuple[int, dict]:
    boundary = b"----sec"
    disposition = b'Content-Disposition: form-data; name="file"; filename="' + name.encode() + b'"'
    body = b"".join([
        b"--", boundary, b"\r\n", disposition, b"\r\n",
        b"Content-Type: application/octet-stream\r\n\r\n", content, b"\r\n",
        b"--", boundary, b"--\r\n",
    ])
    return request("POST", "/captures", body, "multipart/form-data; boundary=----sec")


def rejected(status: int, body: dict) -> bool:
    return status == 400 and body.get("error", {}).get("code") in {
        "INVALID_CAPTURE",
        "UNSUPPORTED_FORMAT",
    }


print("Upload validation")
status, body = upload("evil.pcap", b"not a capture at all, just text" * 4)
check("non-capture content rejected despite .pcap extension", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

status, body = upload("evil.txt", VALID_CAPTURE)
check("disallowed extension rejected", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

status, body = upload("empty.pcap", b"")
check("empty file rejected", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

status, body = upload("short.pcap", b"\xd4\xc3")
check("truncated magic rejected", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

status, body = upload("../../etc/passwd.pcap", VALID_CAPTURE)
check("path separators in filename rejected", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

status, body = upload("a\\b.pcap", VALID_CAPTURE)
check("backslash in filename rejected", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

status, body = upload("..", VALID_CAPTURE)
check("bare '..' filename rejected", rejected(status, body),
      f"HTTP {status} {body.get('error', {}).get('code')}")

# Percent-encoded separators arrive as literal '%2f' text, not as separators, so
# the request is legitimately accepted. What matters is that the stored name is
# always server-generated and therefore cannot escape the upload directory.
for hostile in ("..%2f..%2fetc%2fpasswd.pcap", "x.pcap\x00.png", "....//....//x.pcap"):
    status, body = upload(hostile, VALID_CAPTURE)
    if status == 200:
        created.append(body["data"]["capture_id"])
        stored = body["data"]["stored_filename"]
        check(f"hostile filename {hostile!r} stored server-side only",
              stored.startswith("CAP-") and "/" not in stored and "\\" not in stored
              and ".." not in stored,
              f"stored_filename={stored}")
    else:
        check(f"hostile filename {hostile!r} rejected", rejected(status, body),
              f"HTTP {status} {body.get('error', {}).get('code')}")

print("\nSQL injection in identifier parameters")
injections = [
    "1' OR '1'='1",
    "1; DROP TABLE flows;--",
    "' UNION SELECT NULL,NULL--",
    "%27%20OR%201%3D1--",
    "CAP-000001'--",
]
templates = ["/captures/{}", "/analyses/{}", "/analysis-jobs/{}"]
leaked = False
probes = 0
for inj in injections:
    for tmpl in templates:
        probes += 1
        status, body = request("GET", tmpl.format(urllib.parse.quote(inj, safe="")))
        if status == 200 and isinstance(body.get("data"), dict):
            leaked = True
            print(f"      LEAK {tmpl.format(inj)} -> {body['data']}")
check("no SQL injection via path identifiers", not leaked, f"{probes} probes")

status, body = request("GET", "/analyses?page=1&page_size=999999")
check("oversized page_size rejected by bound", status == 422, f"HTTP {status}")

status, body = request("GET", "/analyses?page=-1&page_size=10")
check("negative page rejected by bound", status == 422, f"HTTP {status}")

status, body = request("GET", "/analyses?page=1&page_size=500")
check("page_size at the documented maximum is accepted", status == 200,
      f"HTTP {status} total={body.get('data', {}).get('pagination', {}).get('total')}")

print("\nError responses must not leak internals")
status, body = request("GET", "/analyses/ANL-999999")
err = json.dumps(body.get("error", {}))
check("404 is a clean envelope without tracebacks",
      status == 404 and "Traceback" not in err and "sqlalchemy" not in err.lower(), err[:90])

print("\nCleanup")
for capture_id in created:
    request("DELETE", f"/captures/{capture_id}")
print(f"  deleted {len(created)} probe capture(s)")

print()
if failures:
    print(f"RESULT: {len(failures)} check(s) failed:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("RESULT: no security issues found by this probe")
