"""Phase 4 readiness: frontend/backend contract verification.

Parses the TypeScript interfaces in ``frontend/src/types/api.ts`` and checks
every field against a live API response. Catches drift where the frontend
renders a field the backend stopped sending (renders ``undefined``) or where a
new backend field has no typed counterpart.

Run with the backend and a completed analysis available:

    python scripts/contract_check.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request

BASE = os.environ.get("IPSEC_API", "http://localhost:8000/api/v1")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_TS = os.path.join(ROOT, "frontend", "src", "types", "api.ts")

failures: list[str] = []
warnings: list[str] = []


def payload(path: str):
    """Return the unwrapped ``data`` object of a response envelope."""
    with urllib.request.urlopen(f"{BASE}{path}") as resp:
        body = json.loads(resp.read())
    return body.get("data")


def parse_interfaces(source: str) -> dict[str, dict[str, str]]:
    """Map interface name -> {field_name: ts_type} for flat interfaces."""
    out: dict[str, dict[str, str]] = {}
    pattern = re.compile(r"export interface (\w+)[^{]*\{(.*?)\n\}", re.DOTALL)
    for match in pattern.finditer(source):
        name, body = match.group(1), match.group(2)
        fields: dict[str, str] = {}
        depth = 0
        current: list[str] = []
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue
            current.append(stripped)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and ":" in stripped:
                joined = " ".join(current)
                for part in joined.split(";"):
                    part = part.strip()
                    if not part or part.startswith("/"):
                        continue
                    if ":" not in part:
                        continue
                    fname, ftype = part.split(":", 1)
                    fname = fname.strip()
                    if re.fullmatch(r"\w+", fname):
                        fields[fname] = ftype.strip()
                current = []
        out[name] = fields
    return out


def compare(label: str, ts_fields: dict[str, str], sample: dict, path: str = "") -> None:
    if not isinstance(sample, dict):
        warnings.append(f"{label}{path}: API returned {type(sample).__name__}, not an object")
        print(f"  [WARN] {label}{path} - API returned {type(sample).__name__}, expected object")
        return
    missing = [f for f in ts_fields if f not in sample]
    extra = [f for f in sample if f not in ts_fields]
    if missing:
        failures.append(f"{label}{path}: TS declares but API omits {missing}")
        print(f"  [FAIL] {label}{path} - missing from API: {missing}")
    elif extra:
        warnings.append(f"{label}{path}: API sends untyped {extra}")
        print(f"  [WARN] {label}{path} - sent by API, absent from TS: {extra}")
    else:
        print(f"  [PASS] {label}{path} - {len(ts_fields)} fields match exactly")


def main() -> int:
    with open(API_TS) as fh:
        interfaces = parse_interfaces(fh.read())
    print(f"Parsed {len(interfaces)} interfaces from {os.path.relpath(API_TS, ROOT)}\n")

    # Pick the richest completed analysis so every collection has rows to
    # compare; a plaintext capture would leave IKE/ESP/AH/findings empty and
    # silently skip those interfaces.
    candidates = payload("/analyses?page_size=200")["items"]
    candidates = [a for a in candidates if a.get("status") == "completed"]
    if not candidates:
        print("no completed analysis available; run an analysis first")
        return 2
    best, best_score = None, -1
    for a in candidates:
        key = a["id"]
        score = (
            a.get("packet_count") or 0
            + a.get("flow_count") or 0
        )
        for path in ("ike-messages", "esp-packets", "ah-packets", "findings?page_size=1"):
            score += len(payload(f"/analyses/{key}/{path}")["items"])
        if score > best_score:
            best, best_score = key, score
    analysis_id = best
    print(f"Using analysis {analysis_id} (richness score {best_score})\n")

    print("Top-level resources")
    compare("HealthData", interfaces["HealthData"], payload("/health"))
    compare("DashboardStats", interfaces["DashboardStats"],
            payload("/stats/dashboard"))
    compare("SystemInfoData", interfaces["SystemInfoData"], payload("/system/info"))
    compare("ToolsData", interfaces["ToolsData"], payload("/system/tools"))

    captures = payload("/captures?page_size=1")["items"]
    if captures:
        compare("Capture", interfaces["Capture"], captures[0])
    jobs = payload("/analysis-jobs?page_size=1")["items"]
    if jobs:
        compare("AnalysisJob", interfaces["AnalysisJob"], jobs[0])

    print("\nAnalysis resources")
    summary = payload(f"/analyses/{analysis_id}")["analysis"]
    compare("Analysis", interfaces["Analysis"], summary)
    detail = payload(f"/analyses/{analysis_id}")
    if "summary" in detail:
        compare("AnalysisSummary", interfaces["AnalysisSummary"], detail["summary"])

    collections = [
        # (interface, path, nested interface, field holding it)
        ("ProtocolObservation", f"/analyses/{analysis_id}/protocol-observations", None, None),
        ("IkeMessage", f"/analyses/{analysis_id}/ike-messages", "IkeProposal", "proposals"),
        ("EspPacket", f"/analyses/{analysis_id}/esp-packets", None, None),
        ("AhPacket", f"/analyses/{analysis_id}/ah-packets", None, None),
        ("Flow", f"/analyses/{analysis_id}/flows", None, None),
        ("FlowFeatures", f"/analyses/{analysis_id}/features", None, None),
        ("SecurityFinding", f"/analyses/{analysis_id}/findings?page_size=50",
         "FindingEvidence", "evidence"),
    ]
    for name, path, nested, nested_field in collections:
        items = payload(path)["items"]
        if not items:
            warnings.append(f"{name}: no rows to compare (list empty)")
            print(f"  [WARN] {name} - list is empty, nothing compared")
            continue
        compare(name, interfaces[name], items[0])
        if not nested:
            continue
        nested_value = items[0].get(nested_field)
        # `proposals` is a list of objects; `evidence` is a single object.
        if isinstance(nested_value, list):
            if not nested_value:
                warnings.append(f"{name}.{nested}: no rows to compare")
                print(f"  [WARN] {name}.{nested} - empty, nothing compared")
                continue
            nested_sample = nested_value[0]
        elif isinstance(nested_value, dict):
            nested_sample = nested_value
        else:
            warnings.append(f"{name}.{nested_field} was {type(nested_value).__name__}, not an object")
            print(f"  [WARN] {name}.{nested_field} - {type(nested_value).__name__}, nothing compared")
            continue
        compare(f"{name}.{nested}", interfaces[nested], nested_sample, f".{nested_field}")
        if nested == "FindingEvidence" and isinstance(nested_sample.get("items"), list) \
                and nested_sample["items"]:
            compare("FindingEvidenceItem", interfaces["FindingEvidenceItem"],
                    nested_sample["items"][0], f".{nested_field}.items[0]")

    print("\nAssessment + export")
    req = urllib.request.Request(f"{BASE}/analyses/{analysis_id}/assess", data=b"", method="POST")
    with urllib.request.urlopen(req) as resp:
        assess = json.loads(resp.read())["data"]
    compare("AssessmentResult", interfaces["AssessmentResult"], assess)
    if assess.get("rules"):
        compare("RuleAssessment", interfaces["RuleAssessment"], assess["rules"][0], ".rules[0]")

    findings = payload("/findings?page_size=1")
    if findings.get("items"):
        compare("SecurityFinding", interfaces["SecurityFinding"], findings["items"][0])

    print(f"\n{'=' * 60}")
    print(f"contract failures : {len(failures)}")
    print(f"warnings          : {len(warnings)}")
    for w in warnings:
        print(f"  - {w}")
    if failures:
        print("\nRESULT: contract drift detected")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nRESULT: frontend types match the live API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
