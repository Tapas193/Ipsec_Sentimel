"""Phase 4 ML test fixtures.

Everything here is **deterministic test scaffolding**. It exists to exercise
pipeline mechanics — validation, splitting, fitting, persistence, abstention —
and is scoped to the test suite. It is not, and is never presented as, a
real-world labeled corpus.

The distinction matters, so it is enforced in code:

- ``build_deterministic_dataset`` fabricates feature values, and the labels
  attached to it are declared by the *test*, not inferred from traffic. They
  stand in for an operator's ground-truth file.
- The one place labels may legitimately come from in this repository is
  :func:`write_label_file`, which produces a file in the same schema an
  operator would supply. That is how the "real label file" path is tested.
- No test asserts that a model is *accurate*. Tests assert that the mechanism
  is correct and that the system refuses to claim more than it knows.

The absence of genuine labels is itself covered by
``TestLabelProvenanceHonesty``, which asserts that the repository as shipped
produces ``INSUFFICIENT_LABELED_DATA`` and writes no artifact.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from sqlalchemy.orm import Session

from app.ml.schema import MLFeatureSchema, get_feature_schema
from app.models import (
    Analysis,
    AnalysisStatus,
    Capture,
    CaptureStatus,
    Flow,
    FlowFeatures,
)

__all__ = [
    "build_deterministic_dataset",
    "ml_model_dir",
    "ml_schema",
    "make_analysis",
    "make_capture",
    "make_flow_with_features",
    "synthetic_features",
    "write_label_file",
]

# Two well-separated regions of feature space per class. A classifier fitted on
# this can legitimately separate them, which lets the tests verify that fitting,
# prediction and persistence work end to end. The values themselves are
# arbitrary and carry no claim about real traffic.
_CLASS_CENTERS: dict[str, dict[str, float]] = {
    "VOIP": {"packet_count": 40, "duration_seconds": 20.0, "direction_ratio": 0.5},
    "WEB": {"packet_count": 400, "duration_seconds": 60.0, "direction_ratio": 0.7},
    "EMAIL": {"packet_count": 120, "duration_seconds": 30.0, "direction_ratio": 0.3},
    "ICMP": {"packet_count": 10, "duration_seconds": 5.0, "direction_ratio": 0.9},
}


def as_feature_rows(rows: list[dict[str, object]]) -> list[dict[str, float | None]]:
    """Narrow synthetic rows to the type the ML pipeline consumes.

    ``synthetic_features`` is typed ``dict[str, object]`` because it
    deliberately mixes numbers, categorical strings and ``None``. Tests that
    call ``rows_to_matrix``/``predict_rows`` directly bypass ``validate_row``,
    which is the component that actually enforces the narrower type, so this is
    a static assertion only: no value is coerced or changed at runtime.
    """
    return cast("list[dict[str, float | None]]", rows)


def synthetic_features(label: str, index: int, schema: MLFeatureSchema) -> dict[str, object]:
    """Deterministic feature mapping for one synthetic flow.

    Values derive from the class centre plus a fixed per-index offset, so the
    same call always produces the same row and a dataset digest is stable.
    """
    center = _CLASS_CENTERS[label]
    offset = (index % 5) * 0.5
    out: dict[str, object] = {}
    for spec in schema.features:
        if spec.kind == "categorical":
            out[spec.name] = "alpha" if index % 2 == 0 else "beta"
            continue

        # Every third flow leaves nullable features missing, to exercise the
        # imputer + missing-indicator path deterministically.
        if spec.nullable and index % 3 == 0:
            out[spec.name] = None
            continue

        base = center.get(spec.name, 10.0)
        value = base + offset + (index % 3) * 0.1
        # Every generated value must satisfy the schema bounds, otherwise the
        # row would be rejected and the fixture would test nothing. Bounded
        # features (ratios in [0, 1]) are pulled into range.
        if spec.maximum is not None:
            value = min(value, spec.maximum)
        if spec.minimum is not None:
            value = max(value, spec.minimum)
        out[spec.name] = round(value, 4)
    return out


def make_capture(db: Session, capture_key: str, *, sha256: str | None = None) -> Capture:
    now = datetime.now(UTC)
    capture = Capture(
        capture_reference=f"REF-{capture_key}",
        capture_id=capture_key,
        filename=f"{capture_key}.pcap",
        original_filename=f"{capture_key}.pcap",
        stored_filename=f"{capture_key}.pcap",
        file_size=1024 + len(capture_key),
        sha256=sha256 or hashlib_sha(capture_key),
        capture_format="pcap",
        packet_count=100,
        status=CaptureStatus.ANALYZED,
        storage_path=f"/tmp/{capture_key}.pcap",
        uploaded_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(capture)
    db.flush()
    return capture


def hashlib_sha(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_analysis(db: Session, capture: Capture, analysis_key: str) -> Analysis:
    now = datetime.now(UTC)
    analysis = Analysis(
        analysis_id=analysis_key,
        capture_id=capture.id,
        status=AnalysisStatus.COMPLETED,
        protocol_detected="ipsec",
        ike_detected=True,
        esp_detected=True,
        analyzer_version="2.0.0",
        parser_version="2.0.0",
        rule_version="3.0.0",
        started_at=now,
        completed_at=now + timedelta(seconds=1),
        created_at=now,
        updated_at=now,
    )
    db.add(analysis)
    db.flush()
    return analysis


def make_flow_with_features(
    db: Session,
    analysis: Analysis,
    features: dict[str, object],
    *,
    index: int = 0,
    schema: MLFeatureSchema | None = None,
    feature_schema_version: str = "1.0",
) -> Flow:
    """Create a Flow + FlowFeatures pair with the given feature mapping."""
    active = schema or get_feature_schema()
    # The `schema` argument is load-bearing: it fails the fixture at build time
    # rather than producing a row that a later validation stage would silently
    # reject, which would make the test assert nothing.
    unknown = sorted(set(features) - set(active.feature_names))
    if unknown:
        raise ValueError(
            f"Fixture features are outside schema {active.feature_schema_version}: {unknown}"
        )
    now = datetime.now(UTC) + timedelta(seconds=index)

    def count(name: str, fallback: int) -> int:
        """Read a count-like feature as an int.

        `features` is typed `dict[str, object]` because the synthetic generator
        mixes numbers, strings and None, so the value is narrowed here rather
        than asserted at every call site.
        """
        value = features.get(name)
        return int(value) if isinstance(value, (int, float)) else fallback

    flow = Flow(
        analysis_id=analysis.id,
        flow_id=(f"10.0.0.{index % 255 + 1}:{50000 + index}-tcp/4->10.0.1.{index % 255 + 1}:443"),
        source_ip="10.0.0.1",
        destination_ip="10.0.1.1",
        source_port=50000 + index,
        destination_port=443,
        protocol="tcp",
        transport="tcp",
        ip_version=4,
        start_time=now,
        end_time=now + timedelta(seconds=5),
        duration=5.0,
        packet_count=count("packet_count", 10),
        byte_count=count("byte_count", 1000),
        upstream_packets=count("upstream_packets", 5),
        downstream_packets=count("downstream_packets", 5),
        upstream_bytes=count("upstream_bytes", 500),
        downstream_bytes=count("downstream_bytes", 500),
        direction="bidirectional",
        ike_packets=0,
        esp_packets=count("packet_count", 10),
        ah_packets=0,
        created_at=now,
        updated_at=now,
    )
    db.add(flow)
    db.flush()

    db.add(
        FlowFeatures(
            flow_id=flow.id,
            analysis_id=analysis.id,
            feature_schema_version=feature_schema_version,
            feature_json=json.dumps(features),
            created_at=now,
            updated_at=now,
        )
    )
    db.flush()
    return flow


def build_deterministic_dataset(
    db: Session,
    *,
    classes: tuple[str, ...] = ("VOIP", "WEB", "EMAIL", "ICMP"),
    flows_per_class: int = 10,
    captures_per_class: int = 4,
    schema: MLFeatureSchema | None = None,
) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Build a deterministic, fully-labeled dataset for mechanics testing.

    Returns ``(labels_by_capture, capture_sha_by_capture)`` so a caller can
    write a real label file matching exactly what was created.
    """
    active = schema or get_feature_schema()
    labels: dict[str, list[str]] = {}
    shas: dict[str, str] = {}
    flow_index = 0

    for class_index, label in enumerate(classes):
        for capture_index in range(captures_per_class):
            capture_key = f"CAP-T{class_index}{capture_index:02d}"
            sha = hashlib_sha(capture_key)
            capture = make_capture(db, capture_key, sha256=sha)
            analysis = make_analysis(db, capture, f"ANL-T{class_index}{capture_index:02d}")
            for _ in range(flows_per_class):
                features = synthetic_features(label, flow_index, active)
                make_flow_with_features(
                    db,
                    analysis,
                    features,
                    index=flow_index,
                    schema=active,
                )
                flow_index += 1
            labels.setdefault(capture_key, []).append(label)
            shas[capture_key] = sha

    db.commit()
    return labels, shas


def write_label_file(
    path: Path,
    labels: dict[str, list[str]],
    *,
    shas: dict[str, str] | None = None,
    schema: MLFeatureSchema | None = None,
    source: str = "user_provided",
) -> Path:
    """Write a ground-truth label file in the operator format.

    This is how the legitimate label path is exercised end to end: a file on
    disk, in the documented schema, read by the real registry loader.
    """
    active = schema or get_feature_schema()
    entries = []
    for capture_key, class_labels in sorted(labels.items()):
        if not class_labels:
            continue
        label = class_labels[0]
        entry: dict[str, object] = {"capture_id": capture_key, "traffic_type": label}
        if shas and capture_key in shas:
            entry["capture_sha256"] = shas[capture_key]
        entries.append(entry)

    payload = {
        "label_source": source,
        "feature_schema_version": active.feature_schema_version,
        "class_definition_version": active.class_definition_version,
        "labels": entries,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


@pytest.fixture()
def ml_schema() -> MLFeatureSchema:
    return get_feature_schema()


@pytest.fixture()
def ml_model_dir(tmp_path: Path) -> Path:
    """An isolated, empty model registry."""
    target = tmp_path / "models"
    target.mkdir(parents=True, exist_ok=True)
    return target
