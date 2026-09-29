"""Dataset builder for Phase 4.

Reads persisted Phase 2 ``flow_features`` rows, joins them to their ``flows`` /
``analyses`` / ``captures`` for provenance, resolves labels from the operator
label registry, validates every row, and returns a versioned, reproducible
dataset.

Reproducibility comes from three things: the feature order is the schema order,
rows are ordered by a stable key (analysis key, then flow key) rather than by
database return order, and the split seed is recorded. Two runs over the same
database produce byte-identical artefacts.

What the builder refuses to do:

- It will not fabricate a label for an unlabeled capture. Unlabeled captures are
  reported as such and excluded.
- It will not repair a bad feature value. Bad rows are rejected with a reason.
- It will not read features from anywhere except ``flow_features``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.ml.labels import LabelRegistry, empty_registry, load_label_registry
from app.ml.schema import MLFeatureSchema, get_feature_schema
from app.ml.splitter import SplitAllocation, allocate_captures, split_rows
from app.ml.validation import Rejection, ValidatedRow, validate_row
from app.models import Analysis, Flow, FlowFeatures

if TYPE_CHECKING:
    from app.ml.splitter import SplitResult

STATUS_OK = "OK"
STATUS_INSUFFICIENT_LABELED_DATA = "INSUFFICIENT_LABELED_DATA"


@dataclass(frozen=True)
class LabeledSample:
    """A validated feature row with its resolved ground-truth label."""

    row: ValidatedRow
    label: str
    label_source: str


@dataclass
class DatasetBuildResult:
    status: str
    dataset_version: str
    feature_schema_version: str
    class_definition_version: str
    feature_names: tuple[str, ...]
    total_feature_rows: int
    labeled_rows: int
    unlabeled_rows: int
    samples: list[LabeledSample]
    rejections: list[Rejection]
    class_distribution: dict[str, int]
    capture_count: int
    labeled_capture_count: int
    allocation: SplitAllocation | None
    splits: SplitResult[ValidatedRow] | None
    label_registry_source: str
    label_file: str | None
    notes: list[str]

    @property
    def dataset_digest(self) -> str:
        """Stable digest over the accepted samples, for reproducibility checks."""
        payload = [
            {
                "capture": sample.row.capture_id,
                "flow": sample.row.flow_key,
                "label": sample.label,
                "features": [sample.row.features[name] for name in self.feature_names],
            }
            for sample in sorted(self.samples, key=lambda s: (s.row.capture_id, s.row.flow_key))
        ]
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "dataset_version": self.dataset_version,
            "feature_schema_version": self.feature_schema_version,
            "class_definition_version": self.class_definition_version,
            "dataset_digest": self.dataset_digest,
            "feature_names": list(self.feature_names),
            "feature_count": len(self.feature_names),
            "total_feature_rows": self.total_feature_rows,
            "labeled_rows": self.labeled_rows,
            "unlabeled_rows": self.unlabeled_rows,
            "rejected_rows": len(self.rejections),
            "rejection_reasons": _count_by(self.rejections, lambda r: r.reason),
            "capture_count": self.capture_count,
            "labeled_capture_count": self.labeled_capture_count,
            "class_distribution": self.class_distribution,
            "label_registry_source": self.label_registry_source,
            "label_file": self.label_file,
            "notes": self.notes,
            "split": None if self.allocation is None else self.allocation.as_dict(),
        }


def _count_by(items: list[Rejection], key: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        bucket = str(key(item))
        counts[bucket] = counts.get(bucket, 0) + 1
    return dict(sorted(counts.items()))


def build_dataset(
    db: Session,
    *,
    schema: MLFeatureSchema | None = None,
    label_registry: LabelRegistry | None = None,
    label_file: str | None = None,
    max_rows: int | None = None,
) -> DatasetBuildResult:
    """Build the labeled dataset from persisted Phase 2 features.

    The registry and schema are injectable so tests never touch global settings.
    """
    active_schema = schema or get_feature_schema()
    if label_registry is None:
        registry = load_label_registry(label_file, active_schema)
    else:
        registry = label_registry

    notes: list[str] = []
    if registry.is_empty:
        notes.append(
            "No ground-truth labels are registered (ML_LABEL_FILE is unset or empty). "
            "Phase 4 will not invent labels, so no dataset can be labeled."
        )
    if registry.rejected:
        notes.append(f"{len(registry.rejected)} label rows were rejected; see label_rejections.")

    samples: list[LabeledSample] = []
    rejections: list[Rejection] = []
    unlabeled = 0
    total_rows = 0
    captures: set[str] = set()
    labeled_captures: set[str] = set()

    registry_lookup = registry.by_capture_key

    query = (
        select(FlowFeatures)
        .options(
            selectinload(FlowFeatures.flow)
            .selectinload(Flow.analysis)
            .selectinload(Analysis.capture)
        )
        .order_by(FlowFeatures.analysis_id, FlowFeatures.flow_id)
    )
    if max_rows is not None:
        query = query.limit(max_rows)

    for feature_row in db.scalars(query).all():
        total_rows += 1
        flow = feature_row.flow
        if flow is None:
            rejections.append(
                Rejection(
                    flow_key=feature_row.flow_id,
                    analysis_id=feature_row.analysis_id,
                    capture_id="unknown",
                    reason="orphan_flow_feature",
                    detail="FlowFeatures row has no flow",
                )
            )
            continue

        analysis = flow.analysis
        capture = analysis.capture if analysis is not None else None
        if analysis is None or capture is None:
            rejections.append(
                Rejection(
                    flow_key=flow.flow_id,
                    analysis_id=analysis.analysis_id if analysis else feature_row.analysis_id,
                    capture_id="unknown",
                    reason="orphan_flow_feature",
                    detail="Flow has no analysis/capture",
                )
            )
            continue

        captures.add(capture.capture_id)
        raw_features = feature_row.features

        candidate, rejection = validate_row(
            raw_features,
            schema=active_schema,
            source_feature_schema_version=feature_row.feature_schema_version,
            flow_key=flow.flow_id,
            flow_uuid=flow.id,
            analysis_id=analysis.id,
            analysis_key=analysis.analysis_id,
            capture_id=capture.capture_id,
            capture_sha256=capture.sha256,
            analyzer_version=analysis.analyzer_version,
            parser_version=analysis.parser_version,
        )
        if rejection is not None:
            rejections.append(rejection)
            continue

        assert candidate is not None  # for type checkers

        label = registry_lookup.get(capture.capture_id)
        if label is None and capture.sha256:
            label = registry_lookup.get(capture.sha256)
        if label is None:
            unlabeled += 1
            continue

        labeled_captures.add(capture.capture_id)
        samples.append(
            LabeledSample(row=candidate, label=label.traffic_type, label_source=label.source)
        )

    samples.sort(key=lambda s: (s.row.capture_id, s.row.flow_key))

    class_distribution: dict[str, int] = {}
    for sample in samples:
        class_distribution[sample.label] = class_distribution.get(sample.label, 0) + 1

    allocation = None
    splits = None
    status = STATUS_OK
    if not samples:
        status = STATUS_INSUFFICIENT_LABELED_DATA
    else:
        allocate_keys = sorted({sample.row.capture_id for sample in samples})
        allocation = allocate_captures(
            allocate_keys,
            seed=active_schema.dataset.random_seed,
            train_ratio=active_schema.dataset.train_ratio,
            validation_ratio=active_schema.dataset.validation_ratio,
            test_ratio=active_schema.dataset.test_ratio,
            min_captures_per_split=active_schema.dataset.min_captures_per_split,
        )
        splits = split_rows([sample.row for sample in samples], allocation)

    return DatasetBuildResult(
        status=status,
        dataset_version=active_schema.dataset_version,
        feature_schema_version=active_schema.feature_schema_version,
        class_definition_version=active_schema.class_definition_version,
        feature_names=tuple(active_schema.feature_names),
        total_feature_rows=total_rows,
        labeled_rows=len(samples),
        unlabeled_rows=unlabeled,
        samples=samples,
        rejections=rejections,
        class_distribution=dict(sorted(class_distribution.items())),
        capture_count=len(captures),
        labeled_capture_count=len(labeled_captures),
        allocation=allocation,
        splits=splits,
        label_registry_source=registry.source if not registry.is_empty else "none",
        label_file=label_file,
        notes=notes,
    )


def dataset_records(result: DatasetBuildResult) -> list[dict[str, Any]]:
    """Audit-friendly flat view of the dataset, used in tests and reports."""
    created = datetime.now(UTC).isoformat()
    return [
        {
            "capture_id": sample.row.capture_id,
            "analysis_key": sample.row.analysis_key,
            "flow_key": sample.row.flow_key,
            "label": sample.label,
            "label_source": sample.label_source,
            "feature_schema_version": sample.row.feature_schema_version,
            "analyzer_version": sample.row.analyzer_version,
            "parser_version": sample.row.parser_version,
            "created_at": created,
            "features": dict(sample.row.features),
        }
        for sample in result.samples
    ]


def unlabeled_placeholder() -> LabelRegistry:
    """Kept for tests that want an explicit empty registry."""
    return empty_registry()
