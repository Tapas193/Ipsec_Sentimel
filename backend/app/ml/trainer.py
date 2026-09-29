"""Training entrypoint for Phase 4.

Training is **explicit, deliberate and auditable**. It is only reachable when
``ML_TRAINING_ENABLED`` is true, and its only input is the label registry —
never an uploaded capture. There is no "train on the last capture" path.

The trainer's first job is to decide whether training is legitimate at all:

- No labels registered -> ``INSUFFICIENT_LABELED_DATA``. No model is fitted and
  no artifact is written. This is the expected state of the repository as
  shipped, because it contains no ground truth.
- Labels present but too few, or too few per class, or too few captures to hold
  out a test split -> ``INSUFFICIENT_DATA`` with the exact shortfall.
- Only then is a model fitted, evaluated on the held-out test split, versioned
  and written to the registry.

Fitting is skipped entirely in the first two cases, so a misleading artifact can
never exist.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from app.ml import baseline
from app.ml import metrics as metrics_module
from app.ml.artifacts import (
    ModelArtifact,
    ModelMetadata,
    environment_fingerprint,
    save_artifact,
    utc_now_iso,
)
from app.ml.dataset import (
    STATUS_INSUFFICIENT_LABELED_DATA,
    STATUS_OK,
    DatasetBuildResult,
    build_dataset,
)
from app.ml.labels import load_label_registry
from app.ml.preprocessing import rows_to_matrix
from app.ml.schema import MLFeatureSchema, get_feature_schema
from app.ml.splitter import assert_no_capture_leakage

logger = logging.getLogger("ipsec_sentinel.ml")

STATUS_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
STATUS_TRAINED = "TRAINED"
DEFAULT_MODEL_NAME = "traffic-classifier"


@dataclass(frozen=True)
class TrainingResult:
    status: str
    reason: str | None
    model_version: str | None
    dataset: dict[str, Any]
    class_distribution: dict[str, dict[str, Any]]
    split_counts: dict[str, int]
    evaluation: dict[str, Any] | None
    metadata: dict[str, Any] | None
    duration_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "model_version": self.model_version,
            "dataset": self.dataset,
            "class_distribution": self.class_distribution,
            "split_counts": self.split_counts,
            "evaluation": self.evaluation,
            "metadata": self.metadata,
            "duration_ms": self.duration_ms,
        }


def _split_counts(result: DatasetBuildResult) -> dict[str, int]:
    if result.splits is None:
        return {"train": 0, "validation": 0, "test": 0}
    return {
        "train": len(result.splits.train),
        "validation": len(result.splits.validation),
        "test": len(result.splits.test),
    }


def _distribution(result: DatasetBuildResult, schema: MLFeatureSchema) -> dict[str, dict[str, Any]]:
    labels = [sample.label for sample in result.samples]
    classes = sorted({*schema.declared_classes, *result.class_distribution})
    return metrics_module.class_distribution(labels, classes)


def _insufficient(
    status: str,
    reason: str,
    result: DatasetBuildResult,
    schema: MLFeatureSchema,
    started: float,
) -> TrainingResult:
    return TrainingResult(
        status=status,
        reason=reason,
        model_version=None,
        dataset=result.summary(),
        class_distribution=_distribution(result, schema),
        split_counts=_split_counts(result),
        evaluation=None,
        metadata=None,
        duration_ms=round((time.monotonic() - started) * 1000, 2),
    )


def train_model(
    db: Any,
    *,
    model_dir: str,
    model_version: str,
    label_file: str | None,
    random_seed: int | None = None,
    schema: MLFeatureSchema | None = None,
) -> TrainingResult:
    """Build a dataset and, only if it is legitimate, fit and version a model."""
    started = time.monotonic()
    active_schema = schema or get_feature_schema()
    seed = random_seed if random_seed is not None else active_schema.dataset.random_seed

    logger.info("ml training requested", extra={"model_version": model_version})

    registry = load_label_registry(label_file, active_schema)
    dataset = build_dataset(
        db, schema=active_schema, label_registry=registry, label_file=label_file
    )

    if dataset.status == STATUS_INSUFFICIENT_LABELED_DATA or dataset.labeled_rows == 0:
        logger.warning(
            "ml training refused: insufficient labeled data",
            extra={
                "total_feature_rows": dataset.total_feature_rows,
                "unlabeled_rows": dataset.unlabeled_rows,
                "label_file": bool(label_file),
            },
        )
        return _insufficient(
            STATUS_INSUFFICIENT_LABELED_DATA,
            "No capture in the database has a registered ground-truth label. "
            "Phase 4 does not generate labels, so there is nothing legitimate to train on. "
            "Register ground truth via ML_LABEL_FILE and re-run training.",
            dataset,
            active_schema,
            started,
        )

    spec = active_schema.dataset
    shortfalls: list[str] = []
    if dataset.labeled_rows < spec.min_total_samples:
        shortfalls.append(
            f"labeled flows {dataset.labeled_rows} < min_total_samples {spec.min_total_samples}"
        )
    for name, count in sorted(dataset.class_distribution.items()):
        class_spec = active_schema.class_spec(name)
        minimum = class_spec.min_samples if class_spec else spec.min_samples_per_class
        if count < max(minimum, spec.min_samples_per_class):
            shortfalls.append(f"class {name} has {count} samples, needs {minimum}")
    if dataset.labeled_capture_count < spec.min_captures_per_split:
        shortfalls.append(
            f"labeled captures {dataset.labeled_capture_count} < "
            f"min_captures_per_split {spec.min_captures_per_split}"
        )

    splits = dataset.splits
    assert splits is not None  # guaranteed once samples exist
    if not splits.validation or not splits.test:
        shortfalls.append(
            "capture-level split produced an empty validation or test set "
            "(more labeled captures are required for a held-out evaluation)"
        )

    if shortfalls:
        logger.warning(
            "ml training refused: insufficient data",
            extra={"shortfalls": shortfalls, "labeled_rows": dataset.labeled_rows},
        )
        return _insufficient(
            STATUS_INSUFFICIENT_DATA,
            "; ".join(shortfalls),
            dataset,
            active_schema,
            started,
        )

    assert_no_capture_leakage(splits)

    labels = {id(sample.row.flow_uuid): sample.label for sample in dataset.samples}
    y_train = [labels[id(row.flow_uuid)] for row in splits.train]
    y_validation = [labels[id(row.flow_uuid)] for row in splits.validation]
    y_test = [labels[id(row.flow_uuid)] for row in splits.test]
    x_train = rows_to_matrix([row.features for row in splits.train], active_schema)
    x_validation = rows_to_matrix([row.features for row in splits.validation], active_schema)
    x_test = rows_to_matrix([row.features for row in splits.test], active_schema)

    classes = sorted(set(y_train) | set(y_validation) | set(y_test))
    distribution = metrics_module.class_distribution([*y_train, *y_validation, *y_test], classes)

    fit_started = time.monotonic()
    pipeline = baseline.build_pipeline(active_schema, seed=seed)
    pipeline.fit(x_train, y_train)
    fit_ms = round((time.monotonic() - fit_started) * 1000, 2)

    validation_pred = list(pipeline.predict(x_validation))
    test_pred = list(pipeline.predict(x_test))
    test_proba = [list(row) for row in pipeline.predict_proba(x_test)]
    test_classes = [str(c) for c in pipeline.classes_]

    evaluation: dict[str, Any] = {
        "status": STATUS_OK,
        "dataset_version": dataset.dataset_version,
        "feature_schema_version": dataset.feature_schema_version,
        "class_definition_version": dataset.class_definition_version,
        "model_version": model_version,
        "model_type": baseline.MODEL_TYPE,
        "random_seed": seed,
        "training_timestamp": utc_now_iso(),
        "train_count": len(y_train),
        "validation_count": len(y_validation),
        "test_count": len(y_test),
        "class_distribution": distribution,
        "dataset_digest": dataset.dataset_digest,
        "model_parameters": baseline.classifier_params(seed),
        "preprocessing_version": active_schema.preprocessing.version,
        "split": dataset.allocation.as_dict() if dataset.allocation else None,
        "fit_duration_ms": fit_ms,
    }

    if len(y_test) < spec.min_samples_for_metrics:
        evaluation.update(
            metrics_module.insufficient_data(
                f"held-out test split has {len(y_test)} samples, "
                f"below min_samples_for_metrics {spec.min_samples_for_metrics}",
                {"train": len(y_train), "validation": len(y_validation), "test": len(y_test)},
            )
        )
        logger.info(
            "ml model fitted but metrics withheld: insufficient held-out data",
            extra={"test_count": len(y_test), "model_version": model_version},
        )
    else:
        evaluation.update(
            metrics_module.evaluate_predictions(y_test, test_pred, test_classes, test_proba)
        )
        evaluation["validation"] = {
            "predictions": len(validation_pred),
            "agreement_with_train_labels": sum(
                1
                for pred, truth in zip(validation_pred, y_validation, strict=True)
                if pred == truth
            ),
        }

    metadata = ModelMetadata(
        model_version=model_version,
        model_type=baseline.MODEL_TYPE,
        dataset_version=dataset.dataset_version,
        feature_schema_version=dataset.feature_schema_version,
        class_definition_version=dataset.class_definition_version,
        analyzer_version=_single_version([row.analyzer_version for row in splits.train]),
        parser_version=_single_version([row.parser_version for row in splits.train]),
        preprocessing_version=active_schema.preprocessing.version,
        training_timestamp=str(evaluation["training_timestamp"]),
        random_seed=seed,
        classes=test_classes,
        feature_names=active_schema.feature_names,
        dataset_digest=dataset.dataset_digest,
        label_source=dataset.label_registry_source,
        training_data_counts={
            "train": len(y_train),
            "validation": len(y_validation),
            "test": len(y_test),
        },
        environment=environment_fingerprint(),
        artifact_sha256="",
        ml_library_versions=environment_fingerprint(),
    )

    artifact: ModelArtifact = save_artifact(
        model_dir=model_dir,
        metadata=metadata,
        pipeline=pipeline,
        evaluation=evaluation,
    )

    logger.info(
        "ml training complete",
        extra={
            "model_version": artifact.model_version,
            "train_count": len(y_train),
            "validation_count": len(y_validation),
            "test_count": len(y_test),
            "fit_duration_ms": fit_ms,
        },
    )

    return TrainingResult(
        status=STATUS_TRAINED,
        reason=None,
        model_version=artifact.model_version,
        dataset=dataset.summary(),
        class_distribution=distribution,
        split_counts={"train": len(y_train), "validation": len(y_validation), "test": len(y_test)},
        evaluation=evaluation,
        metadata=artifact.metadata.as_dict(),
        duration_ms=round((time.monotonic() - started) * 1000, 2),
    )


def _single_version(values: list[str | None]) -> str | None:
    unique = {value for value in values if value}
    if len(unique) == 1:
        return unique.pop()
    return None
