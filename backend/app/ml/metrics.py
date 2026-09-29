"""Metrics and calibration for Phase 4.

The hard rule here is that **small samples do not produce numbers**. A
2-sample test split yields an accuracy of 0.0 or 1.0 and a macro F1 that is
either meaningless or undefined. Publishing those as if they measured
something is worse than publishing nothing, so below
``min_samples_for_metrics`` the artifact records ``INSUFFICIENT_DATA`` and the
metric block is absent.
"""

from __future__ import annotations

from typing import Any

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)

STATUS_OK = "OK"
STATUS_INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


def class_distribution(labels: list[str], classes: list[str]) -> dict[str, dict[str, Any]]:
    """Class -> count and percentage, in declared class order (zeros included)."""
    total = len(labels)
    distribution: dict[str, dict[str, Any]] = {}
    for name in classes:
        count = sum(1 for label in labels if label == name)
        distribution[name] = {
            "count": count,
            "percentage": round((count / total) * 100, 2) if total else 0.0,
        }
    return distribution


def evaluate_predictions(
    y_true: list[str],
    y_pred: list[str],
    classes: list[str],
    y_proba: list[list[float]] | None = None,
    min_confidence: float = 0.60,
) -> dict[str, Any]:
    """Full metric block for a labelled evaluation set.

    The returned mapping is **flat** and is merged straight into the artifact's
    ``evaluation.json`` by the trainer, so every headline metric sits at the top
    level where the API reads it.

    ``y_proba`` is optional but strongly preferred: without it the calibration
    and confidence figures are omitted rather than guessed.
    """
    if not y_true or len(y_true) != len(y_pred):
        return insufficient_data(
            "evaluation requires a non-empty, aligned (y_true, y_pred) pair",
            {"y_true": len(y_true), "y_pred": len(y_pred)},
        )

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=classes,
        zero_division=0,
    )
    per_class = {
        name: {
            "precision": round(float(precision[i]), 4),
            "recall": round(float(recall[i]), 4),
            "f1": round(float(f1[i]), 4),
            "support": int(support[i]),
        }
        for i, name in enumerate(classes)
    }
    matrix = confusion_matrix(y_true, y_pred, labels=classes).tolist()

    result: dict[str, Any] = {
        "status": STATUS_OK,
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_macro": round(
            float(
                precision_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)
            ),
            4,
        ),
        "recall_macro": round(
            float(recall_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
            4,
        ),
        "f1_macro": round(
            float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)), 4
        ),
        "f1_weighted": round(
            float(f1_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0)),
            4,
        ),
        "per_class": per_class,
        "confusion_matrix": matrix,
        "confusion_matrix_labels": list(classes),
        "class_order": list(classes),
        "evaluated_samples": len(y_true),
    }

    if y_proba is not None and len(y_proba) == len(y_true):
        result.update(_calibration(y_true, y_pred, y_proba, classes, min_confidence))

    return result


def _calibration(
    y_true: list[str],
    y_pred: list[str],
    y_proba: list[list[float]],
    classes: list[str],
    min_confidence: float,
) -> dict[str, Any]:
    """Confidence quality: log loss, reliability, and the abstention rate.

    Not a full calibration curve — the sample counts here never justify one.
    ``expected_calibration_error`` is reported as ``None`` rather than 0.0 when
    there is not enough signal to estimate it.
    """
    try:
        loss: float | None = round(float(log_loss(y_true, y_proba, labels=classes)), 4)
    except ValueError:
        loss = None

    buckets: dict[str, dict[str, int]] = {
        "0.00-0.40": {"total": 0, "correct": 0},
        "0.40-0.60": {"total": 0, "correct": 0},
        "0.60-0.80": {"total": 0, "correct": 0},
        "0.80-1.00": {"total": 0, "correct": 0},
    }
    confidences: list[float] = []
    abstained = 0

    for truth, predicted, probabilities in zip(y_true, y_pred, y_proba, strict=True):
        top = max(range(len(probabilities)), key=lambda i: probabilities[i])
        confidence = float(probabilities[top])
        confidences.append(confidence)
        if confidence < min_confidence:
            abstained += 1
        key = _bucket(confidence)
        buckets[key]["total"] += 1
        # Correctness is judged against `y_pred`, the same array the headline
        # accuracy is computed from, so the reliability buckets can never
        # disagree with the reported score. `top` is used only to read the
        # confidence out of the probability vector.
        if predicted == truth:
            buckets[key]["correct"] += 1

    reliability = {
        key: {
            "count": value["total"],
            "accuracy": round(value["correct"] / value["total"], 4) if value["total"] else None,
        }
        for key, value in buckets.items()
    }

    ece: float | None = None
    # A bucket with a non-zero count always has an accuracy, so the `None` case
    # is filtered out here rather than asserted away at the arithmetic below.
    populated = [
        (name, bucket["count"], bucket["accuracy"])
        for name, bucket in reliability.items()
        if bucket["count"] and bucket["accuracy"] is not None
    ]
    if populated:
        ece = round(
            sum(
                (count / len(y_true)) * abs(accuracy - _bucket_midpoint(name))
                for name, count, accuracy in populated
            ),
            4,
        )

    return {
        "calibration": {
            "log_loss": loss,
            "reliability_by_confidence": reliability,
            "min_confidence": min_confidence,
        },
        "log_loss": loss,
        "mean_predicted_confidence": (
            round(sum(confidences) / len(confidences), 4) if confidences else None
        ),
        "expected_calibration_error": ece,
        "abstained_count": abstained,
        "abstention_rate": round(abstained / len(y_true), 4) if y_true else None,
    }


def _bucket_midpoint(label: str) -> float:
    low, _, high = label.partition("-")
    try:
        return (float(low) + float(high)) / 2
    except ValueError:
        return 0.5


def _bucket(confidence: float) -> str:
    if confidence < 0.40:
        return "0.00-0.40"
    if confidence < 0.60:
        return "0.40-0.60"
    if confidence < 0.80:
        return "0.60-0.80"
    return "0.80-1.00"


def insufficient_data(reason: str, counts: dict[str, int]) -> dict[str, Any]:
    """The explicit 'we are not reporting metrics' artifact body."""
    return {
        "status": STATUS_INSUFFICIENT_DATA,
        "reason": reason,
        "sample_counts": counts,
        "metrics": None,
        "confusion_matrix": None,
    }
