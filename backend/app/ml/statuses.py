"""The Phase 4 ML status vocabulary.

One definition of the status strings, typed as literals so that the service
layer, the predictor and the Pydantic response schemas cannot drift apart. The
schemas import from here rather than redeclaring the literals, which means a new
status is added in exactly one place and a typo becomes a type error instead of
a value that silently escapes to the frontend.

These statuses are deliberately *not* HTTP errors. "No model has been trained"
is a normal, expected state of a system with no ground truth, so it travels as
HTTP 200 with an explicit status the UI renders as information.
"""

from __future__ import annotations

from typing import Literal

__all__ = ["RunStatus", "TrainStatus", "TRAIN_STATUSES"]

RunStatus = Literal["OK", "MODEL_NOT_AVAILABLE", "INSUFFICIENT_DATA", "DISABLED"]

TrainStatus = Literal[
    "OK",
    "INSUFFICIENT_LABELED_DATA",
    "INSUFFICIENT_DATA",
    "DISABLED",
    "NO_LABELS_REGISTERED",
    "LABEL_FILE_UNREADABLE",
    "FAILED",
]

#: Runtime-accessible form of :data:`TrainStatus`, used to validate a status
#: before it is stored on an artifact.
TRAIN_STATUSES: frozenset[str] = frozenset(
    {
        "OK",
        "INSUFFICIENT_LABELED_DATA",
        "INSUFFICIENT_DATA",
        "DISABLED",
        "NO_LABELS_REGISTERED",
        "LABEL_FILE_UNREADABLE",
        "FAILED",
    }
)
