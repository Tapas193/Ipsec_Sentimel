"""Capture-level splitting for Phase 4.

The split unit is the **capture**, never the flow. This is the single most
important correctness property of the dataset.

Why
---
Flows inside one capture share a source, a destination, a time window, an MTU, a
network stack and often an application session. They are statistically
dependent. If flow 1 of capture A trains a model and flow 2 of the same capture
tests it, the test score measures memorisation of that capture's traffic mix,
not generalisation. A model can score near-perfect on such a split while being
useless on a new capture — the failure mode is invisible in the metrics.

Splitting whole captures makes the test set a set of *environments* the model
has never seen, which is the only split that answers the real question.

Determinism
-----------
Grouping uses ``sorted(capture keys)`` plus a seeded ``random.Random``. Python's
built-in ``hash()`` is salted per process and would make splits irreproducible
between runs, so it is never used. Sorting the keys first also removes any
dependence on database row order.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from app.ml.validation import ValidatedRow

T = TypeVar("T")

SPLIT_TRAIN = "train"
SPLIT_VALIDATION = "validation"
SPLIT_TEST = "test"

SPLITS = (SPLIT_TRAIN, SPLIT_VALIDATION, SPLIT_TEST)


@dataclass(frozen=True)
class SplitAllocation:
    """Which captures landed in which split, and why."""

    train: tuple[str, ...]
    validation: tuple[str, ...]
    test: tuple[str, ...]
    seed: int
    strategy: str

    def captures_for(self, split: str) -> tuple[str, ...]:
        if split == SPLIT_TRAIN:
            return self.train
        if split == SPLIT_VALIDATION:
            return self.validation
        if split == SPLIT_TEST:
            return self.test
        raise ValueError(f"unknown split {split!r}")

    def as_dict(self) -> dict[str, object]:
        return {
            "split_unit": "capture",
            "strategy": self.strategy,
            "random_seed": self.seed,
            "captures": {
                SPLIT_TRAIN: list(self.train),
                SPLIT_VALIDATION: list(self.validation),
                SPLIT_TEST: list(self.test),
            },
            "counts": {
                SPLIT_TRAIN: len(self.train),
                SPLIT_VALIDATION: len(self.validation),
                SPLIT_TEST: len(self.test),
            },
        }


@dataclass
class SplitResult(Generic[T]):
    train: list[T] = field(default_factory=list)
    validation: list[T] = field(default_factory=list)
    test: list[T] = field(default_factory=list)
    allocation: SplitAllocation | None = None

    def as_dict(self) -> dict[str, list[T]]:
        return {
            SPLIT_TRAIN: self.train,
            SPLIT_VALIDATION: self.validation,
            SPLIT_TEST: self.test,
        }


def allocate_captures(
    capture_keys: list[str],
    *,
    seed: int,
    train_ratio: float,
    validation_ratio: float,
    test_ratio: float,
    min_captures_per_split: int = 1,
) -> SplitAllocation:
    """Assign whole captures to train/validation/test deterministically."""
    total_ratio = train_ratio + validation_ratio + test_ratio
    if abs(total_ratio - 1.0) > 1e-6:
        raise ValueError(f"split ratios must sum to 1.0, got {total_ratio}")

    unique_keys = sorted(set(capture_keys))
    if not unique_keys:
        return SplitAllocation((), (), (), seed, "empty")

    shuffled = list(unique_keys)
    random.Random(seed).shuffle(shuffled)

    total = len(shuffled)
    n_train = int(total * train_ratio)
    n_validation = int(total * validation_ratio)

    # Guarantee at least one capture per split once there are enough captures,
    # because an empty test split silently makes evaluation meaningless.
    if total >= 3 * min_captures_per_split:
        n_train = max(n_train, min_captures_per_split)
        n_validation = max(n_validation, min_captures_per_split)
        leftover = total - n_train - n_validation
        while leftover < min_captures_per_split:
            if n_train >= n_validation:
                n_train -= 1
            else:
                n_validation -= 1
            leftover += 1
    else:
        # Too few captures: everything trains, nothing is held out. Reported as
        # insufficient rather than producing a fake evaluation.
        n_train, n_validation = total, 0

    train = tuple(sorted(shuffled[:n_train]))
    validation = tuple(sorted(shuffled[n_train : n_train + n_validation]))
    test = tuple(sorted(shuffled[n_train + n_validation :]))

    return SplitAllocation(
        train=train,
        validation=validation,
        test=test,
        seed=seed,
        strategy="seeded_shuffle_by_capture",
    )


def split_rows(
    rows: list[ValidatedRow],
    allocation: SplitAllocation,
) -> SplitResult[ValidatedRow]:
    """Partition rows by the capture allocation.

    A row whose capture is in no split is dropped; the caller compares totals
    and reports the difference rather than hiding it.
    """
    train_keys = set(allocation.train)
    validation_keys = set(allocation.validation)
    test_keys = set(allocation.test)

    result: SplitResult[ValidatedRow] = SplitResult(allocation=allocation)
    for row in rows:
        if row.capture_id in train_keys:
            result.train.append(row)
        elif row.capture_id in validation_keys:
            result.validation.append(row)
        elif row.capture_id in test_keys:
            result.test.append(row)
    return result


def assert_no_capture_leakage(result: SplitResult[ValidatedRow]) -> None:
    """Raise if any capture appears in more than one split.

    Called by the trainer before fitting. Cheap insurance against a future
    refactor reintroducing flow-level splitting.
    """
    train = {row.capture_id for row in result.train}
    validation = {row.capture_id for row in result.validation}
    test = {row.capture_id for row in result.test}

    overlaps = {
        "train/validation": sorted(train & validation),
        "train/test": sorted(train & test),
        "validation/test": sorted(validation & test),
    }
    leaked = {name: keys for name, keys in overlaps.items() if keys}
    if leaked:
        raise ValueError(f"capture leakage detected between splits: {leaked}")
