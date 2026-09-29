"""Schema-driven feature contract for the Phase 4 ML pipeline.

The single source of truth is ``configs/ml_feature_schema.yaml``. Nothing in
this package hardcodes a feature name, a bound, or a class: if it is not in the
schema, the pipeline does not know about it.

Two rules are enforced here rather than trusted downstream:

- A feature may never appear in both ``features`` and ``excluded_fields``.
  Exclusions cover identifiers, timestamps, addresses/ports, free-form strings
  and Phase 3 outputs — every one of them a leakage route.
- Feature order is the order declared in the file, so a ``feature_names`` list
  recorded on a model can be replayed exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.config import get_settings


class MLSchemaError(RuntimeError):
    """Raised when the ML feature schema is missing or internally inconsistent."""


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    kind: str  # numeric | categorical
    unit: str
    nullable: bool
    minimum: float | None
    maximum: float | None

    def in_range(self, value: float) -> bool:
        if self.minimum is not None and value < self.minimum:
            return False
        if self.maximum is not None and value > self.maximum:
            return False
        return True


@dataclass(frozen=True)
class ClassSpec:
    name: str
    active: bool
    min_samples: int


@dataclass(frozen=True)
class PreprocessingSpec:
    version: str
    imputer_strategy: str
    add_missing_indicator: bool
    scaler: str
    categorical_imputer_strategy: str
    unknown_token: str


@dataclass(frozen=True)
class DatasetSpec:
    split_unit: str
    train_ratio: float
    validation_ratio: float
    test_ratio: float
    random_seed: int
    min_total_samples: int
    min_samples_per_class: int
    min_captures_per_split: int
    min_samples_for_metrics: int


@dataclass(frozen=True)
class MLFeatureSchema:
    dataset_version: str
    feature_schema_version: str
    source_feature_schema_version: str
    target_name: str
    label_sources: tuple[str, ...]
    provenance_observation_status: str
    forbidden_label_sources: tuple[str, ...]
    classes: tuple[ClassSpec, ...]
    class_definition_version: str
    features: tuple[FeatureSpec, ...]
    excluded_fields: frozenset[str]
    preprocessing: PreprocessingSpec
    dataset: DatasetSpec
    path: Path = field(default=Path())

    @property
    def feature_names(self) -> list[str]:
        return [f.name for f in self.features]

    @property
    def numeric_features(self) -> list[str]:
        return [f.name for f in self.features if f.kind == "numeric"]

    @property
    def categorical_features(self) -> list[str]:
        return [f.name for f in self.features if f.kind == "categorical"]

    @property
    def nullable_features(self) -> list[str]:
        return [f.name for f in self.features if f.nullable]

    @property
    def active_classes(self) -> list[str]:
        return [c.name for c in self.classes if c.active]

    @property
    def declared_classes(self) -> list[str]:
        return [c.name for c in self.classes]

    def class_spec(self, name: str) -> ClassSpec | None:
        upper = name.upper()
        return next((c for c in self.classes if c.name == upper), None)

    def feature_spec(self, name: str) -> FeatureSpec | None:
        return next((f for f in self.features if f.name == name), None)


def _require(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise MLSchemaError(f"missing required key {key!r} in {where}")
    return mapping[key]


def load_feature_schema(path: str | Path | None = None) -> MLFeatureSchema:
    """Load and validate the ML feature schema.

    Parameter is explicit so tests can point at a fixture schema without
    mutating process-global settings.
    """
    resolved = Path(path) if path is not None else Path(get_settings().ML_FEATURE_SCHEMA_PATH)
    if not resolved.is_file():
        raise MLSchemaError(f"ML feature schema not found: {resolved}")

    raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise MLSchemaError(f"ML feature schema must be a mapping: {resolved}")

    target = _require(raw, "target", "schema")
    class_def = _require(raw, "class_definition", "schema")
    preprocessing = _require(raw, "preprocessing", "schema")
    dataset = _require(raw, "dataset", "schema")

    features: list[FeatureSpec] = []
    for entry in _require(raw, "features", "schema"):
        name = str(_require(entry, "name", "features[]"))
        kind = str(_require(entry, "kind", f"features[{name}]"))
        if kind not in {"numeric", "categorical"}:
            raise MLSchemaError(f"feature {name!r} has unsupported kind {kind!r}")
        features.append(
            FeatureSpec(
                name=name,
                kind=kind,
                unit=str(entry.get("unit", "")),
                nullable=bool(_require(entry, "nullable", f"features[{name}]")),
                minimum=None if entry.get("min") is None else float(entry["min"]),
                maximum=None if entry.get("max") is None else float(entry["max"]),
            )
        )

    if not features:
        raise MLSchemaError("schema declares no features")
    duplicates = {n for n in (f.name for f in features) if sum(f.name == n for f in features) > 1}
    if duplicates:
        raise MLSchemaError(f"duplicate feature names: {sorted(duplicates)}")

    excluded: set[str] = set()
    for group in _require(raw, "excluded_fields", "schema").values():
        excluded.update(str(name) for name in _require(group, "fields", "excluded_fields[]"))

    overlap = sorted({f.name for f in features} & excluded)
    if overlap:
        raise MLSchemaError(f"features declared as both included and excluded: {overlap}")

    classes = tuple(
        ClassSpec(
            name=str(_require(entry, "name", "class_definition.classes[]")).upper(),
            active=bool(entry.get("active", False)),
            min_samples=int(entry.get("min_samples", 1)),
        )
        for entry in _require(class_def, "classes", "class_definition")
    )
    if not classes:
        raise MLSchemaError("schema declares no classes")

    numeric_pre = _require(preprocessing, "numeric", "preprocessing")

    return MLFeatureSchema(
        dataset_version=str(_require(raw, "dataset_version", "schema")),
        feature_schema_version=str(_require(raw, "feature_schema_version", "schema")),
        source_feature_schema_version=str(_require(raw, "source_feature_schema_version", "schema")),
        target_name=str(_require(target, "name", "target")),
        label_sources=tuple(str(s) for s in _require(target, "label_sources", "target")),
        provenance_observation_status=str(
            _require(target, "provenance_observation_status", "target")
        ),
        forbidden_label_sources=tuple(str(s) for s in target.get("forbidden_sources", [])),
        classes=classes,
        class_definition_version=str(_require(class_def, "version", "class_definition")),
        features=tuple(features),
        excluded_fields=frozenset(excluded),
        preprocessing=PreprocessingSpec(
            version=str(_require(preprocessing, "version", "preprocessing")),
            imputer_strategy=str(
                _require(numeric_pre, "imputer_strategy", "preprocessing.numeric")
            ),
            add_missing_indicator=bool(
                _require(numeric_pre, "add_missing_indicator", "preprocessing.numeric")
            ),
            scaler=str(_require(numeric_pre, "scaler", "preprocessing.numeric")),
            categorical_imputer_strategy=str(
                _require(preprocessing, "categorical", "preprocessing")["imputer_strategy"]
            ),
            unknown_token=str(preprocessing["categorical"].get("unknown_token", "__UNKNOWN__")),
        ),
        dataset=DatasetSpec(
            split_unit=str(_require(dataset, "split_unit", "dataset")),
            train_ratio=float(_require(dataset, "train_ratio", "dataset")),
            validation_ratio=float(_require(dataset, "validation_ratio", "dataset")),
            test_ratio=float(_require(dataset, "test_ratio", "dataset")),
            random_seed=int(_require(dataset, "random_seed", "dataset")),
            min_total_samples=int(_require(dataset, "min_total_samples", "dataset")),
            min_samples_per_class=int(_require(dataset, "min_samples_per_class", "dataset")),
            min_captures_per_split=int(_require(dataset, "min_captures_per_split", "dataset")),
            min_samples_for_metrics=int(_require(dataset, "min_samples_for_metrics", "dataset")),
        ),
        path=resolved,
    )


@lru_cache(maxsize=4)
def _cached_schema(path: str) -> MLFeatureSchema:
    return load_feature_schema(path)


def get_feature_schema() -> MLFeatureSchema:
    """Process-wide cached schema, keyed on the configured path."""
    return _cached_schema(get_settings().ML_FEATURE_SCHEMA_PATH)
