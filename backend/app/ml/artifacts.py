"""Versioned model artifacts for Phase 4.

Layout, one directory per model version::

    $ML_MODEL_DIR/
        traffic-classifier-0.1.0/
            model.joblib        # fitted sklearn Pipeline (preprocessor included)
            metadata.json       # reproduction + provenance record
            evaluation.json     # metrics, confusion matrix, class distribution

Storage strategy
----------------
Artifacts are **build outputs, not source**. They are written under
``ML_MODEL_DIR`` (default ``backend/data/models``) and gitignored. What is
tracked in git is the registry layout contract, the feature schema, and the
code that produces them — so a model is reproduced by re-running the trainer,
not by checking in a binary. ``metadata.json`` records the Python/sklearn
versions, seed, dataset version and dataset digest needed to verify that.

Trust boundary
--------------
``joblib.load`` deserializes with pickle, so loading a model file executes code.
The controls here are:

1. Only paths inside the configured ``ML_MODEL_DIR`` are ever opened.
2. A model version must match ``MODEL_VERSION_PATTERN`` (letters, digits, dot,
   dash, underscore) — no separators, no ``..``, no absolute paths.
3. The resolved path is re-checked for containment after symlink resolution.
4. Artifacts are never supplied by API input. The API accepts a version string,
   never a path, and ``resolve_model_dir`` refuses anything unresolvable.

A model file placed in the trusted directory by an operator is trusted by
definition — that is the documented residual risk (see docs/ml-security.md).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from joblib import dump, load

from app.ml.schema import MLFeatureSchema

MODEL_FILE = "model.joblib"
METADATA_FILE = "metadata.json"
EVALUATION_FILE = "evaluation.json"

MODEL_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ModelArtifactError(RuntimeError):
    """Raised for an invalid model version or unusable artifact directory."""


@dataclass(frozen=True)
class ModelMetadata:
    model_version: str
    model_type: str
    dataset_version: str
    feature_schema_version: str
    class_definition_version: str
    analyzer_version: str | None
    parser_version: str | None
    preprocessing_version: str
    training_timestamp: str
    random_seed: int
    classes: list[str]
    feature_names: list[str]
    dataset_digest: str
    label_source: str
    training_data_counts: dict[str, int]
    environment: dict[str, str]
    artifact_sha256: str
    ml_library_versions: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "model_type": self.model_type,
            "dataset_version": self.dataset_version,
            "feature_schema_version": self.feature_schema_version,
            "class_definition_version": self.class_definition_version,
            "analyzer_version": self.analyzer_version,
            "parser_version": self.parser_version,
            "preprocessing_version": self.preprocessing_version,
            "training_timestamp": self.training_timestamp,
            "random_seed": self.random_seed,
            "classes": self.classes,
            "feature_names": self.feature_names,
            "feature_count": len(self.feature_names),
            "dataset_digest": self.dataset_digest,
            "label_source": self.label_source,
            "training_data_counts": self.training_data_counts,
            "environment": self.environment,
            "artifact_sha256": self.artifact_sha256,
            "ml_library_versions": self.ml_library_versions,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ModelMetadata:
        return cls(
            model_version=str(payload["model_version"]),
            model_type=str(payload["model_type"]),
            dataset_version=str(payload["dataset_version"]),
            feature_schema_version=str(payload["feature_schema_version"]),
            class_definition_version=str(payload.get("class_definition_version", "1.0")),
            analyzer_version=_opt_str(payload.get("analyzer_version")),
            parser_version=_opt_str(payload.get("parser_version")),
            preprocessing_version=str(payload.get("preprocessing_version", "1.0")),
            training_timestamp=str(payload["training_timestamp"]),
            random_seed=int(payload["random_seed"]),
            classes=[str(c) for c in payload["classes"]],
            feature_names=[str(f) for f in payload["feature_names"]],
            dataset_digest=str(payload.get("dataset_digest", "")),
            label_source=str(payload.get("label_source", "user_provided")),
            training_data_counts=dict(payload.get("training_data_counts", {})),
            environment=dict(payload.get("environment", {})),
            artifact_sha256=str(payload.get("artifact_sha256", "")),
            ml_library_versions=dict(payload.get("ml_library_versions", {})),
        )


@dataclass(frozen=True)
class ModelArtifact:
    model_version: str
    directory: Path
    metadata: ModelMetadata
    evaluation: dict[str, Any] | None

    def load_pipeline(self) -> Any:
        return load_artifact(self.directory)


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)


def validate_model_version(model_version: str) -> str:
    """Reject anything that is not a plain version token.

    This is the primary path-traversal control: no ``/``, no ``..``, no
    absolute paths, no NUL, bounded length.
    """
    if not isinstance(model_version, str) or not model_version.strip():
        raise ModelArtifactError("model_version must be a non-empty string")
    candidate = model_version.strip()
    if candidate != model_version:
        raise ModelArtifactError("model_version must not contain surrounding whitespace")
    if not MODEL_VERSION_PATTERN.match(candidate):
        raise ModelArtifactError(
            f"invalid model_version {model_version!r}: expected letters, digits, '.', '-' or '_'"
        )
    if ".." in candidate:
        raise ModelArtifactError("model_version must not contain '..'")
    return candidate


def model_root(model_dir: str | Path) -> Path:
    root = Path(model_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_model_dir(model_dir: str | Path, model_version: str) -> Path:
    """Return the artifact directory, asserting it stays inside the root."""
    version = validate_model_version(model_version)
    root = model_root(model_dir)
    candidate = (root / version).resolve()
    if not candidate.is_relative_to(root):
        raise ModelArtifactError(f"model directory escapes the model root: {model_version!r}")
    return candidate


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_artifact(
    *,
    model_dir: str | Path,
    metadata: ModelMetadata,
    pipeline: Any,
    evaluation: dict[str, Any] | None = None,
) -> ModelArtifact:
    """Write model.joblib + metadata.json (+ evaluation.json) atomically-ish.

    The binary is written first to a temp name and renamed, so a crash mid-write
    cannot leave a half-written artifact that later looks loadable.
    """
    directory = resolve_model_dir(model_dir, metadata.model_version)
    directory.mkdir(parents=True, exist_ok=True)

    model_path = directory / MODEL_FILE
    temp_path = directory / f".{MODEL_FILE}.tmp"
    dump(pipeline, temp_path)
    temp_path.replace(model_path)

    # The digest can only be computed once the binary exists on disk.
    metadata = replace(metadata, artifact_sha256=sha256_of_file(model_path))

    (directory / METADATA_FILE).write_text(
        json.dumps(metadata.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    evaluation_payload = evaluation
    if evaluation_payload is not None:
        (directory / EVALUATION_FILE).write_text(
            json.dumps(evaluation_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return ModelArtifact(
        model_version=metadata.model_version,
        directory=directory,
        metadata=metadata,
        evaluation=evaluation_payload,
    )


def load_artifact(directory: Path) -> Any:
    """Unpickle a pipeline from a directory already proven to be inside the root."""
    model_path = directory / MODEL_FILE
    if not model_path.is_file():
        raise ModelArtifactError(f"model artifact missing: {model_path.name}")
    return load(model_path)


def read_metadata(directory: Path) -> ModelMetadata:
    metadata_path = directory / METADATA_FILE
    if not metadata_path.is_file():
        raise ModelArtifactError(f"model metadata missing: {metadata_path.name}")
    return ModelMetadata.from_dict(json.loads(metadata_path.read_text(encoding="utf-8")))


def read_evaluation(directory: Path) -> dict[str, Any] | None:
    evaluation_path = directory / EVALUATION_FILE
    if not evaluation_path.is_file():
        return None
    payload = json.loads(evaluation_path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def list_model_versions(model_dir: str | Path) -> list[str]:
    root = model_root(model_dir)
    versions: list[str] = []
    for child in root.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        if MODEL_VERSION_PATTERN.match(child.name) and (child / METADATA_FILE).is_file():
            versions.append(child.name)
    return sorted(versions)


def list_artifacts(model_dir: str | Path) -> list[ModelArtifact]:
    root = model_root(model_dir)
    artifacts: list[ModelArtifact] = []
    for version in list_model_versions(model_dir):
        directory = root / version
        artifacts.append(
            ModelArtifact(
                model_version=version,
                directory=directory,
                metadata=read_metadata(directory),
                evaluation=read_evaluation(directory),
            )
        )
    return artifacts


def resolve_default_version(
    model_dir: str | Path,
    *,
    requested: str,
    schema: MLFeatureSchema,
) -> str | None:
    """Pick the model to use: explicit request first, else newest compatible.

    "Newest" is by training timestamp, tie-broken by version string, so the
    choice is deterministic and does not depend on filesystem order.
    """
    if requested:
        return validate_model_version(requested)

    compatible = [
        artifact
        for artifact in list_artifacts(model_dir)
        if artifact.metadata.feature_schema_version == schema.feature_schema_version
    ]
    if not compatible:
        return None
    compatible.sort(key=lambda a: (a.metadata.training_timestamp, a.model_version))
    return compatible[-1].model_version


def environment_fingerprint() -> dict[str, str]:
    """Versions needed to decide whether a model is reproducible here."""
    import platform

    import numpy
    import sklearn

    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "scikit_learn": sklearn.__version__,
        "numpy": numpy.__version__,
    }


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()
