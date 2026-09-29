"""Deterministic preprocessing for Phase 4.

The fitted ``ColumnTransformer`` is serialized **inside the model artifact**.
Inference calls ``predict`` on the whole pipeline, so preprocessing can never
drift from training — there is exactly one implementation and it travels with
the model.

Missingness
-----------
Phase 2 writes ``null`` when a statistic is not computable (a single-packet
flow has no interarrival std). That is not the same as ``0.0``:

- The imputer fills a value only so the estimator has a number.
- ``add_missing_indicator=True`` appends one binary column per numeric feature
  recording that the value was absent.

So the model can always tell "measured zero" from "not measurable", which a bare
imputer would destroy.

Categories
----------
Categorical features are one-hot encoded with an explicit ``__UNKNOWN__`` bucket
so an unseen value at inference time cannot raise. Schema 1.0 declares no
categorical feature, but the transformer is built from the schema rather than
hardcoded, so adding one is a config change.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from app.ml.schema import MLFeatureSchema, PreprocessingSpec

PREPROCESSOR_CLASS = "ColumnTransformer"


def build_preprocessor(schema: MLFeatureSchema) -> ColumnTransformer:
    """Construct the unfitted transformer described by the schema."""
    spec: PreprocessingSpec = schema.preprocessing
    transformers: list[tuple[str, Pipeline, list[str]]] = []

    numeric = schema.numeric_features
    if numeric:
        steps: list[tuple[str, Any]] = [
            (
                "imputer",
                SimpleImputer(
                    strategy=spec.imputer_strategy,
                    add_indicator=spec.add_missing_indicator,
                ),
            )
        ]
        if spec.scaler == "standard":
            steps.append(("scaler", StandardScaler()))
        transformers.append(("numeric", Pipeline(steps), numeric))

    categorical = schema.categorical_features
    if categorical:
        transformers.append(
            (
                "categorical",
                Pipeline(
                    [
                        (
                            "imputer",
                            SimpleImputer(strategy=spec.categorical_imputer_strategy),
                        ),
                        (
                            "onehot",
                            OneHotEncoder(
                                handle_unknown="infrequent_if_exist",
                                min_frequency=1,
                                sparse_output=False,
                            ),
                        ),
                    ]
                ),
                categorical,
            )
        )

    if not transformers:
        raise ValueError("schema declares no usable features for preprocessing")

    return ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        # Strict: an unexpected column in a row is a schema error, not noise.
        verbose_feature_names_out=True,
    )


def row_to_vector(
    row: dict[str, float | None],
    schema: MLFeatureSchema,
) -> list[float | None]:
    """Project a validated feature mapping onto the schema's feature order.

    A feature absent from ``row`` becomes ``None`` rather than an error, so a
    partially-populated row is imputed (with its indicator set) instead of
    silently scoring as zero.
    """
    return [row.get(name) for name in schema.feature_names]


def rows_to_frame(
    rows: list[dict[str, float | None]],
    schema: MLFeatureSchema,
) -> pd.DataFrame:
    """Stack rows into a DataFrame with the schema's column names and order.

    A DataFrame (not a bare ndarray) is required because the ``ColumnTransformer``
    selects features *by name*. Passing a numpy array would lose the column
    contract and could silently feed the estimator the wrong feature order.
    """
    frame = pd.DataFrame(
        [{name: _nan_if_none(row.get(name)) for name in schema.feature_names} for row in rows],
        columns=schema.feature_names,
        dtype=float,
    )
    if frame.empty:
        # An empty frame still needs the declared dtypes so sklearn can fit.
        return frame.astype(float)
    return frame


def rows_to_matrix(
    rows: list[dict[str, float | None]],
    schema: MLFeatureSchema,
) -> pd.DataFrame:
    """Stack rows into a schema-ordered DataFrame, keeping ``None`` as NaN.

    Named this ``rows_to_matrix`` because it is the training/inference input
    builder, but it returns a DataFrame so feature names survive into the
    transformer.
    """
    return rows_to_frame(rows, schema)


def _nan_if_none(value: float | None) -> float:
    return float("nan") if value is None else float(value)


def transformed_feature_names(schema: MLFeatureSchema) -> list[str]:
    """Names after imputation/scaling/encoding, computed from a fitted clone.

    Used only for audit output; the artifact is authoritative.
    """
    preprocessor = build_preprocessor(schema)
    preprocessor.fit(_synthetic_probe(schema))
    return [str(name) for name in preprocessor.get_feature_names_out()]


def _synthetic_probe(schema: MLFeatureSchema) -> pd.DataFrame:
    """Minimal valid input so a throwaway preprocessor can be fitted for names."""
    row: dict[str, float | None] = {}
    for spec in schema.features:
        row[spec.name] = 0.0 if spec.nullable else _default_non_null(spec.minimum)
    return rows_to_matrix([row], schema)


def _default_non_null(minimum: float | None) -> float:
    return 0.0 if minimum is None else float(minimum)
