"""phase 4: ML traffic prediction persistence (traffic_predictions)

Revision ID: d5a1b8f3c204
Revises: c3e8a4f1b902
Create Date: 2026-09-29 18:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d5a1b8f3c204"
down_revision = "c3e8a4f1b902"
branch_labels = None
depends_on = None

# Mirrors app.security.enums.ObservationStatus. Only the values are duplicated
# here (Alembic migrations must not import app code, which can drift after the
# fact); the enum is created exactly once by upgrade() and reused by the
# column. This is the first place ObservationStatus reaches the database
# schema — Phase 3 carried it inside the findings.evidence_json payload, not
# as a column type.
_OBSERVATION_STATUS_VALUES = (
    "observed",
    "inferred",
    "model_predicted",
    "not_observable",
    "user_provided",
    "unknown",
)


def _is_postgres(bind: sa.Connection) -> bool:
    return bind.dialect.name == "postgresql"


def _observation_status_type() -> sa.types.TypeEngine[object]:
    """The column type for ``observation_status``.

    On PostgreSQL the enum type is created explicitly by :func:`upgrade`, so the
    column type must be built with ``create_type=False``. Leaving the default
    (``create_type=True``) makes SQLAlchemy emit its own ``CREATE TYPE`` inside
    ``create_table``, which then collides with the explicit one and aborts the
    migration with ``type "observation_status" already exists``.

    That failure is invisible on SQLite, which renders every ``Enum`` as
    ``VARCHAR`` and never creates a type at all — so the column is a plain
    string there and the round-trip passes locally while a real PostgreSQL
    deployment cannot upgrade.
    """
    if _is_postgres(op.get_bind()):
        return postgresql.ENUM(
            *_OBSERVATION_STATUS_VALUES,
            name="observation_status",
            create_type=False,
        )
    return sa.String(length=32)


def upgrade() -> None:
    bind = op.get_bind()

    if _is_postgres(bind):
        op.execute(
            "CREATE TYPE observation_status AS ENUM "
            f"({', '.join(repr(value) for value in _OBSERVATION_STATUS_VALUES)})"
        )

    op.create_table(
        "traffic_predictions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("prediction_id", sa.String(length=32), nullable=True),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=36), nullable=False),
        sa.Column("capture_id", sa.String(length=32), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("model_type", sa.String(length=128), nullable=True),
        sa.Column("dataset_version", sa.String(length=32), nullable=True),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("prediction", sa.String(length=32), nullable=False),
        sa.Column("top_candidate", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("min_confidence_threshold", sa.Float(), nullable=True),
        sa.Column("abstained", sa.Boolean(), nullable=False),
        sa.Column("probabilities_json", sa.Text(), nullable=True),
        sa.Column("observation_status", _observation_status_type(), nullable=False),
        sa.Column("pipeline_position", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analyses.id"],
            name="fk_traffic_predictions_analysis_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["flows.id"],
            name="fk_traffic_predictions_flow_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_traffic_predictions_prediction_id",
        "traffic_predictions",
        ["prediction_id"],
        unique=True,
    )
    op.create_index(
        "ix_traffic_predictions_analysis_id",
        "traffic_predictions",
        ["analysis_id"],
        unique=False,
    )
    op.create_index(
        "ix_traffic_predictions_flow_id",
        "traffic_predictions",
        ["flow_id"],
        unique=False,
    )
    op.create_index(
        "ix_traffic_predictions_capture_id",
        "traffic_predictions",
        ["capture_id"],
        unique=False,
    )
    op.create_index(
        "ix_traffic_predictions_model_version",
        "traffic_predictions",
        ["model_version"],
        unique=False,
    )
    op.create_index(
        "ix_traffic_predictions_prediction",
        "traffic_predictions",
        ["prediction"],
        unique=False,
    )
    op.create_index(
        "ix_traffic_predictions_confidence",
        "traffic_predictions",
        ["confidence"],
        unique=False,
    )
    op.create_index(
        "ix_traffic_predictions_observation_status",
        "traffic_predictions",
        ["observation_status"],
        unique=False,
    )
    # Idempotency: one prediction per (flow, model_version). Re-running
    # inference for the same model version updates rather than appends.
    op.create_index(
        "ix_traffic_predictions_flow_model",
        "traffic_predictions",
        ["flow_id", "model_version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_traffic_predictions_flow_model",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_observation_status",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_confidence",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_prediction",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_model_version",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_capture_id",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_flow_id",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_analysis_id",
        table_name="traffic_predictions",
    )
    op.drop_index(
        "ix_traffic_predictions_prediction_id",
        table_name="traffic_predictions",
    )
    op.drop_table("traffic_predictions")

    bind = op.get_bind()
    if _is_postgres(bind):
        sa.Enum(name="observation_status").drop(bind, checkfirst=True)
