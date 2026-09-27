"""phase 2: packet analysis schema (observations, ike, esp, ah, flows, features)

Revision ID: 4f9c6d7e2a81
Revises: 921a9dd10bd6
Create Date: 2026-09-23 20:19:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "4f9c6d7e2a81"
down_revision = "921a9dd10bd6"
branch_labels = None
depends_on = None


def _is_postgres(bind: sa.Connection) -> bool:
    return bind.dialect.name == "postgresql"


def _add_enum_values(enum_name: str, values: list[str]) -> None:
    bind = op.get_bind()
    if not _is_postgres(bind):
        return
    for value in values:
        op.execute(f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS '{value}'")


def _drop_enum_if_exists(enum_name: str) -> None:
    bind = op.get_bind()
    if _is_postgres(bind):
        sa.Enum(name=enum_name).drop(bind, checkfirst=True)


def upgrade() -> None:
    # --- Enum value additions (PostgreSQL only; SQLite uses CHECK constraints) ---
    # SQLAlchemy SAEnum persists enum member NAMES, so new members are added by
    # name matching the StrEnum classes (CaptureStatus, JobStatus, ...).
    _add_enum_values("capture_status", ["VALIDATING", "VALID", "INVALID"])
    _add_enum_values("job_status", ["PARTIAL"])
    _add_enum_values(
        "job_stage",
        [
            "VALIDATION",
            "PACKET_READING",
            "IKE_ANALYSIS",
            "ESP_ANALYSIS",
            "FLOW_BUILDING",
            "PERSISTENCE",
        ],
    )
    _add_enum_values("analysis_status", ["RUNNING"])

    # --- New columns on existing tables -----------------------------------------
    op.add_column("captures", sa.Column("capture_id", sa.String(length=32), nullable=True))
    op.add_column("captures", sa.Column("stored_filename", sa.String(length=512), nullable=True))
    op.add_column("captures", sa.Column("packet_count", sa.Integer(), nullable=True))
    op.add_column("captures", sa.Column("duration", sa.Float(), nullable=True))
    op.add_column(
        "captures", sa.Column("first_packet_time", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "captures", sa.Column("last_packet_time", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("captures", sa.Column("analysis_status", sa.String(length=32), nullable=True))
    op.create_index(op.f("ix_captures_capture_id"), "captures", ["capture_id"], unique=True)

    op.add_column("analyses", sa.Column("analysis_id", sa.String(length=32), nullable=True))
    op.add_column("analyses", sa.Column("protocol_detected", sa.String(length=64), nullable=True))
    op.add_column("analyses", sa.Column("protocol_confidence", sa.String(length=16), nullable=True))
    op.add_column("analyses", sa.Column("ike_detected", sa.Boolean(), nullable=True))
    op.add_column("analyses", sa.Column("ike_confidence", sa.String(length=16), nullable=True))
    op.add_column("analyses", sa.Column("esp_detected", sa.Boolean(), nullable=True))
    op.add_column("analyses", sa.Column("ah_detected", sa.Boolean(), nullable=True))
    op.add_column("analyses", sa.Column("ipv4_detected", sa.Boolean(), nullable=True))
    op.add_column("analyses", sa.Column("ipv6_detected", sa.Boolean(), nullable=True))
    op.add_column("analyses", sa.Column("byte_count", sa.BigInteger(), nullable=True))
    op.add_column("analyses", sa.Column("duration", sa.Float(), nullable=True))
    op.add_column("analyses", sa.Column("error_message", sa.Text(), nullable=True))
    op.add_column("analyses", sa.Column("parser_version", sa.String(length=32), nullable=True))
    op.create_index(op.f("ix_analyses_analysis_id"), "analyses", ["analysis_id"], unique=True)

    op.add_column("analysis_jobs", sa.Column("job_id", sa.String(length=32), nullable=True))
    op.add_column("analysis_jobs", sa.Column("stage_message", sa.String(length=256), nullable=True))
    op.create_index(op.f("ix_analysis_jobs_job_id"), "analysis_jobs", ["job_id"], unique=True)

    # --- New detail tables ------------------------------------------------------
    op.create_table(
        "protocol_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("evidence_json", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_protocol_observations_analysis_id"),
        "protocol_observations",
        ["analysis_id"],
        unique=False,
    )

    op.create_table(
        "ike_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("packet_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("destination_ip", sa.String(length=64), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False),
        sa.Column("exchange_type", sa.Integer(), nullable=False),
        sa.Column("exchange_name", sa.String(length=64), nullable=False),
        sa.Column("flags", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.String(length=16), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("next_payload", sa.Integer(), nullable=False),
        sa.Column("payload_types_json", sa.Text(), nullable=True),
        sa.Column("initiator_spi", sa.String(length=32), nullable=False),
        sa.Column("responder_spi", sa.String(length=32), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ike_messages_analysis_id"), "ike_messages", ["analysis_id"], unique=False
    )

    op.create_table(
        "ike_proposals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("ike_message_id", sa.String(length=36), nullable=True),
        sa.Column("proposal_number", sa.Integer(), nullable=True),
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        sa.Column("protocol_name", sa.String(length=32), nullable=False),
        sa.Column("encryption", sa.String(length=64), nullable=False),
        sa.Column("encryption_id", sa.Integer(), nullable=True),
        sa.Column("key_length", sa.Integer(), nullable=True),
        sa.Column("integrity", sa.String(length=64), nullable=False),
        sa.Column("integrity_id", sa.Integer(), nullable=True),
        sa.Column("prf", sa.String(length=64), nullable=False),
        sa.Column("prf_id", sa.Integer(), nullable=True),
        sa.Column("dh_group", sa.Integer(), nullable=True),
        sa.Column("esn", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("transform_confidence", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["ike_message_id"], ["ike_messages.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ike_proposals_analysis_id"), "ike_proposals", ["analysis_id"], unique=False
    )
    op.create_index(
        op.f("ix_ike_proposals_ike_message_id"), "ike_proposals", ["ike_message_id"], unique=False
    )

    op.create_table(
        "esp_packets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("packet_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("destination_ip", sa.String(length=64), nullable=False),
        sa.Column("spi", sa.String(length=16), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("encryption_algorithm", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_esp_packets_analysis_id"), "esp_packets", ["analysis_id"], unique=False
    )
    op.create_index(op.f("ix_esp_packets_spi"), "esp_packets", ["spi"], unique=False)

    op.create_table(
        "ah_packets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("packet_id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("destination_ip", sa.String(length=64), nullable=False),
        sa.Column("spi", sa.String(length=16), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("next_header", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ah_packets_analysis_id"), "ah_packets", ["analysis_id"], unique=False)
    op.create_index(op.f("ix_ah_packets_spi"), "ah_packets", ["spi"], unique=False)

    op.create_table(
        "flows",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("destination_ip", sa.String(length=64), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("transport", sa.String(length=16), nullable=True),
        sa.Column("ip_version", sa.Integer(), nullable=True),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration", sa.Float(), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("upstream_packets", sa.Integer(), nullable=False),
        sa.Column("downstream_packets", sa.Integer(), nullable=False),
        sa.Column("upstream_bytes", sa.BigInteger(), nullable=False),
        sa.Column("downstream_bytes", sa.BigInteger(), nullable=False),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("spi", sa.String(length=16), nullable=True),
        sa.Column("ike_packets", sa.Integer(), nullable=False),
        sa.Column("esp_packets", sa.Integer(), nullable=False),
        sa.Column("ah_packets", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_flows_analysis_id"), "flows", ["analysis_id"], unique=False)

    op.create_table(
        "flow_features",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("analysis_id", sa.String(length=36), nullable=False),
        sa.Column("flow_id", sa.String(length=36), nullable=False),
        sa.Column("feature_schema_version", sa.String(length=16), nullable=False),
        sa.Column("feature_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["flow_id"], ["flows.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_flow_features_analysis_id"), "flow_features", ["analysis_id"], unique=False
    )
    op.create_index(op.f("ix_flow_features_flow_id"), "flow_features", ["flow_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_flow_features_flow_id"), table_name="flow_features")
    op.drop_index(op.f("ix_flow_features_analysis_id"), table_name="flow_features")
    op.drop_table("flow_features")
    op.drop_index(op.f("ix_flows_analysis_id"), table_name="flows")
    op.drop_table("flows")
    op.drop_index(op.f("ix_ah_packets_spi"), table_name="ah_packets")
    op.drop_index(op.f("ix_ah_packets_analysis_id"), table_name="ah_packets")
    op.drop_table("ah_packets")
    op.drop_index(op.f("ix_esp_packets_spi"), table_name="esp_packets")
    op.drop_index(op.f("ix_esp_packets_analysis_id"), table_name="esp_packets")
    op.drop_table("esp_packets")
    op.drop_index(op.f("ix_ike_proposals_ike_message_id"), table_name="ike_proposals")
    op.drop_index(op.f("ix_ike_proposals_analysis_id"), table_name="ike_proposals")
    op.drop_table("ike_proposals")
    op.drop_index(op.f("ix_ike_messages_analysis_id"), table_name="ike_messages")
    op.drop_table("ike_messages")
    op.drop_index(op.f("ix_protocol_observations_analysis_id"), table_name="protocol_observations")
    op.drop_table("protocol_observations")

    op.drop_index(op.f("ix_analysis_jobs_job_id"), table_name="analysis_jobs")
    op.drop_column("analysis_jobs", "stage_message")
    op.drop_column("analysis_jobs", "job_id")

    op.drop_index(op.f("ix_analyses_analysis_id"), table_name="analyses")
    op.drop_column("analyses", "parser_version")
    op.drop_column("analyses", "error_message")
    op.drop_column("analyses", "duration")
    op.drop_column("analyses", "byte_count")
    op.drop_column("analyses", "ipv6_detected")
    op.drop_column("analyses", "ipv4_detected")
    op.drop_column("analyses", "ah_detected")
    op.drop_column("analyses", "esp_detected")
    op.drop_column("analyses", "ike_confidence")
    op.drop_column("analyses", "ike_detected")
    op.drop_column("analyses", "protocol_confidence")
    op.drop_column("analyses", "protocol_detected")
    op.drop_column("analyses", "analysis_id")

    op.drop_index(op.f("ix_captures_capture_id"), table_name="captures")
    op.drop_column("captures", "analysis_status")
    op.drop_column("captures", "last_packet_time")
    op.drop_column("captures", "first_packet_time")
    op.drop_column("captures", "duration")
    op.drop_column("captures", "packet_count")
    op.drop_column("captures", "stored_filename")
    op.drop_column("captures", "capture_id")
