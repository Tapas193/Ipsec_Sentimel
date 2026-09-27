"""phase 3: security assessment schema (finding enums, ids, evidence digest)

Revision ID: b7f0a1e2034a
Revises: 4f9c6d7e2a81
Create Date: 2026-09-23 21:15:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b7f0a1e2034a"
down_revision = "4f9c6d7e2a81"
branch_labels = None
depends_on = None

# New columns added to security_findings.
_FINDING_COLUMNS = (
    ("finding_id", sa.String(length=32)),
    ("rule_version", sa.String(length=32)),
    ("source", sa.String(length=64)),
    ("observed_value", sa.Text()),
    ("expected_value", sa.Text()),
    ("evidence_digest", sa.String(length=64)),
)


def _is_postgres(bind: sa.Connection) -> bool:
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    bind = op.get_bind()
    for name, column in _FINDING_COLUMNS:
        op.add_column("security_findings", sa.Column(name, column, nullable=True))

    if _is_postgres(bind):
        # The table has no rows in any environment this migration applies to
        # (Phase 1 never wrote findings). Cast float -> text -> enum and
        # varchar -> enum directly; text forms of legacy defaults ('1.0',
        # 'open') are unrelated to the new enum member names and no data is
        # lost in practice.
        op.execute("CREATE TYPE finding_confidence AS ENUM ('HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')")
        op.execute(
            "ALTER TABLE security_findings "
            "ALTER COLUMN confidence TYPE finding_confidence "
            "USING confidence::text::finding_confidence"
        )
        op.execute("CREATE TYPE finding_status AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')")
        op.execute(
            "ALTER TABLE security_findings "
            "ALTER COLUMN status TYPE finding_status "
            "USING status::text::finding_status"
        )
    else:
        # SQLite cannot ALTER COLUMN; batch mode recreates the table with the
        # new enum (VARCHAR + CHECK) types.
        with op.batch_alter_table("security_findings") as batch:
            batch.alter_column(
                "confidence",
                type_=sa.Enum("HIGH", "MEDIUM", "LOW", "UNKNOWN", name="finding_confidence"),
                existing_type=sa.Float(),
                existing_nullable=False,
            )
            batch.alter_column(
                "status",
                type_=sa.Enum("OPEN", "ACKNOWLEDGED", "RESOLVED", name="finding_status"),
                existing_type=sa.String(length=32),
                existing_nullable=False,
            )

    op.create_index(
        op.f("ix_security_findings_finding_id"),
        "security_findings",
        ["finding_id"],
        unique=True,
    )
    op.create_index(
        "ix_security_findings_analysis_rule_evidence",
        "security_findings",
        ["analysis_id", "rule_id", "evidence_digest"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_security_findings_analysis_rule_evidence",
        table_name="security_findings",
    )
    op.drop_index(
        op.f("ix_security_findings_finding_id"),
        table_name="security_findings",
    )

    bind = op.get_bind()
    if _is_postgres(bind):
        op.execute(
            "ALTER TABLE security_findings "
            "ALTER COLUMN confidence TYPE double precision "
            "USING CASE confidence::text "
            "WHEN 'HIGH' THEN 1.0 WHEN 'MEDIUM' THEN 0.7 "
            "WHEN 'LOW' THEN 0.4 ELSE 0.0 END"
        )
        op.execute(
            "ALTER TABLE security_findings ALTER COLUMN status TYPE varchar(32) USING status::text"
        )
        sa.Enum(name="finding_confidence").drop(bind, checkfirst=True)
        sa.Enum(name="finding_status").drop(bind, checkfirst=True)
    else:
        with op.batch_alter_table("security_findings") as batch:
            batch.alter_column(
                "confidence",
                type_=sa.Float(),
                existing_type=sa.Enum(
                    "HIGH", "MEDIUM", "LOW", "UNKNOWN", name="finding_confidence"
                ),
                existing_nullable=False,
            )
            batch.alter_column(
                "status",
                type_=sa.String(length=32),
                existing_type=sa.Enum("OPEN", "ACKNOWLEDGED", "RESOLVED", name="finding_status"),
                existing_nullable=False,
            )

    op.drop_column("security_findings", "evidence_digest")
    op.drop_column("security_findings", "expected_value")
    op.drop_column("security_findings", "observed_value")
    op.drop_column("security_findings", "source")
    op.drop_column("security_findings", "rule_version")
    op.drop_column("security_findings", "finding_id")
