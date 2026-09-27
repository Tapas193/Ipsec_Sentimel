"""widen flows.flow_id so flow keys cannot be truncated

Revision ID: c3e8a4f1b902
Revises: b7f0a1e2034a
Create Date: 2026-09-27 16:10:00.000000

`flows.flow_id` was created as ``VARCHAR(32)``, which is too small for the
flow key rendered by ``app.analyzers.packet_analyzer.flow_builder.flow_key_for``:

    "<src_ip>:<sport>-<protocol>/<ip_version>-><dst_ip>:<dport>"

A flow with 5-digit ports on both sides already exceeds 32 characters
(``10.0.0.1:12345-udp/4->10.0.0.2:8080`` is 35), and the demo fixture's own
IKE flow key is exactly 32. IPv6 keys are far longer still.

Overflowing this column raised ``StringDataRightTruncation`` during the
persistence flush, which aborted the transaction. Because the failure path did
not roll the session back, the FAILED status could not be persisted and the
analysis remained stuck in ``running`` forever. Truncation would also have been
silently harmful in its own right, because ``flow_id`` is the stable identity
used to group flows.

Widening to 255 comfortably covers the longest possible IPv6 key
(45 + 1 + 5 + 1 + protocol + 1 + 1 + 2 + 45 + 1 + 5).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c3e8a4f1b902"
down_revision = "b7f0a1e2034a"
branch_labels = None
depends_on = None

_OLD_LENGTH = 32
_NEW_LENGTH = 255


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "flows",
            "flow_id",
            type_=sa.String(length=_NEW_LENGTH),
            existing_type=sa.String(length=_OLD_LENGTH),
            existing_nullable=False,
        )
    else:
        # SQLite cannot ALTER COLUMN TYPE. The legacy text affinity stores the
        # value without a length limit, so the widening is a no-op there.
        with op.batch_alter_table("flows") as batch_op:
            batch_op.alter_column(
                "flow_id",
                type_=sa.String(length=_NEW_LENGTH),
                existing_type=sa.String(length=_OLD_LENGTH),
                existing_nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "flows",
            "flow_id",
            type_=sa.String(length=_OLD_LENGTH),
            existing_type=sa.String(length=_NEW_LENGTH),
            existing_nullable=False,
        )
    else:
        with op.batch_alter_table("flows") as batch_op:
            batch_op.alter_column(
                "flow_id",
                type_=sa.String(length=_OLD_LENGTH),
                existing_type=sa.String(length=_NEW_LENGTH),
                existing_nullable=False,
            )
