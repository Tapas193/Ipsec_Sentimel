"""Deterministic security rule implementations.

Each rule is a stateless class that is instantiated by the registry. Rule IDs
follow the ``IPSEC-<MODULE>-<NNN>`` convention and are stable identifiers used
as the ``rule_id`` on persisted findings.
"""

from __future__ import annotations

from app.security.rules.crypto import UnknownEncryptionRule, WeakEncryptionRule
from app.security.rules.esp import CompositeEspAhRule, ReplayAnomalyRule
from app.security.rules.ike import ConflictingSaParametersRule, IncompleteIkeNegotiationRule
from app.security.rules.kex import PfsNotObservedRule, WeakDhGroupRule
from app.security.rules.meta import IkeInitiationFrequencyRule, PlaintextAlongsideIpsecRule

ALL_RULES: list[type] = [
    UnknownEncryptionRule,
    WeakEncryptionRule,
    WeakDhGroupRule,
    PfsNotObservedRule,
    IncompleteIkeNegotiationRule,
    ConflictingSaParametersRule,
    ReplayAnomalyRule,
    CompositeEspAhRule,
    PlaintextAlongsideIpsecRule,
    IkeInitiationFrequencyRule,
]

__all__ = ["ALL_RULES"]
