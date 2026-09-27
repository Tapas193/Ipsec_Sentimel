"""IPsec Sentinel deterministic security assessment engine (Phase 3).

The engine is purely rule-based and deterministic. It consumes only the
persisted Phase 2 analysis data (never a raw PCAP) and produces
evidence-backed ``SecurityFinding`` records with explicit severities and
confidences. It performs no decryption, no ML, no arbitrary code execution
and no shell commands.

Import engine parts from their submodules (``app.security.enums``,
``app.security.evidence``, ``app.security.context``, ``app.security.base``,
``app.security.registry``, ``app.security.rules``) so importing this package
never triggers a model/engine import cycle.
"""
