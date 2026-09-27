"""Rule registry: the ordered, versioned set of deterministic rules.

``RULES_VERSION`` is stamped onto assessments and onto every persisted
finding so results remain reproducible across engine releases.
"""

from __future__ import annotations

from app.security.base import Rule
from app.security.enums import CATEGORIES
from app.security.rules import ALL_RULES

RULES_VERSION = "1.0.0"

RULES: tuple[Rule, ...] = tuple(rule_cls() for rule_cls in ALL_RULES)

_RULES_BY_ID: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}


class RegistryError(RuntimeError):
    """Raised when the rule registry is misconfigured."""


def _validate_registry() -> None:
    seen: set[str] = set()
    for rule in RULES:
        if not rule.rule_id.startswith("IPSEC-"):
            raise RegistryError(f"invalid rule id: {rule.rule_id!r}")
        if rule.rule_id in seen:
            raise RegistryError(f"duplicate rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
        if rule.category not in CATEGORIES:
            raise RegistryError(f"rule {rule.rule_id} uses unknown category {rule.category!r}")
        if not rule.title or not rule.description:
            raise RegistryError(f"rule {rule.rule_id} missing title/description")


_validate_registry()


def get_rule(rule_id: str) -> Rule:
    try:
        return _RULES_BY_ID[rule_id]
    except KeyError as exc:
        raise RegistryError(f"unknown rule id: {rule_id!r}") from exc


def rule_ids() -> list[str]:
    return [rule.rule_id for rule in RULES]
