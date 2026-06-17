"""Shared verdict-escalation rules.

The binary fusion pipeline (`pipeline/fusion.py`) and the repository scanner
(`repo_scanner.py`) both decide when a pile of MEDIUM findings should escalate to
MALICIOUS. That rule used to be copy-pasted in both places; this module is the single
source of truth so the two cannot drift apart.
"""
from __future__ import annotations

from collections.abc import Iterable

from .models import Observation

# Category prefixes that describe analytical *uncertainty* (what static analysis could
# not resolve) rather than a concrete attack step. They still count as findings but are
# excluded when measuring how many distinct attack vectors a sample spans -- three
# "unresolved:*" signals are one analytical gap, not a coordinated attack.
NON_ATTACK_PREFIXES = frozenset({"unresolved", "ast", "coverage_gap", "llm"})

# Evasion-tuned malware deliberately avoids any single HIGH signal. This many MEDIUM
# findings spanning this many distinct attack-vector categories is treated as a coherent
# attack chain and escalated to MALICIOUS.
COMPOUND_MEDIUM_MIN_COUNT = 3
COMPOUND_MEDIUM_MIN_VECTORS = 3


def attack_vector_categories(mediums: Iterable[Observation]) -> set[str]:
    """Distinct attack-vector category prefixes among MEDIUM findings.

    The prefix is everything before the first ``:`` in ``category`` (e.g.
    ``obfuscation:base64`` -> ``obfuscation``). Purely-analytical prefixes
    (:data:`NON_ATTACK_PREFIXES`) are removed.
    """
    return {obs.category.split(":", 1)[0] for obs in mediums} - NON_ATTACK_PREFIXES


def is_compound_attack_chain(mediums: Iterable[Observation]) -> bool:
    """True when MEDIUM findings form a coordinated multi-vector attack chain.

    Requires at least :data:`COMPOUND_MEDIUM_MIN_COUNT` MEDIUM findings AND at least
    :data:`COMPOUND_MEDIUM_MIN_VECTORS` distinct attack-vector categories among them.
    """
    mediums = list(mediums)
    if len(mediums) < COMPOUND_MEDIUM_MIN_COUNT:
        return False
    return len(attack_vector_categories(mediums)) >= COMPOUND_MEDIUM_MIN_VECTORS
