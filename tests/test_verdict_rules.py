from __future__ import annotations

from security_scanner.models import Observation, ObservationSeverity
from security_scanner.verdict_rules import (
    COMPOUND_MEDIUM_MIN_COUNT,
    COMPOUND_MEDIUM_MIN_VECTORS,
    attack_vector_categories,
    is_compound_attack_chain,
)


def _med(category: str) -> Observation:
    return Observation(
        source="test",
        category=category,
        severity=ObservationSeverity.MEDIUM,
        message=category,
    )


def test_attack_vector_categories_uses_prefix_before_colon():
    obs = [_med("obfuscation:base64"), _med("obfuscation:xor"), _med("network:c2")]
    # Two findings share the 'obfuscation' prefix -> two distinct vectors total.
    assert attack_vector_categories(obs) == {"obfuscation", "network"}


def test_attack_vector_categories_excludes_analytical_prefixes():
    obs = [
        _med("unresolved:exec_of_unknown"),
        _med("ast:resolved_obfuscation"),
        _med("coverage_gap:functions"),
        _med("llm:verdict"),
        _med("obfuscation:base64"),
    ]
    # Only the genuine attack vector survives; analytical prefixes are dropped.
    assert attack_vector_categories(obs) == {"obfuscation"}


def test_compound_chain_requires_enough_findings_and_vectors():
    three_vectors = [_med("obfuscation:x"), _med("network:y"), _med("secret:z")]
    assert is_compound_attack_chain(three_vectors) is True


def test_compound_chain_false_when_too_few_vectors():
    # Three MEDIUMs but only two distinct attack vectors -> not a chain.
    same_vector = [_med("obfuscation:a"), _med("obfuscation:b"), _med("network:c")]
    assert is_compound_attack_chain(same_vector) is False


def test_compound_chain_false_when_only_analytical_signals():
    # Three MEDIUMs that are all analytical uncertainty -> zero attack vectors.
    analytical = [
        _med("unresolved:exec_of_unknown"),
        _med("unresolved:path_construction"),
        _med("ast:resolved_obfuscation"),
    ]
    assert is_compound_attack_chain(analytical) is False


def test_compound_chain_false_below_min_count():
    too_few = [_med("obfuscation:x"), _med("network:y")]
    assert is_compound_attack_chain(too_few) is False


def test_thresholds_are_consistent():
    # Guards against the constants drifting out of sync with the docstring contract.
    assert COMPOUND_MEDIUM_MIN_COUNT >= COMPOUND_MEDIUM_MIN_VECTORS >= 1
