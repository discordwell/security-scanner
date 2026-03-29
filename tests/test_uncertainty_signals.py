"""Tests for uncertainty signal detection."""
from __future__ import annotations

from security_scanner.models import FileClassification, Observation, ObservationSeverity
from security_scanner.semantic_fingerprint import SemanticFingerprint, compute_fingerprint
from security_scanner.source_analysis import detect_uncertainty_signals


def _fp(**kwargs) -> SemanticFingerprint:
    return SemanticFingerprint(**kwargs)


def test_exec_of_variable_triggers_signal():
    content = "data = get_payload()\nexec(data)\n"
    fp = compute_fingerprint(content, "loader.py")
    obs = detect_uncertainty_signals(content, "loader.py", [], fp)
    assert any(o.category == "unresolved:exec_of_unknown" for o in obs)


def test_exec_of_literal_no_signal():
    content = 'exec("print(1)")\n'
    fp = compute_fingerprint(content, "util.py")
    obs = detect_uncertainty_signals(content, "util.py", [], fp)
    assert not any(o.category == "unresolved:exec_of_unknown" for o in obs)


def test_path_construction_unresolved():
    """Home dir access + file open but behavioral detector didn't match → signal."""
    content = '''
import os
home = os.path.expanduser("~")
path = os.path.join(home, folder, name)
with open(path) as f:
    data = f.read()
'''
    fp = _fp(reads_home_dir=True, uses_open=True)
    # No behavioral observations (paths are via variables)
    obs = detect_uncertainty_signals(content, "reader.py", [], fp)
    assert any(o.category == "unresolved:path_construction" for o in obs)


def test_path_construction_already_caught_no_duplicate():
    """If behavioral detector already caught it, no uncertainty signal needed."""
    content = 'open(os.path.expanduser("~/.ssh/id_rsa"))\n'
    fp = _fp(reads_home_dir=True, uses_open=True)
    existing = [Observation(
        source="test", category="behavioral:credential_access_exfil",
        severity=ObservationSeverity.MEDIUM, message="test",
    )]
    obs = detect_uncertainty_signals(content, "reader.py", existing, fp)
    assert not any(o.category == "unresolved:path_construction" for o in obs)


def test_capability_cocktail():
    """Network + file_io + encoding capabilities but no compound finding → signal."""
    fp = _fp(
        imports_network=["urllib.request"],
        imports_encoding=["json", "base64"],
        makes_network_calls=True,
        uses_open=True,
        accesses_env_home=True,
        reads_home_dir=True,
    )
    obs = detect_uncertainty_signals("", "module.py", [], fp)
    assert any(o.category == "unresolved:capability_cocktail" for o in obs)


def test_capability_cocktail_not_enough_caps():
    """Only 2 capabilities → no cocktail signal."""
    fp = _fp(imports_network=["urllib.request"], makes_network_calls=True)
    obs = detect_uncertainty_signals("", "module.py", [], fp)
    assert not any(o.category == "unresolved:capability_cocktail" for o in obs)


def test_atexit_complex_handler():
    """atexit with file I/O + network → signal."""
    fp = _fp(registers_atexit=True, uses_open=True, makes_network_calls=True)
    obs = detect_uncertainty_signals("", "telemetry.py", [], fp)
    assert any(o.category == "unresolved:callback_with_side_effects" for o in obs)


def test_atexit_simple_no_signal():
    """atexit that just does simple cleanup → no signal."""
    fp = _fp(registers_atexit=True, uses_open=False, makes_network_calls=False)
    obs = detect_uncertainty_signals("", "cleanup.py", [], fp)
    assert not any(o.category == "unresolved:callback_with_side_effects" for o in obs)


def test_del_with_network():
    """__del__ method with network calls → signal."""
    fp = _fp(has_del_method=True, makes_network_calls=True)
    obs = detect_uncertainty_signals("", "buffer.py", [], fp)
    assert any(o.category == "unresolved:callback_with_side_effects" for o in obs)


def test_clean_file_no_signals():
    content = "def add(a, b):\n    return a + b\n"
    fp = compute_fingerprint(content, "math.py")
    obs = detect_uncertainty_signals(content, "math.py", [], fp)
    assert obs == []


def test_sqlalchemy_telemetry_signals():
    """The poisoned _pool_telemetry.py should trigger multiple signals."""
    fp = _fp(
        imports_network=["urllib.request"],
        imports_encoding=["json"],
        imports_os=["os", "atexit"],
        registers_atexit=True,
        uses_open=True,
        makes_network_calls=True,
        reads_home_dir=True,
        accesses_env_home=True,
    )
    obs = detect_uncertainty_signals("", "_pool_telemetry.py", [], fp)
    categories = {o.category for o in obs}
    # Should have callback + capability cocktail at minimum
    assert "unresolved:callback_with_side_effects" in categories
    assert "unresolved:capability_cocktail" in categories
