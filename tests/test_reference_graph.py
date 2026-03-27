"""Tests for cross-file reference graph and split-payload detection."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_scanner.models import (
    FileClassification,
    Observation,
    ObservationSeverity,
    RepoFileRecord,
)
from security_scanner.reference_graph import (
    CrossFileLead,
    build_reference_graph,
    graph_to_observations,
)


def _file(path, classification=FileClassification.SOURCE, observations=None):
    return RepoFileRecord(
        path=path,
        classification=classification,
        size=100,
        sha256="abc",
        observations=observations or [],
    )


def _obs(category, severity=ObservationSeverity.MEDIUM):
    return Observation(source="test", category=category, severity=severity, message="test")


# -- Entry point / manifest / build file detection --

def test_detects_entry_points(tmp_path):
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()")
    (tmp_path / "main.py").write_text("print('hi')")
    (tmp_path / "util.py").write_text("def add(a,b): return a+b")
    files = [_file("setup.py"), _file("main.py"), _file("util.py")]
    graph = build_reference_graph(files, tmp_path)
    assert "setup.py" in graph.entry_points
    assert "main.py" in graph.entry_points
    assert "util.py" not in graph.entry_points


def test_detects_manifests(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "requirements.txt").write_text("flask")
    files = [
        _file("package.json", FileClassification.CONFIG),
        _file("requirements.txt", FileClassification.CONFIG),
    ]
    graph = build_reference_graph(files, tmp_path)
    assert "package.json" in graph.manifests
    assert "requirements.txt" in graph.manifests


def test_detects_build_files(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12")
    (tmp_path / "Makefile").write_text("build:\n\techo hi")
    files = [
        _file("Dockerfile", FileClassification.CONFIG),
        _file("Makefile", FileClassification.SCRIPT),
    ]
    graph = build_reference_graph(files, tmp_path)
    assert "Dockerfile" in graph.build_files
    assert "Makefile" in graph.build_files


# -- Python import parsing --

def test_python_import_detection(tmp_path):
    (tmp_path / "loader.py").write_text("import data\nfrom data import PAYLOAD\n")
    (tmp_path / "data.py").write_text("PAYLOAD = 'hello'\n")
    files = [_file("loader.py"), _file("data.py")]
    graph = build_reference_graph(files, tmp_path)
    targets = [r.target_path for r in graph.references]
    assert "data.py" in targets


def test_python_open_detection(tmp_path):
    (tmp_path / "loader.py").write_text("data = open('config.json').read()\n")
    (tmp_path / "config.json").write_text("{}")
    files = [_file("loader.py"), _file("config.json", FileClassification.CONFIG)]
    graph = build_reference_graph(files, tmp_path)
    targets = [r.target_path for r in graph.references]
    assert "config.json" in targets


def test_python_exec_open_detection(tmp_path):
    (tmp_path / "runner.py").write_text("exec(open('payload.py').read())\n")
    (tmp_path / "payload.py").write_text("print('pwned')\n")
    files = [_file("runner.py"), _file("payload.py")]
    graph = build_reference_graph(files, tmp_path)
    exec_refs = [r for r in graph.references if r.ref_type == "exec_open"]
    assert len(exec_refs) >= 1


# -- JavaScript import parsing --

def test_js_require_detection(tmp_path):
    (tmp_path / "index.js").write_text("const data = require('./data');\n")
    (tmp_path / "data.js").write_text("module.exports = 'hello';\n")
    files = [_file("index.js"), _file("data.js")]
    graph = build_reference_graph(files, tmp_path)
    targets = [r.target_path for r in graph.references]
    assert "data.js" in targets


def test_js_esmodule_import(tmp_path):
    (tmp_path / "app.ts").write_text("import { thing } from './util';\n")
    (tmp_path / "util.ts").write_text("export const thing = 1;\n")
    files = [_file("app.ts"), _file("util.ts")]
    graph = build_reference_graph(files, tmp_path)
    targets = [r.target_path for r in graph.references]
    assert "util.ts" in targets


# -- Cross-file lead detection --

def test_cross_file_lead_data_to_exec(tmp_path):
    """File A has encoded data, File B imports A and has exec."""
    (tmp_path / "data.py").write_text("PAYLOAD = 'aGVsbG8='\n")
    (tmp_path / "loader.py").write_text("from data import PAYLOAD\nimport base64\nexec(base64.b64decode(PAYLOAD))\n")
    files = [
        _file("data.py", observations=[_obs("obfuscation:base64")]),
        _file("loader.py", observations=[_obs("obfuscation:eval_exec")]),
    ]
    graph = build_reference_graph(files, tmp_path)
    assert len(graph.leads) >= 1
    lead = graph.leads[0]
    assert lead.data_file == "data.py"
    assert lead.exec_file == "loader.py"
    assert lead.severity == ObservationSeverity.HIGH


def test_no_leads_for_clean_files(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    (tmp_path / "util.py").write_text("def add(a,b): return a+b\n")
    files = [_file("main.py"), _file("util.py")]
    graph = build_reference_graph(files, tmp_path)
    assert graph.leads == []


def test_no_self_leads(tmp_path):
    """A file with both data AND exec shouldn't lead to itself."""
    (tmp_path / "evil.py").write_text("exec(base64.b64decode('aGVsbG8='))\n")
    files = [
        _file("evil.py", observations=[_obs("obfuscation:base64"), _obs("obfuscation:eval_exec")]),
    ]
    graph = build_reference_graph(files, tmp_path)
    assert graph.leads == []


def test_transitive_lead(tmp_path):
    """A -> B -> C where A has data, C has exec."""
    (tmp_path / "data.py").write_text("BLOB = 'encoded'\n")
    (tmp_path / "middle.py").write_text("from data import BLOB\ndef get(): return BLOB\n")
    (tmp_path / "runner.py").write_text("from middle import get\nexec(get())\n")
    files = [
        _file("data.py", observations=[_obs("obfuscation:base64")]),
        _file("middle.py"),
        _file("runner.py", observations=[_obs("obfuscation:eval_exec")]),
    ]
    graph = build_reference_graph(files, tmp_path)
    assert len(graph.leads) >= 1
    lead = graph.leads[0]
    assert "transitive" in lead.connection or "reverse" in lead.connection


def test_reverse_reference_lead(tmp_path):
    """Exec file imports data file (exec -> data direction)."""
    (tmp_path / "config.json").write_text('{"code": "aGVsbG8="}')
    (tmp_path / "loader.py").write_text("import json\ndata = json.load(open('config.json'))\nexec(data['code'])\n")
    files = [
        _file("config.json", FileClassification.CONFIG, observations=[_obs("payload:long_string")]),
        _file("loader.py", observations=[_obs("obfuscation:eval_exec")]),
    ]
    graph = build_reference_graph(files, tmp_path)
    assert len(graph.leads) >= 1


# -- Observation generation --

def test_graph_to_observations(tmp_path):
    (tmp_path / "a.py").write_text("X = 'blob'\n")
    (tmp_path / "b.py").write_text("from a import X\nexec(X)\n")
    files = [
        _file("a.py", observations=[_obs("obfuscation:base64")]),
        _file("b.py", observations=[_obs("obfuscation:eval_exec")]),
    ]
    graph = build_reference_graph(files, tmp_path)
    obs = graph_to_observations(graph)
    assert len(obs) >= 1
    assert obs[0].source == "cross-file-analysis"
    assert obs[0].category == "cross_file:data_exec_flow"
    assert "data_file" in obs[0].evidence


# -- Edge cases --

def test_binary_files_skipped_in_parsing(tmp_path):
    (tmp_path / "app.exe").write_bytes(b"MZ" + b"\x00" * 100)
    files = [_file("app.exe", FileClassification.BINARY)]
    graph = build_reference_graph(files, tmp_path)
    assert graph.references == []


def test_missing_file_handled(tmp_path):
    """File in list but not on disk shouldn't crash."""
    files = [_file("ghost.py")]
    graph = build_reference_graph(files, tmp_path)
    assert graph.references == []
