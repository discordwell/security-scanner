"""Source code heuristic analysis for detecting malicious patterns in repos."""
from __future__ import annotations

import base64
import json
import logging
import re
from difflib import SequenceMatcher

from .models import FileClassification, Observation, ObservationSeverity

logger = logging.getLogger(__name__)

# Paths that indicate test/fixture/data files -- findings here are less likely malicious
_TEST_PATH_INDICATORS = {"test", "tests", "spec", "specs", "fixtures", "fixture", "testdata", "test_data", "__tests__", "mocks", "mock"}
_DATA_EXTENSIONS = {".json", ".yml", ".yaml", ".xml", ".csv", ".txt", ".md", ".rst", ".cfg", ".ini", ".toml"}


def _is_test_or_fixture(path: str) -> bool:
    parts = set(path.lower().replace("\\", "/").split("/"))
    return bool(parts & _TEST_PATH_INDICATORS) or path.lower().startswith("test")


def _is_data_file(path: str) -> bool:
    return any(path.lower().endswith(ext) for ext in _DATA_EXTENSIONS)


def _is_localhost_or_private(url: str) -> bool:
    """Check if a URL points to localhost, loopback, or RFC 1918 private ranges."""
    import re as _re
    ip_match = _re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
    if not ip_match:
        return False
    ip = ip_match.group(1)
    return (
        ip.startswith("127.") or ip.startswith("0.") or
        ip.startswith("10.") or ip.startswith("192.168.") or
        ip.startswith("172.16.") or ip.startswith("172.17.") or
        ip.startswith("172.18.") or ip.startswith("172.19.") or
        ip.startswith("172.2") or ip.startswith("172.3") or
        ip.startswith("169.254.") or  # link-local (but also cloud metadata -- handled separately)
        ip == "0.0.0.0"
    )


def _is_cloud_metadata_ip(url: str) -> bool:
    """169.254.169.254 and 169.254.170.2 are cloud instance metadata endpoints."""
    return "169.254.169.254" in url or "169.254.170.2" in url


# --- Obfuscation detection ---

_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_HEX_ESCAPE_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}')
_HEX_LONG_RE = re.compile(r'0x[0-9a-fA-F]{16,}')
_EVAL_EXEC_RE = re.compile(r'\b(eval|exec)\s*\(')
_FROMCHARCODE_RE = re.compile(r'String\.fromCharCode\s*\(')
_ATOB_RE = re.compile(r'\batob\s*\(')
_JS_OBFUSC_VAR_RE = re.compile(r'\b_0x[0-9a-f]{4,}\b')
_PACKED_JS_RE = re.compile(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)')

# Invisible Unicode payload (GlassWorm) -- variation selectors and PUA characters
_UNICODE_VARIATION_SELECTOR_RE = re.compile(r'[\uFE00-\uFE0F]')
_UNICODE_PUA_SUPPLEMENT_RE = re.compile(r'[\U000E0100-\U000E01EF]')
_CODEPOINT_DECODER_RE = re.compile(r'codePointAt\s*\(.*?0x[Ff][Ee]00')

# Dynamic import + deobfuscation + exec patterns (Python malware staple)
_DUNDER_IMPORT_RE = re.compile(r"__import__\s*\(\s*['\"](\w+)['\"]\s*\)")
_EXEC_COMPILE_RE = re.compile(r'exec\s*\(\s*compile\s*\(')
_XOR_LAMBDA_RE = re.compile(r'lambda\s+\w+\s*,?\s*\w*\s*:\s*bytes\s*\(\s*\[\s*\w+\s*\^\s*\w+')
_MARSHAL_LOADS_RE = re.compile(r'marshal\.loads\s*\(')
_NESTED_DECODE_RE = re.compile(
    r'(zlib\.decompress|__import__\s*\(\s*[\'"]zlib[\'"]\s*\)\.decompress)\s*\('
    r'.*?(base64\.b64decode|__import__\s*\(\s*[\'"]base64[\'"]\s*\)\.b64decode)',
    re.DOTALL,
)
_CODECS_DECODE_RE = re.compile(r'codecs\.decode\s*\(.*[\'"]rot.?13[\'"]\s*\)')

# Encoding modules that have no reason to be dynamically imported
_SUSPICIOUS_DUNDER_MODULES = {"base64", "zlib", "marshal", "codecs", "bz2", "lzma"}


def detect_obfuscation(content: str, path: str) -> list[Observation]:
    obs: list[Observation] = []
    indicators = 0

    for match in _BASE64_RE.finditer(content):
        try:
            decoded = base64.b64decode(match.group())
            if len(decoded) > 20 and sum(32 <= b < 127 for b in decoded) > len(decoded) * 0.5:
                obs.append(Observation(
                    source="source-heuristic", category="obfuscation:base64",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Base64-encoded blob ({len(match.group())} chars) decodes to readable content.",
                    evidence={"path": path, "offset": match.start(), "decoded_preview": decoded[:80].decode("utf-8", errors="replace")},
                    tags=["source", "obfuscation", "base64"],
                ))
                indicators += 1
                break  # One per file is enough
        except Exception:
            pass

    for pattern, name, tag in [
        (_HEX_ESCAPE_RE, "Hex-escaped byte sequence", "hex_escape"),
        (_EVAL_EXEC_RE, "eval()/exec() call", "eval_exec"),
        (_FROMCHARCODE_RE, "String.fromCharCode()", "fromcharcode"),
        (_ATOB_RE, "atob() call", "atob"),
        (_JS_OBFUSC_VAR_RE, "JS obfuscation variable naming (_0x...)", "js_obfusc"),
        (_PACKED_JS_RE, "Packed JavaScript (p,a,c,k,e,d)", "packed_js"),
    ]:
        matches = pattern.findall(content)
        if matches:
            obs.append(Observation(
                source="source-heuristic", category=f"obfuscation:{tag}",
                severity=ObservationSeverity.MEDIUM,
                message=f"{name} found in {path} ({len(matches)} occurrence(s)).",
                evidence={"path": path, "count": len(matches)},
                tags=["source", "obfuscation", tag],
            ))
            indicators += 1

    # --- Invisible Unicode payload (GlassWorm) ---
    vs_count = len(_UNICODE_VARIATION_SELECTOR_RE.findall(content))
    pua_count = len(_UNICODE_PUA_SUPPLEMENT_RE.findall(content))
    invisible_chars = vs_count + pua_count
    has_codepoint_decoder = bool(_CODEPOINT_DECODER_RE.search(content))

    if invisible_chars > 50:
        severity = ObservationSeverity.HIGH
        if has_codepoint_decoder or _EVAL_EXEC_RE.search(content):
            severity = ObservationSeverity.CRITICAL
        # JSON/data files may legitimately contain Unicode test data (e.g. normalization tests)
        if _is_data_file(path) and not has_codepoint_decoder:
            severity = ObservationSeverity.INFO
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:invisible_unicode",
            severity=severity,
            message=f"Invisible Unicode payload detected in {path}: {invisible_chars} hidden characters (variation selectors / PUA). Code is literally invisible to editors but executable by JavaScript interpreters.",
            evidence={"path": path, "invisible_chars": invisible_chars, "variation_selectors": vs_count, "pua_chars": pua_count, "has_decoder": has_codepoint_decoder},
            tags=["source", "obfuscation", "invisible_unicode", "glassworm"],
        ))
        if severity != ObservationSeverity.INFO:
            indicators += 1

    if has_codepoint_decoder:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:unicode_decoder",
            severity=ObservationSeverity.HIGH,
            message=f"Unicode variation selector decoder (codePointAt + 0xFE00) in {path} -- GlassWorm-style invisible code execution pattern.",
            evidence={"path": path},
            tags=["source", "obfuscation", "unicode_decoder", "glassworm"],
        ))
        indicators += 1

    # --- Dynamic __import__ deobfuscation chain (Python malware staple) ---
    dunder_imports = _DUNDER_IMPORT_RE.findall(content)
    suspicious_dimports = [m for m in dunder_imports if m in _SUSPICIOUS_DUNDER_MODULES]
    has_exec_compile = bool(_EXEC_COMPILE_RE.search(content))
    has_xor_lambda = bool(_XOR_LAMBDA_RE.search(content))
    has_marshal = bool(_MARSHAL_LOADS_RE.search(content))
    has_nested_decode = bool(_NESTED_DECODE_RE.search(content))
    has_codecs_rot = bool(_CODECS_DECODE_RE.search(content))

    if suspicious_dimports:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:dynamic_import",
            severity=ObservationSeverity.MEDIUM,
            message=f"Dynamic __import__() of encoding modules in {path}: {', '.join(suspicious_dimports)}.",
            evidence={"path": path, "modules": suspicious_dimports},
            tags=["source", "obfuscation", "dynamic_import"],
        ))
        indicators += 1

    if has_xor_lambda:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:xor_transform",
            severity=ObservationSeverity.MEDIUM,
            message=f"XOR byte-transform lambda in {path} -- classic malware decryption pattern.",
            evidence={"path": path},
            tags=["source", "obfuscation", "xor"],
        ))
        indicators += 1

    if has_marshal:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:marshal",
            severity=ObservationSeverity.MEDIUM,
            message=f"marshal.loads() in {path} -- deserializes Python code objects at runtime.",
            evidence={"path": path},
            tags=["source", "obfuscation", "marshal"],
        ))
        indicators += 1

    if has_codecs_rot:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:rot13",
            severity=ObservationSeverity.MEDIUM,
            message=f"ROT13 codec decoding in {path}.",
            evidence={"path": path},
            tags=["source", "obfuscation", "rot13"],
        ))
        indicators += 1

    # --- Compound HIGH: __import__ + decode chain + exec (zero legitimate use) ---
    if suspicious_dimports and (has_exec_compile or _EVAL_EXEC_RE.search(content)):
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:import_exec_chain",
            severity=ObservationSeverity.HIGH,
            message=f"Dynamic __import__() of {', '.join(suspicious_dimports)} combined with exec/eval/compile in {path} -- this is a malware deobfuscation-and-execute chain with no legitimate use case.",
            evidence={"path": path, "modules": suspicious_dimports, "has_exec_compile": has_exec_compile, "has_xor": has_xor_lambda},
            tags=["source", "obfuscation", "import_exec_chain", "malware_pattern"],
        ))

    if has_nested_decode:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:nested_decode",
            severity=ObservationSeverity.HIGH,
            message=f"Nested decode chain (zlib.decompress + base64.b64decode) in {path} -- multi-layer payload deobfuscation.",
            evidence={"path": path},
            tags=["source", "obfuscation", "nested_decode", "malware_pattern"],
        ))

    if indicators >= 3:
        obs.append(Observation(
            source="source-heuristic", category="obfuscation:combined",
            severity=ObservationSeverity.HIGH,
            message=f"Multiple obfuscation indicators ({indicators}) in {path} -- strongly suggests intentional code hiding.",
            evidence={"path": path, "indicator_count": indicators},
            tags=["source", "obfuscation", "combined"],
        ))

    return obs


# --- Suspicious imports ---

_HARDCODED_IP_RE = re.compile(r'''["'](https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^"']*)["']''')
_CRYPTO_ADDR_BTC_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
_CRYPTO_ADDR_ETH_RE = re.compile(r'\b0x[0-9a-fA-F]{40}\b')

SUSPICIOUS_PYTHON_IMPORTS = {"subprocess", "ctypes", "socket", "os.system", "os.popen", "importlib", "marshal", "compile"}
SUSPICIOUS_JS_IMPORTS = {"child_process", "net", "dgram"}
SUSPICIOUS_GO_IMPORTS = {"os/exec", "net", "syscall"}


def detect_suspicious_imports(content: str, path: str) -> list[Observation]:
    obs: list[Observation] = []
    lower_path = path.lower()

    found_imports: list[str] = []
    has_network = False
    has_exec = False

    if lower_path.endswith(".py"):
        for imp in SUSPICIOUS_PYTHON_IMPORTS:
            if imp in content:
                found_imports.append(imp)
                if imp in ("subprocess", "os.system", "os.popen", "marshal", "compile"):
                    has_exec = True
                if imp in ("socket",):
                    has_network = True
    elif lower_path.endswith((".js", ".ts", ".jsx", ".tsx")):
        for imp in SUSPICIOUS_JS_IMPORTS:
            if imp in content:
                found_imports.append(imp)
                if imp == "child_process":
                    has_exec = True
                if imp in ("net", "dgram"):
                    has_network = True
    elif lower_path.endswith(".go"):
        for imp in SUSPICIOUS_GO_IMPORTS:
            if imp in content:
                found_imports.append(imp)
                if imp == "os/exec":
                    has_exec = True
                if imp == "net":
                    has_network = True

    if found_imports:
        severity = ObservationSeverity.LOW
        if has_exec and has_network:
            severity = ObservationSeverity.MEDIUM
        obs.append(Observation(
            source="source-heuristic", category="import:suspicious",
            severity=severity,
            message=f"Suspicious imports in {path}: {', '.join(found_imports)}.",
            evidence={"path": path, "imports": found_imports},
            tags=["source", "import"],
        ))

    for match in _HARDCODED_IP_RE.finditer(content):
        url = match.group(1)
        # Cloud metadata endpoints are always suspicious (credential theft)
        if _is_cloud_metadata_ip(url):
            obs.append(Observation(
                source="source-heuristic", category="import:cloud_metadata",
                severity=ObservationSeverity.HIGH,
                message=f"Cloud instance metadata endpoint in {path}: {url[:60]}",
                evidence={"path": path, "url": url[:200]},
                tags=["source", "network", "cloud_metadata"],
            ))
        elif _is_localhost_or_private(url):
            # Localhost/private IPs in test files are always benign
            if not _is_test_or_fixture(path):
                obs.append(Observation(
                    source="source-heuristic", category="import:hardcoded_ip",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Private/localhost IP in non-test file {path}: {url[:60]}",
                    evidence={"path": path, "url": url[:200]},
                    tags=["source", "network", "hardcoded_ip"],
                ))
        else:
            # Public IPs in test files are likely test fixtures
            severity = ObservationSeverity.HIGH
            if _is_test_or_fixture(path):
                severity = ObservationSeverity.MEDIUM
            obs.append(Observation(
                source="source-heuristic", category="import:hardcoded_ip",
                severity=severity,
                message=f"Hardcoded public IP URL in {path}: {url[:60]}",
                evidence={"path": path, "url": url[:200]},
                tags=["source", "network", "hardcoded_ip"],
            ))

    for regex, name, tag in [
        (_CRYPTO_ADDR_BTC_RE, "Bitcoin address", "btc_addr"),
        (_CRYPTO_ADDR_ETH_RE, "Ethereum address", "eth_addr"),
    ]:
        matches = regex.findall(content)
        if matches:
            obs.append(Observation(
                source="source-heuristic", category=f"crypto:{tag}",
                severity=ObservationSeverity.MEDIUM,
                message=f"Possible {name} in {path} ({len(matches)} found).",
                evidence={"path": path, "addresses": matches[:5]},
                tags=["source", "crypto", tag],
            ))

    return obs


# --- Embedded payloads ---

_LONG_STRING_RE = re.compile(r'''["'][^"']{500,}["']''')
_DATA_URI_RE = re.compile(r'data:[^;]+;base64,')
_EMBEDDED_PE_RE = re.compile(r'(?:\\x4[dD]\\x5[aA]|\\x7[fF]ELF|b"MZ"|b\'MZ\')')
_SHELLCODE_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){20,}')


def detect_embedded_payloads(content: str, path: str) -> list[Observation]:
    obs: list[Observation] = []

    if _EMBEDDED_PE_RE.search(content):
        obs.append(Observation(
            source="source-heuristic", category="payload:embedded_pe",
            severity=ObservationSeverity.HIGH,
            message=f"Embedded PE/ELF header detected in source file {path}.",
            evidence={"path": path},
            tags=["source", "payload", "embedded_binary"],
        ))

    shellcode_matches = _SHELLCODE_RE.findall(content)
    if shellcode_matches:
        # Hex constants are common in crypto/Rust/C/contract code and test fixtures
        is_likely_data = (
            path.lower().endswith((".rs", ".c", ".h", ".cpp", ".go")) or
            _is_test_or_fixture(path) or
            _is_data_file(path)
        )
        severity = ObservationSeverity.MEDIUM if is_likely_data else ObservationSeverity.HIGH
        obs.append(Observation(
            source="source-heuristic", category="payload:shellcode",
            severity=severity,
            message=f"Shellcode-like hex byte sequence ({len(shellcode_matches)} occurrences) in {path}." + (" (likely data/constants)" if is_likely_data else ""),
            evidence={"path": path, "count": len(shellcode_matches)},
            tags=["source", "payload", "shellcode"],
        ))

    long_strings = _LONG_STRING_RE.findall(content)
    if long_strings and not _is_data_file(path):
        obs.append(Observation(
            source="source-heuristic", category="payload:long_string",
            severity=ObservationSeverity.MEDIUM,
            message=f"Long encoded string ({len(long_strings[0])} chars) in {path} -- may hide a payload.",
            evidence={"path": path, "count": len(long_strings), "max_length": max(len(s) for s in long_strings)},
            tags=["source", "payload", "encoded"],
        ))

    if _DATA_URI_RE.search(content):
        obs.append(Observation(
            source="source-heuristic", category="payload:data_uri",
            severity=ObservationSeverity.MEDIUM,
            message=f"Base64 data URI in {path}.",
            evidence={"path": path},
            tags=["source", "payload", "data_uri"],
        ))

    return obs


# --- Dependency risks ---

POPULAR_PACKAGES = {
    "python": [
        "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
        "pillow", "cryptography", "paramiko", "boto3", "colorama", "pyyaml",
        "setuptools", "pip", "wheel", "urllib3", "certifi", "six", "idna",
    ],
    "node": [
        "express", "react", "lodash", "axios", "moment", "webpack", "babel",
        "typescript", "eslint", "prettier", "jest", "mocha", "chalk", "commander",
        "inquirer", "dotenv", "cors", "helmet", "mongoose", "sequelize",
    ],
}

_POSTINSTALL_EXEC_RE = re.compile(r'(node|python|python3|bash|sh|curl|wget|powershell|bun|npx)\b')


def _is_typosquat(name: str, ecosystem: str) -> str | None:
    for legit in POPULAR_PACKAGES.get(ecosystem, []):
        if name == legit:
            return None
        ratio = SequenceMatcher(None, name.lower(), legit.lower()).ratio()
        if 0.75 < ratio < 1.0 and name != legit:
            return legit
    return None


def detect_dependency_risks(content: str, path: str) -> list[Observation]:
    obs: list[Observation] = []
    lower_path = path.lower()

    if lower_path.endswith("package.json"):
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return obs

        deps = list((pkg.get("dependencies") or {}).keys()) + list((pkg.get("devDependencies") or {}).keys())
        for dep in deps:
            legit = _is_typosquat(dep, "node")
            if legit:
                obs.append(Observation(
                    source="source-heuristic", category="dependency:typosquat",
                    severity=ObservationSeverity.HIGH,
                    message=f"Possible typosquat: '{dep}' resembles popular package '{legit}'.",
                    evidence={"path": path, "package": dep, "resembles": legit},
                    tags=["source", "dependency", "typosquat"],
                ))

        scripts = pkg.get("scripts") or {}
        for hook in ("preinstall", "postinstall", "preuninstall", "postuninstall"):
            cmd = scripts.get(hook, "")
            if cmd and _POSTINSTALL_EXEC_RE.search(cmd):
                obs.append(Observation(
                    source="source-heuristic", category="dependency:postinstall",
                    severity=ObservationSeverity.MEDIUM,
                    message=f"Suspicious {hook} script in {path}: {cmd[:100]}",
                    evidence={"path": path, "hook": hook, "command": cmd[:200]},
                    tags=["source", "dependency", "postinstall"],
                ))

    elif lower_path.endswith(("requirements.txt",)):
        for line in content.splitlines():
            pkg_name = re.split(r'[>=<!\[]', line.strip())[0].strip()
            if pkg_name and not pkg_name.startswith("#"):
                legit = _is_typosquat(pkg_name, "python")
                if legit:
                    obs.append(Observation(
                        source="source-heuristic", category="dependency:typosquat",
                        severity=ObservationSeverity.HIGH,
                        message=f"Possible typosquat: '{pkg_name}' resembles popular package '{legit}'.",
                        evidence={"path": path, "package": pkg_name, "resembles": legit},
                        tags=["source", "dependency", "typosquat"],
                    ))

    elif lower_path.endswith("setup.py"):
        if "cmdclass" in content:
            obs.append(Observation(
                source="source-heuristic", category="dependency:custom_install",
                severity=ObservationSeverity.MEDIUM,
                message=f"Custom install command (cmdclass) in {path}.",
                evidence={"path": path},
                tags=["source", "dependency", "custom_install"],
            ))

    return obs


# --- Secrets detection ---

_AWS_KEY_RE = re.compile(r'AKIA[0-9A-Z]{16}')
_GENERIC_KEY_RE = re.compile(
    r'(?:api[_-]?key|apikey|token|secret|password|credentials?)\s*[:=]\s*["\']?([A-Za-z0-9_\-/+=]{20,})',
    re.IGNORECASE,
)
_PRIVATE_KEY_RE = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')
_GITHUB_TOKEN_RE = re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')


def detect_secrets(content: str, path: str) -> list[Observation]:
    obs: list[Observation] = []

    if _PRIVATE_KEY_RE.search(content):
        severity = ObservationSeverity.HIGH
        if _is_test_or_fixture(path):
            severity = ObservationSeverity.INFO
        # Crypto libraries reference key format headers as constants for parsing
        elif any(kw in path.lower() for kw in ("serialization", "pem", "x509", "pkcs", "hazmat", "crypto")):
            severity = ObservationSeverity.INFO
        obs.append(Observation(
            source="source-heuristic", category="secret:private_key",
            severity=severity,
            message=f"Private key found in {path}." + (" (test/fixture file)" if severity == ObservationSeverity.INFO else ""),
            evidence={"path": path, "in_test": _is_test_or_fixture(path)},
            tags=["source", "secret", "private_key"],
        ))

    for regex, name, category, severity in [
        (_AWS_KEY_RE, "AWS access key", "secret:aws_key", ObservationSeverity.HIGH),
        (_GITHUB_TOKEN_RE, "GitHub token", "secret:github_token", ObservationSeverity.HIGH),
        (_GENERIC_KEY_RE, "API key/token", "secret:api_key", ObservationSeverity.MEDIUM),
    ]:
        matches = regex.findall(content)
        if matches:
            obs.append(Observation(
                source="source-heuristic", category=category,
                severity=severity,
                message=f"{name} found in {path}.",
                evidence={"path": path, "count": len(matches)},
                tags=["source", "secret"],
            ))

    return obs


# --- Behavioral pattern detection (intent, not mechanism) ---

# Sensitive file paths that credential stealers target
_SENSITIVE_PATH_RE = re.compile(
    r'(?:expanduser|homedir|HOME|USERPROFILE|home_?dir|Path\.home|Path\(\s*["\']~["\'])'
    r'.*?'
    r'(?:\.ssh|\.aws|\.npmrc|\.gitconfig|\.gnupg|\.env\b|\.docker|\.kube|'
    r'credentials|id_rsa|id_ed25519|\.yarnrc|\.pypirc|\.netrc|'
    r'Local\s*Storage|cookies\.sqlite|Login\s*Data|\.config/gh)',
    re.IGNORECASE | re.DOTALL,
)
# Direct path string references (with home prefix)
_SENSITIVE_LITERAL_RE = re.compile(
    r'''['"]((?:~/|/home/|%USERPROFILE%)[^'"]*?(?:\.ssh|\.aws|\.npmrc|\.gitconfig|\.env|\.docker|\.kube|credentials|id_rsa|\.yarnrc|\.pypirc))['"]''',
    re.IGNORECASE,
)
# Bare sensitive path strings (without home prefix -- catches loop patterns)
_BARE_SENSITIVE_RE = re.compile(
    r'''['"]\.(?:ssh/(?:id_rsa|id_ed25519|config|known_hosts)|aws/credentials|gitconfig|npmrc|docker/config\.json|kube/config|gnupg|pypirc|netrc|yarnrc)['"]''',
)

# Network exfiltration methods
_EXFIL_PYTHON_RE = re.compile(
    r'(?:urlopen|urllib\.request\.Request|requests\.(?:post|get|put|send)|'
    r'httpx\.(?:post|get|put)|http\.client\.HTTP|socket\.connect)',
)
_EXFIL_JS_RE = re.compile(
    r'(?:https?\.request|\.fetch\(|XMLHttpRequest|'
    r'execSync\s*\(.*?(?:curl|wget)|axios\.(?:post|get|put))',
    re.DOTALL,
)


def detect_behavioral_patterns(content: str, path: str) -> list[Observation]:
    """Detect operational intent: reading sensitive files + exfiltrating data."""
    obs: list[Observation] = []

    # Find sensitive file access
    sensitive_hits = _SENSITIVE_PATH_RE.findall(content)
    literal_hits = _SENSITIVE_LITERAL_RE.findall(content)
    bare_hits = _BARE_SENSITIVE_RE.findall(content)
    all_sensitive = sensitive_hits + literal_hits + bare_hits

    # Find network exfiltration
    exfil_hits = _EXFIL_PYTHON_RE.findall(content) + _EXFIL_JS_RE.findall(content)

    if all_sensitive and exfil_hits:
        # Compound: reads sensitive files AND transmits data
        sensitive_summary = ", ".join(set(h[:40] for h in all_sensitive[:5]))
        exfil_summary = ", ".join(set(h[:30] for h in exfil_hits[:3]))
        obs.append(Observation(
            source="source-heuristic",
            category="behavioral:credential_access_exfil",
            severity=ObservationSeverity.MEDIUM,
            message=f"Behavioral pattern in {path}: accesses sensitive files ({sensitive_summary}) and transmits data externally ({exfil_summary}). Characteristic of credential theft.",
            evidence={
                "path": path,
                "sensitive_paths": list(set(h[:60] for h in all_sensitive[:10])),
                "exfil_methods": list(set(h[:40] for h in exfil_hits[:5])),
            },
            tags=["source", "behavioral", "credential_theft"],
        ))
    elif all_sensitive and len(all_sensitive) >= 3:
        # Bulk sensitive file access without obvious exfil (might use indirect method)
        obs.append(Observation(
            source="source-heuristic",
            category="behavioral:bulk_credential_access",
            severity=ObservationSeverity.MEDIUM,
            message=f"Bulk sensitive file access in {path}: reads {len(all_sensitive)} credential paths.",
            evidence={"path": path, "sensitive_paths": list(set(h[:60] for h in all_sensitive[:10]))},
            tags=["source", "behavioral", "credential_access"],
        ))

    return obs


# --- Indirect exec detection (top 3 variants, not exhaustive) ---

_GETATTR_BUILTINS_RE = re.compile(r'getattr\s*\(\s*(?:__builtins__|builtins)\s*,')
_GETATTR_CONCAT_RE = re.compile(r"getattr\s*\(\s*(?:__builtins__|builtins)\s*,\s*['\"][^'\"]*['\"]\s*\+")
_GLOBALS_EXEC_RE = re.compile(r'(?:globals|vars)\s*\(\s*(?:__builtins__|builtins)?\s*\)\s*\[')
_JS_GLOBAL_COMPUTED_RE = re.compile(r'global\s*\[')


def detect_indirect_exec(content: str, path: str) -> list[Observation]:
    """Detect common indirect function resolution patterns."""
    obs: list[Observation] = []

    # Special case: getattr(__builtins__, 'ex' + 'ec') -- string concat is the tell
    # No legitimate code splits builtin function names. This is HIGH, not MEDIUM.
    if _GETATTR_CONCAT_RE.search(content):
        obs.append(Observation(
            source="source-heuristic",
            category="obfuscation:indirect_exec:getattr_concat",
            severity=ObservationSeverity.HIGH,
            message=f"getattr(__builtins__, <string concatenation>) in {path} -- splits a builtin name to evade static analysis. No legitimate use case.",
            evidence={"path": path, "pattern": "getattr_concat"},
            tags=["source", "obfuscation", "indirect_exec", "getattr_concat"],
        ))
    elif _GETATTR_BUILTINS_RE.search(content):
        obs.append(Observation(
            source="source-heuristic",
            category="obfuscation:indirect_exec:getattr_builtins",
            severity=ObservationSeverity.MEDIUM,
            message=f"Indirect function resolution via getattr() on __builtins__ in {path} -- commonly used to hide exec/eval calls from static analysis.",
            evidence={"path": path, "pattern": "getattr_builtins"},
            tags=["source", "obfuscation", "indirect_exec", "getattr_builtins"],
        ))

    for pattern, name, tag in [
        (_GLOBALS_EXEC_RE, "Dictionary access to builtins (globals/vars)", "dict_builtins"),
        (_JS_GLOBAL_COMPUTED_RE, "Computed global property access", "global_computed"),
    ]:
        if pattern.search(content):
            obs.append(Observation(
                source="source-heuristic",
                category=f"obfuscation:indirect_exec:{tag}",
                severity=ObservationSeverity.MEDIUM,
                message=f"Indirect function resolution via {name} in {path} -- commonly used to hide exec/eval calls from static analysis.",
                evidence={"path": path, "pattern": tag},
                tags=["source", "obfuscation", "indirect_exec", tag],
            ))

    return obs


# --- Orchestrator ---

def analyze_source(content: str, path: str, classification: FileClassification) -> list[Observation]:
    """Run all applicable detectors on a source/config/script file."""
    observations: list[Observation] = []
    observations.extend(detect_obfuscation(content, path))
    observations.extend(detect_suspicious_imports(content, path))
    observations.extend(detect_embedded_payloads(content, path))
    observations.extend(detect_secrets(content, path))
    observations.extend(detect_behavioral_patterns(content, path))
    observations.extend(detect_indirect_exec(content, path))
    if classification == FileClassification.CONFIG:
        observations.extend(detect_dependency_risks(content, path))

    # Compound escalation: behavioral credential theft + indirect exec = MALICIOUS intent
    categories = {o.category for o in observations}
    has_behavioral = any(c.startswith("behavioral:credential_access") for c in categories)
    has_indirect_exec = any(c.startswith("obfuscation:indirect_exec") for c in categories)
    if has_behavioral and has_indirect_exec:
        observations.append(Observation(
            source="source-heuristic",
            category="compound:credential_theft_with_evasion",
            severity=ObservationSeverity.HIGH,
            message=f"Credential theft with exec evasion in {path}: reads sensitive files AND hides execution via indirect function resolution. This combination has no legitimate use case.",
            evidence={"path": path, "behavioral": True, "indirect_exec": True},
            tags=["source", "compound", "credential_theft", "evasion"],
        ))

    return observations
