from __future__ import annotations

from security_scanner.models import FileClassification, ObservationSeverity
from security_scanner.source_analysis import (
    analyze_source,
    detect_dependency_risks,
    detect_embedded_payloads,
    detect_obfuscation,
    detect_secrets,
    detect_suspicious_imports,
)


# -- Obfuscation --

def test_detect_eval_exec():
    content = 'result = eval(some_expression)\nexec(compile(code, "<string>", "exec"))'
    obs = detect_obfuscation(content, "malware.py")
    categories = [o.category for o in obs]
    assert "obfuscation:eval_exec" in categories


def test_detect_base64_blob():
    import base64
    payload = base64.b64encode(b"This is a hidden payload that should be detected").decode()
    content = f'data = "{payload}"'
    obs = detect_obfuscation(content, "loader.py")
    categories = [o.category for o in obs]
    assert "obfuscation:base64" in categories


def test_detect_fromcharcode():
    content = 'var x = String.fromCharCode(72, 101, 108, 108, 111);'
    obs = detect_obfuscation(content, "script.js")
    assert any("fromcharcode" in o.category for o in obs)


def test_detect_js_obfuscation_vars():
    content = 'var _0x4a2b = ["\\x68\\x65\\x6c\\x6c\\x6f"]; var _0x3c1f = _0x4a2b[0];'
    obs = detect_obfuscation(content, "obfusc.js")
    categories = [o.category for o in obs]
    assert "obfuscation:js_obfusc" in categories


def test_detect_packed_js():
    content = 'eval(function(p,a,c,k,e,d){e=function(c){return c};while(c--){}})("hello",2,2,"hello|world".split("|"),0,{})'
    obs = detect_obfuscation(content, "packed.js")
    assert any("packed_js" in o.category for o in obs)


def test_detect_hex_escapes():
    content = r'shellcode = "\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68"'
    obs = detect_obfuscation(content, "exploit.py")
    assert any("hex_escape" in o.category for o in obs)


def test_combined_obfuscation_escalates_to_high():
    import base64
    payload = base64.b64encode(b"This is a super secret hidden payload data").decode()
    content = f'''
data = "{payload}"
exec(base64.b64decode(data))
var = String.fromCharCode(72, 101, 108, 108, 111)
'''
    obs = detect_obfuscation(content, "evil.py")
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_dynamic_import_exec_chain():
    """ForceMemo/GlassWorm pattern: __import__('base64') + __import__('zlib') + XOR + exec(compile())"""
    content = """
aqgqzxkfjzbdnhz = __import__('base64')
wogyjaaijwqbpxe = __import__('zlib')
idzextbcjbgkdih = 134
qyrrhmmwrhaknyf = lambda d, o: bytes([b ^ idzextbcjbgkdih for b in d])
lzcdrtfxyqiplpd = 'eNq9W19z3MaR...'
runzmcxgusiurqv = wogyjaaijwqbpxe.decompress(aqgqzxkfjzbdnhz.b64decode(lzcdrtfxyqiplpd))
ycqljtcxxkyiplo = qyrrhmmwrhaknyf(runzmcxgusiurqv, idzextbcjbgkdih)
exec(compile(ycqljtcxxkyiplo, '<>', 'exec'))
"""
    obs = detect_obfuscation(content, "setup.py")
    categories = [o.category for o in obs]
    # Must detect the compound import+exec chain as HIGH
    assert "obfuscation:import_exec_chain" in categories
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)
    # Should also catch the individual pieces
    assert "obfuscation:dynamic_import" in categories
    assert "obfuscation:xor_transform" in categories
    assert "obfuscation:eval_exec" in categories


def test_detect_xor_lambda():
    content = "decrypt = lambda data, key: bytes([b ^ key for b in data])"
    obs = detect_obfuscation(content, "loader.py")
    assert any("xor_transform" in o.category for o in obs)


def test_detect_marshal_loads():
    content = "import marshal\ncode = marshal.loads(encoded_data)\nexec(code)"
    obs = detect_obfuscation(content, "packed.py")
    assert any("marshal" in o.category for o in obs)


def test_detect_nested_decode_chain():
    content = "payload = zlib.decompress(base64.b64decode(blob))"
    obs = detect_obfuscation(content, "dropper.py")
    assert any("nested_decode" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_nested_decode_with_dunder_import():
    content = "__import__('zlib').decompress(__import__('base64').b64decode(data))"
    obs = detect_obfuscation(content, "evil.py")
    assert any("nested_decode" in o.category for o in obs)


def test_dynamic_import_without_exec_is_medium_not_high():
    content = "data = __import__('base64').b64decode('aGVsbG8=')"
    obs = detect_obfuscation(content, "util.py")
    dynamic_import_obs = [o for o in obs if o.category == "obfuscation:dynamic_import"]
    assert len(dynamic_import_obs) >= 1
    assert dynamic_import_obs[0].severity == ObservationSeverity.MEDIUM
    # No HIGH import_exec_chain because there's no exec/eval
    assert not any(o.category == "obfuscation:import_exec_chain" for o in obs)


def test_polymorphic_rat_pattern():
    """Polymorphic Python RAT: XOR + zlib + marshal + exec"""
    content = """
key = os.urandom(16)
encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(code)])
decrypted = lambda d, k: bytes([b ^ k for b in d])
import marshal
code_obj = marshal.loads(zlib.decompress(base64.b64decode(blob)))
exec(code_obj)
"""
    obs = detect_obfuscation(content, "rat.py")
    high_obs = [o for o in obs if o.severity == ObservationSeverity.HIGH]
    assert len(high_obs) >= 1  # Combined indicators should push to HIGH


def test_spellcheckpy_pattern():
    """spellcheckpy RAT: hex-encoded 'exec' string to evade static scan"""
    content = """
eval(compile(base64.b64decode(payload).decode('utf-8'), '<string>', bytes.fromhex('65786563').decode('utf-8')))
"""
    obs = detect_obfuscation(content, "spell.py")
    categories = [o.category for o in obs]
    assert "obfuscation:eval_exec" in categories
    assert "obfuscation:hex_escape" in categories or any("obfuscation" in c for c in categories)


def test_clean_source_no_obfuscation():
    content = "def hello():\n    print('Hello, world!')\n"
    obs = detect_obfuscation(content, "clean.py")
    assert obs == []


# -- Suspicious imports --

def test_detect_python_subprocess():
    content = "import subprocess\nsubprocess.run(['ls'])"
    obs = detect_suspicious_imports(content, "script.py")
    assert len(obs) >= 1
    assert any("subprocess" in str(o.evidence) for o in obs)


def test_detect_hardcoded_ip():
    content = 'requests.get("http://192.168.1.100/c2/beacon")'
    obs = detect_suspicious_imports(content, "client.py")
    assert any("hardcoded_ip" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_crypto_address():
    content = 'wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f2BD70"'
    obs = detect_suspicious_imports(content, "stealer.py")
    assert any("eth_addr" in o.category for o in obs)


def test_detect_js_child_process():
    content = "const { exec } = require('child_process');"
    obs = detect_suspicious_imports(content, "server.js")
    assert len(obs) >= 1


def test_clean_imports():
    content = "import os\nprint(os.getcwd())"
    obs = detect_suspicious_imports(content, "clean.py")
    assert all(o.severity.value in ("info", "low") for o in obs)


# -- Embedded payloads --

def test_detect_embedded_pe_header():
    content = r'payload = b"\x4d\x5a\x90\x00" + shellcode'
    obs = detect_embedded_payloads(content, "dropper.py")
    assert any("embedded_pe" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_shellcode():
    content = r'sc = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0"'
    obs = detect_embedded_payloads(content, "exploit.py")
    assert any("shellcode" in o.category for o in obs)


def test_detect_long_encoded_string():
    long_str = '"' + "A" * 600 + '"'
    content = f"data = {long_str}"
    obs = detect_embedded_payloads(content, "data.py")
    assert any("long_string" in o.category for o in obs)


def test_detect_data_uri():
    content = 'img = "data:application/octet-stream;base64,TVqQAAMAAAA..."'
    obs = detect_embedded_payloads(content, "page.html")
    assert any("data_uri" in o.category for o in obs)


# -- Dependency risks --

def test_detect_typosquat_npm():
    content = '{"dependencies": {"expresss": "^4.0.0"}}'
    obs = detect_dependency_risks(content, "package.json")
    assert any("typosquat" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_typosquat_python():
    content = "requets>=2.28.0\nflask"
    obs = detect_dependency_risks(content, "requirements.txt")
    assert any("typosquat" in o.category for o in obs)


def test_detect_postinstall_script():
    content = '{"scripts": {"postinstall": "node setup.js"}}'
    obs = detect_dependency_risks(content, "package.json")
    assert any("postinstall" in o.category for o in obs)


def test_detect_setup_py_cmdclass():
    content = "setup(cmdclass={'install': CustomInstall})"
    obs = detect_dependency_risks(content, "setup.py")
    assert any("custom_install" in o.category for o in obs)


def test_legitimate_deps_no_typosquat():
    content = '{"dependencies": {"express": "^4.18.0", "lodash": "^4.17.0"}}'
    obs = detect_dependency_risks(content, "package.json")
    assert not any("typosquat" in o.category for o in obs)


# -- Secrets --

def test_detect_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    obs = detect_secrets(content, "key.pem")
    assert any("private_key" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_aws_key():
    content = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    obs = detect_secrets(content, "config.py")
    assert any("aws_key" in o.category for o in obs)


def test_detect_github_token():
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    obs = detect_secrets(content, ".env")
    assert any("github_token" in o.category for o in obs)


def test_detect_generic_api_key():
    content = 'api_key = "sk_live_1234567890abcdefghij"'
    obs = detect_secrets(content, "config.yaml")
    assert any("api_key" in o.category for o in obs)


def test_no_secrets_in_clean_file():
    content = "name = 'my-app'\nversion = '1.0.0'"
    obs = detect_secrets(content, "config.py")
    assert obs == []


# -- Orchestrator --

def test_analyze_source_runs_all_detectors():
    content = 'exec(data)\nimport subprocess\n-----BEGIN RSA PRIVATE KEY-----\n'
    obs = analyze_source(content, "evil.py", FileClassification.SOURCE)
    sources = {o.category.split(":")[0] for o in obs}
    assert "obfuscation" in sources
    assert "import" in sources
    assert "secret" in sources


def test_analyze_config_includes_dependency_check():
    content = '{"dependencies": {"expresss": "^4.0.0"}, "scripts": {"postinstall": "node x.js"}}'
    obs = analyze_source(content, "package.json", FileClassification.CONFIG)
    categories = [o.category for o in obs]
    assert any("typosquat" in c for c in categories)
    assert any("postinstall" in c for c in categories)
