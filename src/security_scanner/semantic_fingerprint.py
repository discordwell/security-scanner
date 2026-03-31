"""Per-file semantic fingerprint: captures WHAT a file does, not HOW.

Computes a lightweight behavioral profile for each source file based on
its AST structure -- what it imports, reads, sends, and registers. This
enables cross-file anomaly detection: a file that imports urllib.request
in a directory where no other file does is suspicious regardless of what
specific strings it uses.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Import categorization
NETWORK_MODULES = {"urllib", "urllib.request", "requests", "httpx", "aiohttp", "http", "http.client", "socket", "socketserver"}
FILESYSTEM_MODULES = {"pathlib", "shutil", "glob", "tempfile", "fileinput"}
CRYPTO_MODULES = {"hashlib", "hmac", "ssl", "cryptography", "Crypto"}
EXEC_MODULES = {"subprocess", "ctypes", "marshal", "importlib", "multiprocessing"}
OS_MODULES = {"os", "sys", "platform", "signal", "atexit", "sysconfig"}
ENCODING_MODULES = {"base64", "zlib", "codecs", "json", "struct", "pickle", "bz2", "lzma", "gzip"}


@dataclass(slots=True)
class SemanticFingerprint:
    """Behavioral profile of a single source file."""

    # Import categories
    imports_network: list[str] = field(default_factory=list)
    imports_filesystem: list[str] = field(default_factory=list)
    imports_crypto: list[str] = field(default_factory=list)
    imports_exec: list[str] = field(default_factory=list)
    imports_os: list[str] = field(default_factory=list)
    imports_encoding: list[str] = field(default_factory=list)

    # Behavioral flags
    reads_files: bool = False
    reads_home_dir: bool = False
    makes_network_calls: bool = False
    registers_atexit: bool = False
    registers_signal: bool = False
    has_del_method: bool = False
    accesses_env_home: bool = False
    accesses_env_other: bool = False
    uses_exec: bool = False
    uses_open: bool = False

    def capability_set(self) -> frozenset[str]:
        """Return a set of capability tags for cross-file comparison."""
        caps: set[str] = set()
        if self.imports_network:
            caps.add("imports_network")
        if self.imports_exec:
            caps.add("imports_exec")
        if self.imports_encoding:
            caps.add("imports_encoding")
        if self.makes_network_calls:
            caps.add("network_calls")
        if self.reads_home_dir or self.accesses_env_home:
            caps.add("accesses_home")
        if self.registers_atexit:
            caps.add("atexit")
        if self.registers_signal:
            caps.add("signal_handler")
        if self.has_del_method:
            caps.add("finalizer")
        if self.uses_exec:
            caps.add("exec")
        if self.uses_open:
            caps.add("file_io")
        return frozenset(caps)

    def to_dict(self) -> dict:
        """Serialize for storage in RepoFileRecord.metadata."""
        return {
            "imports_network": self.imports_network,
            "imports_exec": self.imports_exec,
            "imports_encoding": self.imports_encoding,
            "capabilities": sorted(self.capability_set()),
        }


def compute_fingerprint(content: str, path: str) -> SemanticFingerprint:
    """Compute a semantic fingerprint for a source file.

    Uses AST parsing for Python files, falls back to regex for others.
    """
    fp = SemanticFingerprint()

    if not path.lower().endswith(".py"):
        # For non-Python files, use simple keyword detection
        _fingerprint_from_text(content, fp)
        return fp

    try:
        tree = ast.parse(content)
    except SyntaxError:
        _fingerprint_from_text(content, fp)
        return fp

    visitor = _FingerprintVisitor(fp)
    visitor.visit(tree)
    return fp


class _FingerprintVisitor(ast.NodeVisitor):
    """AST visitor that extracts behavioral capabilities."""

    def __init__(self, fp: SemanticFingerprint):
        self.fp = fp

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._categorize_import(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._categorize_import(node.module)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node)
        if func_name:
            # Network calls (including raw socket send methods)
            if any(n in func_name for n in ("urlopen", "request", "fetch", "connect", "getaddrinfo", "sendto", "sendall", "sendmsg")):
                self.fp.makes_network_calls = True
            # Home directory access via expanduser/Path.home
            if any(n in func_name for n in ("expanduser", "Path.home")):
                self.fp.reads_home_dir = True
            # atexit.register
            if "atexit.register" in func_name or func_name == "register":
                self.fp.registers_atexit = True
            # signal.signal
            if "signal.signal" in func_name:
                self.fp.registers_signal = True
            # exec/eval
            if func_name in ("exec", "eval", "compile"):
                self.fp.uses_exec = True
            # open()
            if func_name == "open":
                self.fp.uses_open = True
                self.fp.reads_files = True
            # os.environ
            if "environ" in func_name:
                self._check_env_access(node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Catch os.environ["HOME"] and os.environ.get("HOME")."""
        name = self._get_attr_name(node.value)
        if name and "environ" in name:
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                if node.slice.value in ("HOME", "USERPROFILE"):
                    self.fp.accesses_env_home = True
                    self.fp.reads_home_dir = True
                else:
                    self.fp.accesses_env_other = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.name == "__del__":
            self.fp.has_del_method = True
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        if node.name == "__del__":
            self.fp.has_del_method = True
        self.generic_visit(node)

    def _categorize_import(self, module: str):
        root = module.split(".")[0]
        if module in NETWORK_MODULES or root in {"urllib", "requests", "httpx", "aiohttp", "http", "socket"}:
            self.fp.imports_network.append(module)
        if module in FILESYSTEM_MODULES or root in {"pathlib", "shutil"}:
            self.fp.imports_filesystem.append(module)
        if module in CRYPTO_MODULES or root in {"hashlib", "hmac", "ssl", "cryptography"}:
            self.fp.imports_crypto.append(module)
        if module in EXEC_MODULES or root in {"subprocess", "ctypes", "marshal", "importlib"}:
            self.fp.imports_exec.append(module)
        if module in OS_MODULES or root in {"os", "sys", "signal", "atexit"}:
            self.fp.imports_os.append(module)
            if root == "atexit":
                self.fp.registers_atexit = True
        if module in ENCODING_MODULES or root in {"base64", "zlib", "codecs", "json", "struct", "pickle"}:
            self.fp.imports_encoding.append(module)

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            name = self._get_attr_name(node.func)
            return name
        return None

    def _get_attr_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_attr_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return None

    def _check_env_access(self, node: ast.Call):
        """Check if os.environ.get("HOME") or similar."""
        if node.args:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value in ("HOME", "USERPROFILE"):
                        self.fp.accesses_env_home = True
                        self.fp.reads_home_dir = True
                    else:
                        self.fp.accesses_env_other = True


def _fingerprint_from_text(content: str, fp: SemanticFingerprint):
    """Text-based fingerprint for non-Python files (JS, C/C++, Obj-C, Go, Rust, etc.)."""
    lower = content.lower()

    # --- JS patterns (original) ---
    if any(kw in lower for kw in ("require(", "import ", "fetch(", "xmlhttprequest")):
        if any(kw in lower for kw in ("http", "fetch(", "request", "socket")):
            fp.makes_network_calls = True
            fp.imports_network.append("(text-detected)")
    if "fs." in lower or "readfile" in lower:
        fp.reads_files = True
    if "child_process" in lower or "exec(" in lower:
        fp.uses_exec = True
        fp.imports_exec.append("(text-detected)")

    # --- Polyglot network APIs ---
    _net_apis = (
        "nsurlsession", "nsurlconnection", "datataskwith",
        "curl_easy_perform", "curl_easy_init",
        "http.get(", "http.post(", "http.newrequest",
        "net.dial", "net.listen",
        "reqwest::", "hyper::client",
        "httpclient", "webclient",
        "winhttpopen", "internetopen",
        "cfhoststartinforesolution",
    )
    if any(api in lower for api in _net_apis):
        fp.makes_network_calls = True
        fp.imports_network.append("(polyglot-detected)")

    # --- Polyglot home directory access ---
    _home_apis = (
        "nshomedirectory", "os.userhomedir", "dirs::home_dir",
        "home_dir()", "getpwuid",
        "shgetfolderpath",
    )
    if any(api in lower for api in _home_apis):
        fp.reads_home_dir = True

    # --- Polyglot environment variable access ---
    if "getenv(" in lower or "os.getenv(" in lower or "std::env::var" in lower:
        fp.accesses_env_other = True
    if "nsprocessinfo" in lower and "environment" in lower:
        fp.accesses_env_other = True
    if any(pat in content for pat in ('getenv("HOME")', "getenv('HOME')", 'Getenv("HOME")')):
        fp.accesses_env_home = True
        fp.reads_home_dir = True

    # --- Polyglot file I/O ---
    _file_apis = (
        "dataWithContentsOfFile", "contentsOfFile",
        "stringWithContentsOfFile", "writeToFile",
        "os.ReadFile", "ioutil.ReadFile",
        "std::fs::read", "std::ifstream",
        "fopen(", "fread(",
    )
    if any(api in content for api in _file_apis):
        fp.reads_files = True
        fp.uses_open = True

    # --- Polyglot exec/system ---
    _exec_apis = (
        "system(", "popen(",
        "exec.command", "std::process::command",
        "nsapplescript", "nstask",
        "createprocess",
    )
    if any(api in lower for api in _exec_apis):
        fp.uses_exec = True
        fp.imports_exec.append("(polyglot-detected)")
