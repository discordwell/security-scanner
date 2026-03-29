"""AST-based constant resolution for deobfuscating Python string construction.

Parses Python source into an AST and evaluates constant expressions to
recover the actual string values. This closes the obfuscation gap where
attackers construct sensitive paths from character lists, chr() calls,
or hex decoding to evade regex-based detection.

Never calls eval(). Only pattern-matches AST node shapes and performs
the equivalent arithmetic manually.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ResolvedStrings:
    """Strings recovered by evaluating constant expressions in the AST."""
    values: list[str] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)
    original_had_obfuscation: bool = False


def resolve_constants(source: str) -> ResolvedStrings:
    """Parse Python source and resolve constant string expressions.

    Targets:
    1. "".join(["s","s","h","/",...]) → "ssh/"
    2. chr(115)+chr(115)+chr(104) → "ssh"
    3. bytes.fromhex("737368").decode() → "ssh"
    4. Simple single-assignment variable propagation (limited)
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ResolvedStrings()

    resolver = _ConstantResolver()
    resolver.visit(tree)
    return resolver.result


class _ConstantResolver(ast.NodeVisitor):
    """AST visitor that resolves constant string expressions."""

    def __init__(self):
        self.result = ResolvedStrings()
        # Simple variable tracking: name → constant value (single assignment only)
        self._vars: dict[str, str] = {}

    def visit_Assign(self, node: ast.Assign):
        """Track simple string assignments for variable propagation."""
        if (len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            self._vars[node.targets[0].id] = node.value.value
        # Also try to resolve the value if it's a complex expression
        resolved = self._try_resolve(node.value)
        if resolved is not None and len(resolved) > 3:
            if isinstance(node.targets[0], ast.Name):
                self._vars[node.targets[0].id] = resolved
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check for join(), chr(), bytes.fromhex() patterns."""
        resolved = self._try_resolve(node)
        if resolved is not None and len(resolved) > 3:
            self._record(resolved, node)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Check for string concatenation chains."""
        resolved = self._try_resolve(node)
        if resolved is not None and len(resolved) > 3:
            self._record(resolved, node)
        self.generic_visit(node)

    def visit_List(self, node: ast.List):
        """Check for lists of single-character strings (char lists).

        Even if not wrapped in join(), a list like ["s","s","h","/","i","d","_","r","s","a"]
        is itself suspicious and its joined value is useful for downstream detectors.
        """
        if len(node.elts) >= 4 and all(
            isinstance(elt, ast.Constant) and isinstance(elt.value, str) and len(elt.value) <= 1
            for elt in node.elts
        ):
            joined = "".join(elt.value for elt in node.elts)
            if len(joined) > 3:
                self._record(joined, node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Check for f-strings with all-constant parts."""
        resolved = self._try_resolve(node)
        if resolved is not None and len(resolved) > 3:
            self._record(resolved, node)
        self.generic_visit(node)

    def _record(self, value: str, node: ast.AST):
        """Record a resolved string value."""
        if value not in self.result.values:
            self.result.values.append(value)
            self.result.sources.append({
                "line": getattr(node, "lineno", None),
                "type": type(node).__name__,
            })
            self.result.original_had_obfuscation = True

    def _try_resolve(self, node: ast.AST) -> str | None:
        """Try to resolve an AST node to a constant string value."""
        if node is None:
            return None

        # Literal string constant
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value

        # Variable reference
        if isinstance(node, ast.Name) and node.id in self._vars:
            return self._vars[node.id]

        # "".join([...]) or "sep".join([...])
        if isinstance(node, ast.Call) and self._is_str_join(node):
            return self._resolve_join(node)

        # chr(N) call
        if isinstance(node, ast.Call) and self._is_chr_call(node):
            return self._resolve_chr(node)

        # bytes.fromhex("...").decode()
        if isinstance(node, ast.Call) and self._is_fromhex_decode(node):
            return self._resolve_fromhex(node)

        # String concatenation: A + B
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._resolve_concat(node)

        # list(str) used for building char lists assigned to variables
        if isinstance(node, ast.Call) and self._is_list_call(node):
            return self._resolve_list_call(node)

        return None

    # --- Join resolution ---

    def _is_str_join(self, node: ast.Call) -> bool:
        """Check if node is "str".join(iterable)."""
        return (isinstance(node.func, ast.Attribute)
                and node.func.attr == "join"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
                and len(node.args) == 1)

    def _resolve_join(self, node: ast.Call) -> str | None:
        sep = node.func.value.value
        arg = node.args[0]

        # Direct list: "".join(["a", "b", "c"])
        if isinstance(arg, ast.List):
            parts = []
            for elt in arg.elts:
                resolved = self._try_resolve(elt)
                if resolved is None:
                    return None
                parts.append(resolved)
            return sep.join(parts)

        # Variable reference: "".join(var) where var was assigned a list
        if isinstance(arg, ast.Name) and arg.id in self._vars:
            return self._vars[arg.id]

        return None

    # --- chr() resolution ---

    def _is_chr_call(self, node: ast.Call) -> bool:
        return (isinstance(node.func, ast.Name)
                and node.func.id == "chr"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, int))

    def _resolve_chr(self, node: ast.Call) -> str | None:
        code = node.args[0].value
        if 0 <= code <= 0x10FFFF:
            return chr(code)
        return None

    # --- bytes.fromhex().decode() resolution ---

    def _is_fromhex_decode(self, node: ast.Call) -> bool:
        """Check for bytes.fromhex("hex").decode() or similar chains."""
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "decode"):
            return False
        inner = node.func.value
        return (isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "fromhex"
                and len(inner.args) == 1
                and isinstance(inner.args[0], ast.Constant)
                and isinstance(inner.args[0].value, str))

    def _resolve_fromhex(self, node: ast.Call) -> str | None:
        inner = node.func.value
        hex_str = inner.args[0].value
        try:
            return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return None

    # --- String concatenation resolution ---

    def _resolve_concat(self, node: ast.BinOp) -> str | None:
        left = self._try_resolve(node.left)
        right = self._try_resolve(node.right)
        if left is not None and right is not None:
            return left + right
        return None

    # --- list("string") resolution ---

    def _is_list_call(self, node: ast.Call) -> bool:
        return (isinstance(node.func, ast.Name)
                and node.func.id == "list"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str))

    def _resolve_list_call(self, node: ast.Call) -> str | None:
        return node.args[0].value
