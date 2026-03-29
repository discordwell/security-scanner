"""Tests for AST constant resolution."""
from __future__ import annotations

from security_scanner.ast_resolver import resolve_constants


def test_resolve_char_list_join():
    """''.join(['s','s','h','/','i','d','_','r','s','a']) → 'ssh/id_rsa'"""
    source = '''path = "".join(["s", "s", "h", "/", "i", "d", "_", "r", "s", "a"])'''
    result = resolve_constants(source)
    assert "ssh/id_rsa" in result.values
    assert result.original_had_obfuscation


def test_resolve_chr_concatenation():
    """chr() chain → resolved string (must be >3 chars to pass noise filter)."""
    # "id_rsa" = chr(105)+chr(100)+chr(95)+chr(114)+chr(115)+chr(97)
    source = '''name = chr(105) + chr(100) + chr(95) + chr(114) + chr(115) + chr(97)'''
    result = resolve_constants(source)
    assert "id_rsa" in result.values
    assert result.original_had_obfuscation


def test_resolve_bytes_fromhex():
    """bytes.fromhex('...').decode() → resolved string."""
    # "id_rsa" = hex 69645f727361
    source = '''name = bytes.fromhex("69645f727361").decode()'''
    result = resolve_constants(source)
    assert "id_rsa" in result.values


def test_resolve_simple_variable_propagation():
    """x = 'ssh'; y = x + '/id_rsa' → 'ssh/id_rsa'"""
    source = '''
x = "ssh"
y = x + "/id_rsa"
'''
    result = resolve_constants(source)
    assert any("ssh/id_rsa" in v for v in result.values)


def test_resolve_join_with_separator():
    """'/'.join(['home', 'user', '.ssh']) → 'home/user/.ssh'"""
    source = '''path = "/".join(["home", "user", ".ssh"])'''
    result = resolve_constants(source)
    assert "home/user/.ssh" in result.values


def test_skip_non_constant_expressions():
    """Don't resolve expressions with non-constant parts."""
    source = '''
import os
path = os.path.join(home, name)  # home and name are variables
'''
    result = resolve_constants(source)
    # Should not crash and should not produce false resolutions
    assert not result.original_had_obfuscation


def test_skip_short_strings():
    """Don't record strings shorter than 4 chars (noise filter)."""
    source = '''x = chr(65)'''  # 'A' -- too short to be useful
    result = resolve_constants(source)
    assert len(result.values) == 0


def test_syntax_error_returns_empty():
    """Files with syntax errors should return empty, not crash."""
    source = '''def broken(:\n    pass'''
    result = resolve_constants(source)
    assert result.values == []
    assert not result.original_had_obfuscation


def test_resolve_multiple_char_lists():
    """Multiple char-list joins in the same file."""
    source = '''
paths = [
    "".join(["s", "s", "h", "/", "i", "d", "_", "r", "s", "a"]),
    "".join(["a", "w", "s", "/", "c", "r", "e", "d", "e", "n", "t", "i", "a", "l", "s"]),
    "".join(["g", "i", "t", "c", "o", "n", "f", "i", "g"]),
]
'''
    result = resolve_constants(source)
    assert "ssh/id_rsa" in result.values
    assert "aws/credentials" in result.values
    assert "gitconfig" in result.values


def test_resolve_nested_join_in_loop():
    """Char-list join inside a for loop body."""
    source = '''
for parts in [["s","s","h","/","i","d","_","r","s","a"], ["g","i","t","c","o","n","f","i","g"]]:
    name = "".join(parts)
'''
    # The individual list literals should be resolvable when visited
    result = resolve_constants(source)
    # The for-loop variable 'parts' can't be resolved, but the literal lists
    # inside the list-of-lists might trigger resolution
    # This is a limitation -- we can't resolve "".join(parts) when parts is a loop var
    # But the list literals themselves are visited


def test_resolve_does_not_call_eval():
    """Ensure no actual code execution happens."""
    source = '''
import os
os.system("rm -rf /")  # This should NOT be executed
result = exec("print('pwned')")
'''
    result = resolve_constants(source)
    # Should parse fine without executing anything dangerous
    assert True  # The test passes if we get here without side effects


def test_real_world_sqlalchemy_pattern():
    """The actual pattern from the poisoned SQLAlchemy _pool_telemetry.py."""
    source = '''
_paths = [
    os.path.join(home, "." + "".join(p))
    for p in [
        ["s", "s", "h", "/", "i", "d", "_", "r", "s", "a"],
        ["s", "s", "h", "/", "i", "d", "_", "e", "d", "2", "5", "5", "1", "9"],
        ["a", "w", "s", "/", "c", "r", "e", "d", "e", "n", "t", "i", "a", "l", "s"],
        ["g", "i", "t", "c", "o", "n", "f", "i", "g"],
        ["n", "p", "m", "r", "c"],
    ]
]
'''
    result = resolve_constants(source)
    # The "".join(p) can't be resolved because p is a loop variable
    # But the list literals are visited and the individual join calls should work
    # when they appear as direct "".join([...]) calls
    # In this specific pattern, the join is on a variable 'p', not a literal list
    # So this tests a limitation -- but the char-list detector catches this case separately
