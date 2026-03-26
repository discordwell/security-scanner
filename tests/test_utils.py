from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import zipfile

from security_scanner.models import ArtifactFormat
from security_scanner.utils import (
    calculate_entropy,
    chunk_hashes,
    detect_format,
    extract_strings,
    find_suspicious_matches,
    hash_bytes,
    maybe_extract_archive,
    sha256_text,
)


# -- hash_bytes --

def test_hash_bytes_returns_correct_triple():
    data = b"hello world"
    sha256, sha1, md5 = hash_bytes(data)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert sha1 == hashlib.sha1(data).hexdigest()
    assert md5 == hashlib.md5(data).hexdigest()


def test_hash_bytes_empty():
    sha256, sha1, md5 = hash_bytes(b"")
    assert sha256 == hashlib.sha256(b"").hexdigest()


# -- sha256_text --

def test_sha256_text():
    result = sha256_text("test")
    assert result == hashlib.sha256(b"test").hexdigest()


# -- calculate_entropy --

def test_calculate_entropy_empty_data():
    assert calculate_entropy(b"") == 0.0


def test_calculate_entropy_single_byte_repeated():
    assert calculate_entropy(b"\x00" * 1000) == 0.0


def test_calculate_entropy_two_values():
    data = b"\x00\x01" * 500
    entropy = calculate_entropy(data)
    assert abs(entropy - 1.0) < 0.01


def test_calculate_entropy_high_for_random_like_data():
    data = bytes(range(256)) * 4
    entropy = calculate_entropy(data)
    assert entropy > 7.9


# -- extract_strings --

def test_extract_strings_finds_printable_sequences():
    data = b"\x00\x00Hello World\x00\x00"
    result = extract_strings(data, limit=100)
    assert "Hello World" in result


def test_extract_strings_ignores_short_sequences():
    data = b"\x00ab\x00"
    result = extract_strings(data, limit=100)
    assert result == []


def test_extract_strings_respects_limit():
    data = b"aaaa\x00bbbb\x00cccc\x00dddd"
    result = extract_strings(data, limit=2)
    assert len(result) == 2


# -- detect_format --

def test_detect_format_pe():
    assert detect_format("test.exe", b"MZ" + b"\x00" * 100) == ArtifactFormat.PE


def test_detect_format_elf():
    assert detect_format("test", b"\x7fELF" + b"\x00" * 100) == ArtifactFormat.ELF


def test_detect_format_mach_o_le():
    assert detect_format("test", b"\xcf\xfa\xed\xfe" + b"\x00" * 100) == ArtifactFormat.MACH_O


def test_detect_format_mach_o_be():
    assert detect_format("test", b"\xfe\xed\xfa\xce" + b"\x00" * 100) == ArtifactFormat.MACH_O


def test_detect_format_mach_o_fat():
    assert detect_format("test", b"\xca\xfe\xba\xbe" + b"\x00" * 100) == ArtifactFormat.MACH_O


def test_detect_format_zip_by_magic():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("test.txt", "content")
    assert detect_format("archive.zip", buf.getvalue()) == ArtifactFormat.ZIP


def test_detect_format_zip_by_extension():
    assert detect_format("archive.zip", b"\x00" * 100) == ArtifactFormat.ZIP


def test_detect_format_gzip():
    data = gzip.compress(b"hello")
    assert detect_format("test.gz", data) == ArtifactFormat.GZIP


def test_detect_format_tar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="test.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"data"))
    assert detect_format("archive.tar", buf.getvalue()) == ArtifactFormat.TAR


def test_detect_format_unknown():
    assert detect_format("test.bin", b"\x00\x01\x02\x03") == ArtifactFormat.UNKNOWN


# -- chunk_hashes --

def test_chunk_hashes_empty_data():
    assert chunk_hashes(b"") == []


def test_chunk_hashes_single_chunk():
    data = b"A" * 100
    result = chunk_hashes(data)
    assert len(result) == 1
    assert result[0] == hashlib.sha256(data).hexdigest()


def test_chunk_hashes_multiple_chunks():
    data = b"A" * 4096 + b"B" * 4096
    result = chunk_hashes(data, chunk_size=4096)
    assert len(result) == 2
    assert result[0] != result[1]


def test_chunk_hashes_deterministic():
    data = b"reproducible content"
    assert chunk_hashes(data) == chunk_hashes(data)


# -- find_suspicious_matches --

def test_find_suspicious_matches_detects_known_patterns():
    data = b"\x00" * 10 + b"CreateRemoteThread" + b"\x00" * 10
    matches = find_suspicious_matches(data)
    assert len(matches) >= 1
    offsets = [m[0] for m in matches]
    assert 10 in offsets


def test_find_suspicious_matches_case_insensitive_for_lowercase_patterns():
    data = b"POWERSHELL is here"
    matches = find_suspicious_matches(data)
    categories = [m[2] for m in matches]
    assert "script_exec" in categories


def test_find_suspicious_matches_returns_sorted_by_offset():
    data = b"VirtualAlloc" + b"\x00" * 100 + b"CreateRemoteThread"
    matches = find_suspicious_matches(data)
    offsets = [m[0] for m in matches]
    assert offsets == sorted(offsets)


def test_find_suspicious_matches_no_matches():
    data = b"nothing suspicious here at all"
    matches = find_suspicious_matches(data)
    assert matches == []


# -- maybe_extract_archive --

def test_maybe_extract_archive_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.txt", "hello")
    result = maybe_extract_archive("test.zip", buf.getvalue())
    assert len(result) == 1
    assert result[0][0] == "inner.txt"
    assert result[0][1] == b"hello"


def test_maybe_extract_archive_tar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="inner.txt")
        content = b"hello"
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    result = maybe_extract_archive("test.tar", buf.getvalue())
    assert len(result) == 1
    assert result[0][0] == "inner.txt"
    assert result[0][1] == b"hello"


def test_maybe_extract_archive_gzip():
    compressed = gzip.compress(b"hello world")
    result = maybe_extract_archive("data.bin.gz", compressed)
    assert len(result) == 1
    assert result[0][0] == "data.bin"
    assert result[0][1] == b"hello world"


def test_maybe_extract_archive_non_archive():
    result = maybe_extract_archive("binary.exe", b"MZ" + b"\x00" * 100)
    assert result == []


def test_maybe_extract_archive_empty_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    result = maybe_extract_archive("empty.zip", buf.getvalue())
    assert result == []


def test_maybe_extract_archive_zip_bomb_stops_at_limit():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("big1.bin", b"A" * 1000)
        zf.writestr("big2.bin", b"B" * 1000)
        zf.writestr("big3.bin", b"C" * 1000)
    result = maybe_extract_archive("bomb.zip", buf.getvalue(), max_total_bytes=1500)
    assert len(result) == 1


def test_maybe_extract_archive_tar_path_traversal_sanitized():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="../../etc/passwd")
        content = b"malicious"
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    result = maybe_extract_archive("evil.tar", buf.getvalue())
    assert len(result) == 1
    name, _ = result[0]
    assert ".." not in name
    assert not name.startswith("/")


def test_is_pyinstaller_detects_magic():
    from security_scanner.utils import is_pyinstaller, _PYINST_MAGIC
    # Simulate a PE with PyInstaller magic near the end
    fake_pe = b"MZ" + b"\x00" * 1000 + _PYINST_MAGIC + b"\x00" * 80
    assert is_pyinstaller(fake_pe) is True


def test_is_pyinstaller_false_for_normal_pe():
    from security_scanner.utils import is_pyinstaller
    normal_pe = b"MZ" + b"\x00" * 1000
    assert is_pyinstaller(normal_pe) is False


def test_maybe_extract_archive_zip_with_directories():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dir/", "")
        zf.writestr("dir/file.txt", "content")
    result = maybe_extract_archive("test.zip", buf.getvalue())
    assert len(result) == 1
    assert result[0][0] == "dir/file.txt"
