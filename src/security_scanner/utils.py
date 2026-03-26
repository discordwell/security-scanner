from __future__ import annotations

import gzip
import hashlib
import io
import logging
import math
import re
import struct
import tarfile
import zlib
import zipfile
from pathlib import Path

from .models import ArtifactFormat

logger = logging.getLogger(__name__)

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")

SUSPICIOUS_PATTERNS: dict[bytes, tuple[str, str]] = {
    b"CreateRemoteThread": ("process_injection", "Windows remote thread creation"),
    b"WriteProcessMemory": ("process_injection", "Cross-process memory write"),
    b"VirtualAlloc": ("memory_exec", "Executable memory allocation"),
    b"NtMapViewOfSection": ("memory_exec", "Section mapping"),
    b"LoadLibrary": ("module_load", "Dynamic library load"),
    b"WinExec": ("exec", "Process launch"),
    b"ShellExecute": ("exec", "Shell execution"),
    b"powershell": ("script_exec", "PowerShell reference"),
    b"cmd.exe": ("script_exec", "Command shell reference"),
    b"http://": ("network", "Plain HTTP string"),
    b"https://": ("network", "HTTPS string"),
    b"socket": ("network", "Socket reference"),
    b"curl": ("network", "Curl reference"),
    b"dlopen": ("module_load", "POSIX dynamic library load"),
    b"ptrace": ("anti_analysis", "Debugger detection"),
    b"mach_vm_write": ("memory_exec", "Mach VM write"),
}

# PyInstaller archive magic (COOKIE)
_PYINST_MAGIC = b"MEI\014\013\012\013\016"
# Cookie struct: magic(8) + package_len(4) + toc_offset(4) + toc_len(4) + pyver(4) + pylib(64)
_PYINST_COOKIE_LEN = 88
# TOC entry: entry_len(4) + data_offset(4) + data_len(4) + compress(1) + typecode(1) + name(variable)
_PYINST_TOC_HEADER = struct.Struct("!IIIbb")


def hash_bytes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.sha256(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    size = len(data)
    for count in counts:
        if count == 0:
            continue
        probability = count / size
        entropy -= probability * math.log2(probability)
    return entropy


def extract_strings(data: bytes, limit: int) -> list[str]:
    strings = [match.decode("utf-8", errors="replace") for match in PRINTABLE_RE.findall(data)]
    return strings[:limit]


def detect_format(filename: str, data: bytes) -> ArtifactFormat:
    lower_name = filename.lower()
    if data.startswith(b"MZ"):
        return ArtifactFormat.PE
    if data.startswith(b"\x7fELF"):
        return ArtifactFormat.ELF
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
        return ArtifactFormat.MACH_O
    if data.startswith(b"PK\x03\x04") and not lower_name.endswith((".dll", ".pyd", ".exe", ".so")):
        return ArtifactFormat.ZIP
    if lower_name.endswith(".zip") and not data.startswith(b"MZ"):
        return ArtifactFormat.ZIP
    if _is_tar_archive(data):
        return ArtifactFormat.TAR
    if data.startswith(b"\x1f\x8b") or lower_name.endswith(".gz"):
        return ArtifactFormat.GZIP
    return ArtifactFormat.UNKNOWN


def _is_tar_archive(data: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data)):
            return True
    except tarfile.TarError:
        return False


def is_pyinstaller(data: bytes) -> bool:
    """Check if a PE contains an embedded PyInstaller archive."""
    return data.rfind(_PYINST_MAGIC) != -1


def _extract_pyinstaller(data: bytes, max_total_bytes: int) -> list[tuple[str, bytes]]:
    """Extract files from a PyInstaller CArchive embedded in a PE."""
    magic_offset = data.rfind(_PYINST_MAGIC)
    if magic_offset == -1:
        return []

    # Parse the cookie
    cookie_start = magic_offset
    if cookie_start + _PYINST_COOKIE_LEN > len(data):
        return []

    cookie = data[cookie_start : cookie_start + _PYINST_COOKIE_LEN]
    # magic(8) + pkg_len(4) + toc_offset(4) + toc_len(4) + pyver(4) + pylib(64)
    pkg_len = struct.unpack("!I", cookie[8:12])[0]
    toc_offset = struct.unpack("!I", cookie[12:16])[0]
    toc_len = struct.unpack("!I", cookie[16:20])[0]
    pyver = struct.unpack("!I", cookie[20:24])[0]

    # The package starts at (cookie_end - pkg_len)
    pkg_end = cookie_start + _PYINST_COOKIE_LEN
    pkg_start = pkg_end - pkg_len

    if pkg_start < 0 or toc_offset > pkg_len:
        return []

    abs_toc = pkg_start + toc_offset

    extracted: list[tuple[str, bytes]] = []
    total_bytes = 0
    pos = abs_toc

    while pos < abs_toc + toc_len and pos + _PYINST_TOC_HEADER.size <= len(data):
        entry_len, data_offset, data_len, compress, typecode = _PYINST_TOC_HEADER.unpack_from(data, pos)

        if entry_len < _PYINST_TOC_HEADER.size or entry_len > 4096:
            break

        name_bytes = data[pos + _PYINST_TOC_HEADER.size : pos + entry_len]
        name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
        if not name:
            name = f"entry_{len(extracted)}"

        abs_data_offset = pkg_start + data_offset

        if abs_data_offset + data_len <= len(data) and data_len > 0:
            raw = data[abs_data_offset : abs_data_offset + data_len]
            if compress == 1:
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    pass

            total_bytes += len(raw)
            if total_bytes > max_total_bytes:
                break

            # Skip tiny entries and the manifest/cookie itself
            if len(raw) > 16:
                extracted.append((_sanitize_member_name(name), raw))

        pos += entry_len

    logger.info("PyInstaller: extracted %d files (pyver=%d)", len(extracted), pyver)
    return extracted


def chunk_hashes(data: bytes, chunk_size: int = 4096) -> list[str]:
    if not data:
        return []
    hashes: list[str] = []
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset : offset + chunk_size]
        hashes.append(hashlib.sha256(chunk).hexdigest())
    return hashes


def find_suspicious_matches(data: bytes) -> list[tuple[int, bytes, str, str]]:
    matches: list[tuple[int, bytes, str, str]] = []
    lowered = data.lower()
    for needle, (category, message) in SUSPICIOUS_PATTERNS.items():
        if needle.islower():
            search_source = lowered
            search_needle = needle
        else:
            search_source = data
            search_needle = needle
        index = search_source.find(search_needle)
        while index != -1:
            matches.append((index, needle, category, message))
            index = search_source.find(search_needle, index + 1)
    matches.sort(key=lambda match: match[0])
    return matches


MAX_EXTRACT_BYTES = 512 * 1024 * 1024  # 512 MB total extraction limit


def _sanitize_member_name(name: str) -> str:
    parts = Path(name).parts
    safe_parts = [p for p in parts if p not in ("..", ".") and not p.startswith("/")]
    return str(Path(*safe_parts)) if safe_parts else "extracted"


def maybe_extract_archive(
    filename: str, data: bytes, max_total_bytes: int = MAX_EXTRACT_BYTES,
) -> list[tuple[str, bytes]]:
    extracted: list[tuple[str, bytes]] = []
    total_bytes = 0
    file_format = detect_format(filename, data)

    # Check for PyInstaller inside PE/ELF binaries
    if file_format in (ArtifactFormat.PE, ArtifactFormat.ELF) and is_pyinstaller(data):
        return _extract_pyinstaller(data, max_total_bytes)

    if file_format == ArtifactFormat.ZIP:
        try:
            archive_obj = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return extracted
        with archive_obj as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                content = archive.read(member)
                total_bytes += len(content)
                if total_bytes > max_total_bytes:
                    break
                extracted.append((_sanitize_member_name(member.filename), content))
    elif file_format == ArtifactFormat.TAR:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                content = handle.read()
                total_bytes += len(content)
                if total_bytes > max_total_bytes:
                    break
                extracted.append((_sanitize_member_name(member.name), content))
    elif file_format == ArtifactFormat.GZIP:
        name = Path(filename).stem or "unpacked"
        extracted.append((name, gzip.decompress(data)))
    return extracted
