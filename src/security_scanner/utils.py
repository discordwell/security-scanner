from __future__ import annotations

import gzip
import hashlib
import io
import math
import re
import tarfile
import zipfile
from pathlib import Path

from .models import ArtifactFormat

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
    if data.startswith(b"PK\x03\x04") or lower_name.endswith(".zip"):
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
    if file_format == ArtifactFormat.ZIP:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
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
