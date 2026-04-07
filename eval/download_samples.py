#!/usr/bin/env python3
"""Download labeled malware samples from MalwareBazaar for evaluation.

Usage:
    python eval/download_samples.py                         # download 50 recent PE samples
    python eval/download_samples.py --count 100 --tag trojan
    python eval/download_samples.py --count 20 --format elf
    python eval/download_samples.py --add-benign 20         # generate synthetic benign PEs

Samples are saved to eval/samples/{malicious,benign}/ with a manifest at
eval/samples/manifest.json tracking SHA256, label, source, and tags.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"


def query_bazaar(tag: str | None, file_type: str, limit: int) -> list[dict]:
    """Query MalwareBazaar for recent samples."""
    if tag:
        data = f"query=get_taginfo&tag={tag}&limit={limit}"
    else:
        data = f"query=get_recent&selector={limit}"

    req = Request(BAZAAR_API, data=data.encode(), method="POST")
    req.add_header("API-KEY", os.environ.get("MALWARE_BAZAAR_API_KEY", ""))
    resp = urlopen(req, timeout=30)
    result = json.loads(resp.read())

    if result.get("query_status") != "ok":
        print(f"MalwareBazaar query failed: {result.get('query_status')}", file=sys.stderr)
        return []

    samples = result.get("data", [])
    # Filter by file type
    type_map = {"pe": "exe", "elf": "elf", "apk": "apk", "doc": "doc"}
    target_type = type_map.get(file_type, file_type)
    filtered = [s for s in samples if target_type in s.get("file_type", "").lower()]
    return filtered[:limit]


def download_sample(sha256: str, dest: Path) -> bool:
    """Download a sample from MalwareBazaar by SHA256.

    MalwareBazaar returns samples as password-protected ZIP (password: 'infected').
    """
    data = f"query=get_file&sha256_hash={sha256}"
    req = Request(BAZAAR_API, data=data.encode(), method="POST")
    req.add_header("API-KEY", os.environ.get("MALWARE_BAZAAR_API_KEY", ""))

    try:
        resp = urlopen(req, timeout=60)
        content = resp.read()

        # MalwareBazaar returns a ZIP file, not JSON
        if content[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                for name in zf.namelist():
                    sample_data = zf.read(name, pwd=b"infected")
                    dest.write_bytes(sample_data)
                    return True
        else:
            # Might be an error response
            try:
                err = json.loads(content)
                print(f"  Error for {sha256[:12]}: {err.get('query_status')}", file=sys.stderr)
            except json.JSONDecodeError:
                pass
            return False
    except Exception as exc:
        print(f"  Download failed for {sha256[:12]}: {exc}", file=sys.stderr)
        return False


def generate_benign_pe(index: int) -> tuple[bytes, str]:
    """Generate a synthetic benign PE-like file."""
    # Minimal valid-looking PE with benign content
    content = (
        b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00"  # DOS header
        + b"\x00" * 64  # DOS stub
        + b"PE\x00\x00"  # PE signature
        + b"\x4c\x01"  # Machine: i386
        + b"\x01\x00"  # Number of sections: 1
        + bytes(f"BenignTestBinary_{index:04d}".encode())
        + b"\x00" * 256
        + bytes(f"This is a benign test file #{index}".encode())
        + b"\x00" * 512
    )
    sha = hashlib.sha256(content).hexdigest()
    return content, sha


def load_manifest() -> list[dict]:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text())
    return []


def save_manifest(entries: list[dict]) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(entries, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Download malware samples for evaluation")
    parser.add_argument("--count", type=int, default=50, help="Number of malicious samples")
    parser.add_argument("--tag", type=str, default=None, help="MalwareBazaar tag filter")
    parser.add_argument("--format", type=str, default="pe", choices=["pe", "elf", "apk"], help="File format")
    parser.add_argument("--add-benign", type=int, default=0, help="Number of synthetic benign samples to generate")
    args = parser.parse_args()

    manifest = load_manifest()
    existing_hashes = {e["sha256"] for e in manifest}

    # Download malicious samples
    mal_dir = SAMPLES_DIR / "malicious"
    mal_dir.mkdir(parents=True, exist_ok=True)

    print(f"Querying MalwareBazaar for {args.count} {args.format} samples" + (f" (tag={args.tag})" if args.tag else "") + "...")
    samples = query_bazaar(args.tag, args.format, args.count)
    print(f"  Found {len(samples)} matching samples")

    downloaded = 0
    for sample in samples:
        sha = sample["sha256_hash"]
        if sha in existing_hashes:
            continue

        dest = mal_dir / sha
        print(f"  Downloading {sha[:12]}...", end=" ")
        if download_sample(sha, dest):
            manifest.append({
                "sha256": sha,
                "label": "malicious",
                "source": "malwarebazaar",
                "filename": sample.get("file_name", "unknown"),
                "file_type": sample.get("file_type", "unknown"),
                "tags": sample.get("tags", []),
                "format": args.format,
            })
            existing_hashes.add(sha)
            downloaded += 1
            print("OK")
        else:
            print("FAILED")

    print(f"Downloaded {downloaded} malicious samples")

    # Generate benign samples
    if args.add_benign > 0:
        benign_dir = SAMPLES_DIR / "benign"
        benign_dir.mkdir(parents=True, exist_ok=True)

        generated = 0
        for i in range(args.add_benign):
            content, sha = generate_benign_pe(i)
            if sha in existing_hashes:
                continue
            dest = benign_dir / sha
            dest.write_bytes(content)
            manifest.append({
                "sha256": sha,
                "label": "benign",
                "source": "synthetic",
                "filename": f"benign_{i:04d}.exe",
                "file_type": "exe",
                "tags": [],
                "format": "pe",
            })
            existing_hashes.add(sha)
            generated += 1
        print(f"Generated {generated} benign samples")

    save_manifest(manifest)
    print(f"\nManifest: {MANIFEST_PATH} ({len(manifest)} total entries)")


if __name__ == "__main__":
    main()
