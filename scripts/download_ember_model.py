#!/usr/bin/env python3
"""Download a pre-trained EMBER LightGBM model for binary malware classification.

Usage:
    python scripts/download_ember_model.py [--output PATH] [--skip-verify]

The model is downloaded from the EMBER2024 HuggingFace repository and saved
to data/models/ember_lgbm.txt by default.  Override with SCANNER_EMBER_MODEL_PATH
or the --output flag.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from urllib.request import urlretrieve

MODEL_URL = (
    "https://huggingface.co/joyce8/EMBER2024-benchmark-models"
    "/resolve/main/lightgbm_model.txt"
)

# Expected SHA-256 of the model file.  Update this when pinning a new version.
# Set to None to skip verification (not recommended).
EXPECTED_SHA256: str | None = None

DEFAULT_OUTPUT = Path("data/models/ember_lgbm.txt")


def download(url: str, dest: Path, *, skip_verify: bool = False) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading EMBER model to {dest} ...")

    def _progress(block: int, block_size: int, total: int) -> None:
        pct = block * block_size * 100 // max(total, 1)
        print(f"\r  {min(pct, 100)}%", end="", flush=True)

    urlretrieve(url, dest, reporthook=_progress)
    print()

    sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    print(f"SHA-256: {sha}")

    if not skip_verify and EXPECTED_SHA256 is not None:
        if sha != EXPECTED_SHA256:
            dest.unlink()
            print(
                f"ERROR: Hash mismatch!\n"
                f"  Expected: {EXPECTED_SHA256}\n"
                f"  Got:      {sha}\n"
                f"Downloaded file deleted. Use --skip-verify to bypass.",
                file=sys.stderr,
            )
            sys.exit(1)
        print("Integrity verified.")
    elif EXPECTED_SHA256 is None:
        print(
            "WARNING: No expected hash configured. Pin the hash in this script\n"
            f"  after verifying the model: EXPECTED_SHA256 = \"{sha}\""
        )

    print(f"Model saved to {dest} ({dest.stat().st_size:,} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download EMBER LightGBM model")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.environ.get("SCANNER_EMBER_MODEL_PATH", str(DEFAULT_OUTPUT))),
        help="Destination path for the model file",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip SHA-256 integrity verification",
    )
    args = parser.parse_args()

    if args.output.is_file():
        print(f"Model already exists at {args.output}")
        resp = input("Overwrite? [y/N] ").strip().lower()
        if resp != "y":
            sys.exit(0)

    download(MODEL_URL, args.output, skip_verify=args.skip_verify)
    print("\nTo use a custom path, set SCANNER_EMBER_MODEL_PATH in your environment.")


if __name__ == "__main__":
    main()
