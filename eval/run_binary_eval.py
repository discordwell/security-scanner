#!/usr/bin/env python3
"""Evaluate the binary scanner against labeled samples.

Usage:
    python eval/run_binary_eval.py                          # run all samples in manifest
    python eval/run_binary_eval.py --static-only            # skip sandbox
    python eval/run_binary_eval.py --max-samples 20         # limit sample count
    python eval/run_binary_eval.py --format pe              # filter by format
    python eval/run_binary_eval.py --output eval/results_binary.json

Reads samples from eval/samples/manifest.json, submits each to the scanner,
and records verdicts to eval/results_binary.json.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from security_scanner.config import Settings
from security_scanner.models import ExecutionPolicy
from security_scanner.repository import JsonRepository
from security_scanner.service import AnalysisService
from security_scanner.storage import LocalArtifactStore

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "results_binary.json"


async def run_sample(
    entry: dict,
    service: AnalysisService,
    policy: ExecutionPolicy,
) -> dict:
    """Submit a single sample and record the result."""
    label = entry["label"]
    sha256 = entry["sha256"]

    # Find sample file
    sample_path = SAMPLES_DIR / label / sha256
    if not sample_path.exists():
        return {"sha256": sha256, "label": label, "status": "missing", "verdict": None}

    data = sample_path.read_bytes()
    filename = entry.get("filename", f"{sha256[:12]}.bin")

    start = time.monotonic()
    try:
        result = await service.submit(
            filename=filename,
            data=data,
            policy=policy,
        )
        elapsed = time.monotonic() - start

        verdict = result.verdict
        observations = [
            {
                "source": obs.source,
                "category": obs.category,
                "severity": obs.severity.value,
                "message": obs.message[:200],
            }
            for obs in verdict.observations[:50]
        ]
        tool_runs = [
            {
                "tool": tr.tool,
                "status": tr.status.value,
                "summary": tr.summary[:200],
            }
            for tr in result.artifacts[0].tool_runs
        ]

        return {
            "sha256": sha256,
            "label": label,
            "status": "ok",
            "verdict": verdict.state.value,
            "summary": verdict.summary[:200],
            "reasons": verdict.reasons[:5],
            "observation_count": len(verdict.observations),
            "observations": observations,
            "tool_runs": tool_runs,
            "elapsed_seconds": round(elapsed, 2),
            "correct": (
                (label == "malicious" and verdict.state.value == "malicious")
                or (label == "benign" and verdict.state.value in ("clean", "inconclusive"))
            ),
        }
    except Exception as exc:
        elapsed = time.monotonic() - start
        return {
            "sha256": sha256,
            "label": label,
            "status": "error",
            "error": str(exc)[:200],
            "elapsed_seconds": round(elapsed, 2),
            "verdict": None,
            "correct": False,
        }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Run binary eval harness")
    parser.add_argument("--static-only", action="store_true", help="Disable dynamic analysis")
    parser.add_argument("--max-samples", type=int, default=0, help="Max samples to evaluate (0=all)")
    parser.add_argument("--format", type=str, default=None, help="Filter by format (pe, elf)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output results file")
    args = parser.parse_args()

    if not MANIFEST_PATH.exists():
        print(f"No manifest found at {MANIFEST_PATH}", file=sys.stderr)
        print("Run: python eval/download_samples.py --count 20 --add-benign 10", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(MANIFEST_PATH.read_text())
    if args.format:
        manifest = [e for e in manifest if e.get("format") == args.format]
    if args.max_samples:
        manifest = manifest[:args.max_samples]

    print(f"Evaluating {len(manifest)} samples...")

    policy = ExecutionPolicy(
        enable_dynamic_analysis=not args.static_only,
        enable_symbolic_execution=False,
    )

    # Create a fresh service with temp storage for eval
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp(prefix="eval_"))
    service = AnalysisService(
        repository=JsonRepository(tmp_dir / "state.json"),
        artifact_store=LocalArtifactStore(tmp_dir / "artifacts"),
    )

    results = []
    for i, entry in enumerate(manifest):
        label_tag = "MAL" if entry["label"] == "malicious" else "BEN"
        print(f"  [{i + 1}/{len(manifest)}] {label_tag} {entry['sha256'][:12]}...", end=" ", flush=True)
        result = await run_sample(entry, service, policy)
        results.append(result)

        status = result["status"]
        if status == "ok":
            verdict = result["verdict"]
            correct = "CORRECT" if result["correct"] else "WRONG"
            print(f"{verdict} ({correct}, {result['elapsed_seconds']}s)")
        elif status == "missing":
            print("MISSING")
        else:
            print(f"ERROR: {result.get('error', 'unknown')[:60]}")

    # Save results
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to {args.output}")

    # Quick summary
    ok = [r for r in results if r["status"] == "ok"]
    correct = sum(1 for r in ok if r["correct"])
    print(f"\nAccuracy: {correct}/{len(ok)} ({correct / len(ok) * 100:.1f}%)" if ok else "\nNo results.")


if __name__ == "__main__":
    asyncio.run(main())
