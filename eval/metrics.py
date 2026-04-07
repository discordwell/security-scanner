#!/usr/bin/env python3
"""Compute precision, recall, F1, and confusion matrix from eval results.

Usage:
    python eval/metrics.py                              # read results_binary.json
    python eval/metrics.py --input eval/results_binary.json
    python eval/metrics.py --save eval/report.md        # save markdown report
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DEFAULT_INPUT = Path(__file__).resolve().parent / "results_binary.json"


def compute_metrics(results: list[dict]) -> dict:
    """Compute classification metrics from eval results.

    Ground truth labels: 'malicious', 'benign'
    Scanner verdicts mapped to binary: malicious → positive, everything else → negative
    """
    ok = [r for r in results if r["status"] == "ok" and r["verdict"] is not None]
    if not ok:
        return {"error": "No valid results to compute metrics from"}

    # Binary classification: malicious = positive
    tp = fp = tn = fn = 0
    for r in ok:
        predicted_positive = r["verdict"] == "malicious"
        actual_positive = r["label"] == "malicious"

        if actual_positive and predicted_positive:
            tp += 1
        elif actual_positive and not predicted_positive:
            fn += 1
        elif not actual_positive and predicted_positive:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    # Verdict distribution
    verdict_counts = Counter(r["verdict"] for r in ok)
    label_counts = Counter(r["label"] for r in ok)

    # Tool contribution
    tool_findings: Counter = Counter()
    for r in ok:
        if r["verdict"] == "malicious":
            for obs in r.get("observations", []):
                if obs["severity"] in ("high", "critical"):
                    tool_findings[obs["source"]] += 1

    # Errors and missing
    errors = [r for r in results if r["status"] == "error"]
    missing = [r for r in results if r["status"] == "missing"]

    return {
        "total_samples": len(results),
        "evaluated": len(ok),
        "errors": len(errors),
        "missing": len(missing),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "verdict_distribution": dict(verdict_counts),
        "label_distribution": dict(label_counts),
        "tool_contributions": dict(tool_findings.most_common(10)),
    }


def format_report(metrics: dict) -> str:
    """Format metrics as a readable report."""
    if "error" in metrics:
        return f"Error: {metrics['error']}"

    cm = metrics["confusion_matrix"]
    lines = [
        "# Binary Eval Report",
        "",
        "## Summary",
        f"- Samples: {metrics['total_samples']} total, {metrics['evaluated']} evaluated, {metrics['errors']} errors, {metrics['missing']} missing",
        "",
        "## Classification Metrics",
        f"- **Accuracy**: {metrics['accuracy']:.1%}",
        f"- **Precision**: {metrics['precision']:.1%}",
        f"- **Recall**: {metrics['recall']:.1%}",
        f"- **F1 Score**: {metrics['f1']:.1%}",
        "",
        "## Confusion Matrix",
        "```",
        "                 Predicted",
        "              MAL      BEN",
        f"Actual MAL   {cm['tp']:4d}     {cm['fn']:4d}",
        f"       BEN   {cm['fp']:4d}     {cm['tn']:4d}",
        "```",
        "",
        "## Verdict Distribution",
    ]
    for verdict, count in sorted(metrics["verdict_distribution"].items()):
        lines.append(f"- {verdict}: {count}")

    lines.append("")
    lines.append("## Tool Contributions (HIGH/CRITICAL findings in MALICIOUS verdicts)")
    for tool, count in metrics.get("tool_contributions", {}).items():
        lines.append(f"- {tool}: {count}")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute eval metrics")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Results JSON file")
    parser.add_argument("--save", type=Path, default=None, help="Save report to markdown file")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of report")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"No results file at {args.input}", file=sys.stderr)
        print("Run: python eval/run_binary_eval.py --static-only", file=sys.stderr)
        sys.exit(1)

    results = json.loads(args.input.read_text())
    metrics = compute_metrics(results)

    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        report = format_report(metrics)
        print(report)

        if args.save:
            args.save.write_text(report)
            print(f"\nReport saved to {args.save}")


if __name__ == "__main__":
    main()
