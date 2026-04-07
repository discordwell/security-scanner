"""Tests for the binary eval harness (metrics computation and manifest handling)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure eval scripts are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from metrics import compute_metrics, format_report


# -- compute_metrics --


def test_metrics_perfect_classification():
    results = [
        {"status": "ok", "label": "malicious", "verdict": "malicious", "observations": [], "correct": True},
        {"status": "ok", "label": "malicious", "verdict": "malicious", "observations": [], "correct": True},
        {"status": "ok", "label": "benign", "verdict": "clean", "observations": [], "correct": True},
        {"status": "ok", "label": "benign", "verdict": "clean", "observations": [], "correct": True},
    ]
    m = compute_metrics(results)
    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["confusion_matrix"] == {"tp": 2, "fp": 0, "tn": 2, "fn": 0}


def test_metrics_all_false_negatives():
    results = [
        {"status": "ok", "label": "malicious", "verdict": "clean", "observations": [], "correct": False},
        {"status": "ok", "label": "malicious", "verdict": "inconclusive", "observations": [], "correct": False},
    ]
    m = compute_metrics(results)
    assert m["recall"] == 0.0
    assert m["confusion_matrix"]["fn"] == 2
    assert m["confusion_matrix"]["tp"] == 0


def test_metrics_all_false_positives():
    results = [
        {"status": "ok", "label": "benign", "verdict": "malicious", "observations": [], "correct": False},
        {"status": "ok", "label": "benign", "verdict": "malicious", "observations": [], "correct": False},
    ]
    m = compute_metrics(results)
    assert m["precision"] == 0.0
    assert m["confusion_matrix"]["fp"] == 2


def test_metrics_mixed():
    results = [
        {"status": "ok", "label": "malicious", "verdict": "malicious", "observations": [], "correct": True},
        {"status": "ok", "label": "malicious", "verdict": "suspicious", "observations": [], "correct": False},
        {"status": "ok", "label": "benign", "verdict": "clean", "observations": [], "correct": True},
        {"status": "ok", "label": "benign", "verdict": "malicious", "observations": [], "correct": False},
    ]
    m = compute_metrics(results)
    assert m["confusion_matrix"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert m["accuracy"] == 0.5
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5


def test_metrics_skips_errors_and_missing():
    results = [
        {"status": "ok", "label": "malicious", "verdict": "malicious", "observations": [], "correct": True},
        {"status": "error", "label": "malicious", "verdict": None, "correct": False},
        {"status": "missing", "label": "benign", "verdict": None, "correct": False},
    ]
    m = compute_metrics(results)
    assert m["evaluated"] == 1
    assert m["errors"] == 1
    assert m["missing"] == 1
    assert m["accuracy"] == 1.0


def test_metrics_empty_results():
    m = compute_metrics([])
    assert "error" in m


def test_metrics_tool_contributions():
    results = [
        {
            "status": "ok",
            "label": "malicious",
            "verdict": "malicious",
            "observations": [
                {"source": "yara", "severity": "high", "category": "test", "message": "match"},
                {"source": "ember", "severity": "high", "category": "test", "message": "score"},
                {"source": "ember", "severity": "medium", "category": "test", "message": "low score"},
            ],
            "correct": True,
        },
    ]
    m = compute_metrics(results)
    assert m["tool_contributions"]["yara"] == 1
    assert m["tool_contributions"]["ember"] == 1  # Only HIGH counted


def test_metrics_verdict_distribution():
    results = [
        {"status": "ok", "label": "malicious", "verdict": "malicious", "observations": []},
        {"status": "ok", "label": "malicious", "verdict": "suspicious", "observations": []},
        {"status": "ok", "label": "benign", "verdict": "clean", "observations": []},
    ]
    m = compute_metrics(results)
    assert m["verdict_distribution"] == {"malicious": 1, "suspicious": 1, "clean": 1}


# -- format_report --


def test_format_report_produces_markdown():
    results = [
        {"status": "ok", "label": "malicious", "verdict": "malicious", "observations": [], "correct": True},
        {"status": "ok", "label": "benign", "verdict": "clean", "observations": [], "correct": True},
    ]
    m = compute_metrics(results)
    report = format_report(m)
    assert "# Binary Eval Report" in report
    assert "Accuracy" in report
    assert "Confusion Matrix" in report
    assert "100.0%" in report
