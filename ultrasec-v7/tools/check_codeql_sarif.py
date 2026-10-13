#!/usr/bin/env python3
"""Fail-closed quality gate for real CodeQL SARIF from the public verifier only."""
from __future__ import annotations

import json
import os
from pathlib import Path


def scan_sarif(directory: Path) -> dict[str, int]:
    if not directory.is_dir():
        raise ValueError("CodeQL SARIF output directory is missing")
    files = sorted(directory.rglob("*.sarif"))
    if not files:
        raise ValueError("No CodeQL SARIF files were produced; analysis cannot be called clean")

    runs_seen = 0
    blocking = 0
    informational = 0
    for filename in files:
        data = json.loads(filename.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != "2.1.0":
            raise ValueError("Invalid SARIF document")
        runs = data.get("runs")
        if not isinstance(runs, list) or not runs:
            raise ValueError("SARIF contains no analysis runs")
        for run in runs:
            if not isinstance(run, dict):
                raise ValueError("Invalid SARIF analysis run")
            runs_seen += 1
            results = run.get("results", [])
            if not isinstance(results, list):
                raise ValueError("Invalid SARIF results list")
            for finding in results:
                if not isinstance(finding, dict):
                    raise ValueError("Invalid SARIF finding")
                level = finding.get("level", "warning")
                if level in ("warning", "error"):
                    blocking += 1
                elif level in ("note", "none"):
                    informational += 1
                else:
                    raise ValueError("Unknown SARIF severity; cannot pass fail-closed gate")
    summary = {"scans": runs_seen, "blocking": blocking, "informational": informational}
    if blocking:
        raise ValueError(f"CodeQL reported {blocking} warning/error alerts in public Python code")
    return summary


if __name__ == "__main__":
    path = os.environ.get("CODEQL_SARIF_DIR", "")
    if not path:
        raise SystemExit("CODEQL_SARIF_DIR was not provided")
    try:
        report = scan_sarif(Path(path))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL CodeQL SARIF quality gate: {exc}") from exc
    print(f"PASS CodeQL public SARIF: {report['scans']} run(s), "
          f"0 blocking warning/error findings, {report['informational']} informational")
