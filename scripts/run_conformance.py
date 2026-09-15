#!/usr/bin/env python3
"""Run the exact PCP cases listed in the conformance manifest."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "conformance" / "manifest.json"
MANIFEST_SCHEMA_PATH = ROOT / "conformance" / "manifest.schema.json"


def load_manifest() -> tuple[dict[str, object], str]:
    raw = MANIFEST_PATH.read_bytes()
    manifest = json.loads(raw)
    schema = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)
    cases = manifest["cases"]
    if manifest["expected_case_count"] != len(cases):
        raise ValueError("expected_case_count does not equal manifest case length")
    ids = [case["id"] for case in cases]
    tests = [case["test"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("manifest case ids must be unique")
    if len(tests) != len(set(tests)):
        raise ValueError("manifest test names must be unique")
    return manifest, "sha256:" + hashlib.sha256(raw).hexdigest()


def run() -> tuple[dict[str, object], int]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    manifest, manifest_digest = load_manifest()
    results = []
    passed = 0
    for case in manifest["cases"]:
        suite = unittest.defaultTestLoader.loadTestsFromName(case["test"])
        if suite.countTestCases() != 1:
            status = "load_error"
        else:
            outcome = unittest.TestResult()
            suite.run(outcome)
            if outcome.wasSuccessful() and not outcome.skipped:
                status = "passed"
                passed += 1
            elif outcome.skipped:
                status = "skipped"
            else:
                status = "failed"
        results.append({"id": case["id"], "status": status, "test": case["test"]})

    total = len(results)
    report = {
        "spec_version": manifest["spec_version"],
        "profile": manifest["profile"],
        "manifest_digest": manifest_digest,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "cases": results,
    }
    return report, 0 if passed == total else 1


def main() -> int:
    try:
        report, exit_code = run()
    except Exception as error:
        report = {
            "spec_version": "pcp/0.1",
            "profile": "reference-core",
            "total": 0,
            "passed": 0,
            "failed": 1,
            "error": f"{type(error).__name__}: {error}",
        }
        exit_code = 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
