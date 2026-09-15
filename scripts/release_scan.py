#!/usr/bin/env python3
"""Portable public-release scan with non-sensitive diagnostics."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


EXCLUDED_DIRS = {".git", ".tox", ".venv", "__pycache__", "build", "dist", "node_modules"}
MAX_FILE_BYTES = 20 * 1024 * 1024

PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key-block", re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai-style-token", re.compile(rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("windows-user-path", re.compile(rb"[A-Za-z]:\\Users\\[^\\\s]+\\")),
    ("unix-user-path", re.compile(rb"/(?:home|Users)/[^/\s]+/")),
    ("private-workspace-link", re.compile(rb"(?:docs|drive)\.google\.com|notion\.(?:so|com)", re.I)),
)


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in parts):
            continue
        yield path


def scan(root: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                findings.append((relative, "file-too-large-to-scan"))
                continue
            data = path.read_bytes()
        except OSError:
            findings.append((relative, "unreadable-file"))
            continue
        for label, pattern in PATTERNS:
            if pattern.search(data):
                findings.append((relative, label))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"PUBLIC RELEASE SCAN ERROR: directory missing: {root}", file=sys.stderr)
        return 2

    findings = scan(root)
    if findings:
        print("PUBLIC RELEASE SCAN FAILED")
        for path, label in findings:
            print(f"{path}: {label}")
        return 1

    print("PUBLIC RELEASE SCAN PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
