from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "ARTIFACTS.sha256"
TREE_ROOTS = (".github", "conformance", "docs", "pcp_reference", "schemas", "scripts", "tests")
ROOT_FILES = {
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "pyproject.toml",
}
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache"}


def expected_paths() -> list[str]:
    paths = set(ROOT_FILES)
    for directory in TREE_ROOTS:
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and not any(part in EXCLUDED_PARTS for part in path.parts):
                if path.suffix not in {".pyc", ".pyo"}:
                    paths.add(path.relative_to(ROOT).as_posix())
    return sorted(paths)


class ArtifactManifestTests(unittest.TestCase):
    def test_clean_checkout_text_bytes_are_lf_stable(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="ascii").splitlines()
        self.assertIn("* text=auto eol=lf", attributes)
        self.assertIn("LICENSE text eol=lf", attributes)
        text_paths = sorted(set(expected_paths()) | {MANIFEST.name})
        for relative in text_paths:
            with self.subTest(path=relative):
                self.assertNotIn(
                    b"\r",
                    (ROOT / relative).read_bytes(),
                    f"{relative} has checkout-unstable carriage returns",
                )

    def test_artifact_manifest_is_complete_and_matches_bytes(self):
        entries: dict[str, str] = {}
        for number, line in enumerate(MANIFEST.read_text(encoding="ascii").splitlines(), 1):
            match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
            self.assertIsNotNone(match, f"malformed ARTIFACTS.sha256 line {number}")
            assert match is not None
            digest_value, relative = match.groups()
            self.assertNotIn(relative, entries, f"duplicate artifact path: {relative}")
            entries[relative] = digest_value
        self.assertEqual(expected_paths(), sorted(entries))
        for relative, expected in entries.items():
            with self.subTest(path=relative):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
