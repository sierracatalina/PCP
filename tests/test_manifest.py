from __future__ import annotations

import unittest

from scripts.run_conformance import load_manifest


class ManifestTests(unittest.TestCase):
    def test_manifest_has_one_loadable_test_per_case(self):
        manifest, digest = load_manifest()
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(manifest["expected_case_count"], len(manifest["cases"]))
        for case in manifest["cases"]:
            with self.subTest(case=case["id"]):
                suite = unittest.defaultTestLoader.loadTestsFromName(case["test"])
                self.assertEqual(1, suite.countTestCases())


if __name__ == "__main__":
    unittest.main()
