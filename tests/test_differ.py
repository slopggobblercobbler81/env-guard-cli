"""Unit tests for environment file differ."""

import os
import tempfile
import unittest
from env_guard.differ import EnvDiffer


class TestEnvDiffer(unittest.TestCase):
    def test_compare_missing_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_a = os.path.join(tmpdir, ".env.example")
            file_b = os.path.join(tmpdir, ".env")

            with open(file_a, "w") as f:
                f.write("PORT=8080\nHOST=localhost\nNEW_FEATURE_FLAG=false\n")
            with open(file_b, "w") as f:
                f.write("PORT=3000\nHOST=localhost\nLOCAL_OVERRIDE=1\n")

            diff = EnvDiffer.compare(file_a, file_b, compare_values=False)
            self.assertTrue(diff.has_differences)
            self.assertEqual(diff.missing_in_target, ["NEW_FEATURE_FLAG"])
            self.assertEqual(diff.missing_in_source, ["LOCAL_OVERRIDE"])
            self.assertIn("PORT", diff.identical_keys)
            self.assertIn("HOST", diff.identical_keys)

    def test_compare_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_a = os.path.join(tmpdir, "a.env")
            file_b = os.path.join(tmpdir, "b.env")

            with open(file_a, "w") as f:
                f.write("PORT=8080\nENV=dev\n")
            with open(file_b, "w") as f:
                f.write("PORT=8080\nENV=prod\n")

            diff = EnvDiffer.compare(file_a, file_b, compare_values=True)
            self.assertTrue(diff.has_differences)
            self.assertIn("ENV", diff.value_differences)
            self.assertEqual(diff.value_differences["ENV"], ("dev", "prod"))


if __name__ == "__main__":
    unittest.main()
