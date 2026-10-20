"""Unit tests for the CLI runner."""

import json
import os
import tempfile
import unittest
from env_guard.cli import main


class TestCLI(unittest.TestCase):
    def test_cli_version_and_help(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

        # No command returns 0
        ret = main([])
        self.assertEqual(ret, 0)

    def test_cli_validate_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_file = os.path.join(tmpdir, "schema.json")
            valid_env = os.path.join(tmpdir, "valid.env")
            invalid_env = os.path.join(tmpdir, "invalid.env")

            with open(schema_file, "w") as f:
                json.dump({"variables": {"PORT": {"type": "port", "required": True}}}, f)

            with open(valid_env, "w") as f:
                f.write("PORT=8080\n")

            with open(invalid_env, "w") as f:
                f.write("PORT=999999\n")

            # Valid should return 0
            code = main(["validate", valid_env, "-s", schema_file])
            self.assertEqual(code, 0)

            # JSON mode
            code = main(["validate", valid_env, "-s", schema_file, "--json"])
            self.assertEqual(code, 0)

            # Invalid should return 1
            code = main(["validate", invalid_env, "-s", schema_file])
            self.assertEqual(code, 1)

            # Missing files should return 2
            code = main(["validate", "nonexistent.env", "-s", schema_file])
            self.assertEqual(code, 2)

            code = main(["validate", valid_env, "-s", "nonexistent_schema.json"])
            self.assertEqual(code, 2)

    def test_cli_audit_secrets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_env = os.path.join(tmpdir, "clean.env")
            leaky_env = os.path.join(tmpdir, "leaky.env")

            with open(clean_env, "w") as f:
                f.write("API_KEY=<your_api_key>\n")

            dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
            with open(leaky_env, "w") as f:
                f.write(f"API_KEY={dummy_aws}\n")

            code = main(["audit", clean_env])
            self.assertEqual(code, 0)

            code = main(["audit", leaky_env])
            self.assertEqual(code, 1)

            code = main(["audit", leaky_env, "--json"])
            self.assertEqual(code, 1)

            # Audit non-existent
            code = main(["audit", os.path.join(tmpdir, "nonexistent")])
            self.assertEqual(code, 2)

    def test_cli_generate_and_infer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_env = os.path.join(tmpdir, ".env")
            out_example = os.path.join(tmpdir, ".env.example")
            out_schema = os.path.join(tmpdir, "inferred.json")

            with open(source_env, "w") as f:
                f.write("PORT=3000\nAPI_SECRET=mysecretphrase123\n")

            # Generate example
            code = main(["generate", source_env, "-o", out_example])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out_example))

            # Generate example to stdout
            code = main(["generate", source_env, "--stdout"])
            self.assertEqual(code, 0)

            # Infer schema
            code = main(["infer", source_env, "-o", out_schema])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(out_schema))

            # Infer schema to stdout
            code = main(["infer", source_env, "--stdout"])
            self.assertEqual(code, 0)

    def test_cli_diff(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_a = os.path.join(tmpdir, "a.env")
            file_b = os.path.join(tmpdir, "b.env")

            with open(file_a, "w") as f:
                f.write("PORT=8080\n")
            with open(file_b, "w") as f:
                f.write("PORT=8080\n")

            # In sync returns 0
            code = main(["diff", file_a, file_b])
            self.assertEqual(code, 0)

            # Mismatch returns 1
            with open(file_b, "w") as f:
                f.write("PORT=3000\nEXTRA=1\n")

            code = main(["diff", file_a, file_b, "--values"])
            self.assertEqual(code, 1)

            # Nonexistent file returns 2
            code = main(["diff", "nonexistent.env", file_b])
            self.assertEqual(code, 2)

    def test_cli_redact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_env = os.path.join(tmpdir, ".env")
            out_redacted = os.path.join(tmpdir, "redacted.env")

            with open(source_env, "w") as f:
                f.write("SECRET_KEY=1234567890abcdef\n")

            code = main(["redact", source_env, "-o", out_redacted])
            self.assertEqual(code, 0)
            with open(out_redacted, "r") as f:
                content = f.read()
            self.assertIn("SECRET_KEY=12************ef", content)

            # Redact to stdout
            code = main(["redact", source_env])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
