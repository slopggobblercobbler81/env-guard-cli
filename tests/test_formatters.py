"""Unit tests for terminal and JSON formatters."""

import json
import unittest
from env_guard.auditor import AuditFinding
from env_guard.differ import DiffResult
from env_guard.formatters import (
    Colors,
    format_audit_results,
    format_diff_results,
    format_validation_results,
)
from env_guard.validator import ValidationError


class TestFormatters(unittest.TestCase):
    def test_colors_disable(self):
        Colors.disable()
        self.assertEqual(Colors.RED, "")
        self.assertEqual(Colors.GREEN, "")

    def test_format_validation_results_pass(self):
        res = format_validation_results([], ".env", as_json=False)
        self.assertIn("matches schema perfectly", res)

        json_res = format_validation_results([], ".env", as_json=True)
        data = json.loads(json_res)
        self.assertEqual(data["status"], "pass")
        self.assertEqual(data["error_count"], 0)

    def test_format_validation_results_fail(self):
        err = ValidationError(
            key="PORT",
            line_number=5,
            error_type="INVALID_TYPE",
            message="Not an int",
            expected="integer",
            actual="abc",
        )
        res = format_validation_results([err], ".env", as_json=False)
        self.assertIn("PORT", res)
        self.assertIn("Not an int", res)

        json_res = format_validation_results([err], ".env", as_json=True)
        data = json.loads(json_res)
        self.assertEqual(data["status"], "fail")
        self.assertEqual(len(data["errors"]), 1)

    def test_format_audit_results_clean_and_findings(self):
        clean_res = format_audit_results([], as_json=False)
        self.assertIn("No committed secrets", clean_res)

        finding = AuditFinding(
            file_path=".env",
            line_number=10,
            key="SECRET_KEY",
            rule_id="SEC001",
            rule_name="AWS Key",
            severity="HIGH",
            description="Exposed AWS key",
            sample="AKIAIOSFODNN7EXAMPLE",
            entropy=3.9,
        )
        res = format_audit_results([finding], as_json=False)
        self.assertIn("AWS Key", res)
        self.assertIn("AKIA", res)

        json_res = format_audit_results([finding], as_json=True)
        data = json.loads(json_res)
        self.assertEqual(data["status"], "secrets_detected")
        self.assertEqual(data["count"], 1)

    def test_format_diff_results(self):
        diff = DiffResult(
            source_path="a.env",
            target_path="b.env",
            missing_in_target=["EXTRA_1"],
            missing_in_source=["EXTRA_2"],
            value_differences={"PORT": ("8080", "3000")},
            identical_keys=["DB_NAME"],
        )
        res = format_diff_results(diff, as_json=False)
        self.assertIn("EXTRA_1", res)
        self.assertIn("EXTRA_2", res)
        self.assertIn("PORT", res)

        json_res = format_diff_results(diff, as_json=True)
        data = json.loads(json_res)
        self.assertTrue(data["has_differences"])
        self.assertIn("EXTRA_1", data["missing_in_target"])


if __name__ == "__main__":
    unittest.main()
