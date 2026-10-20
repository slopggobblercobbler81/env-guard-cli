"""Unit tests for secret auditor and heuristics."""

import os
import tempfile
import unittest
from env_guard.auditor import SecretAuditor
from env_guard.parser import parse_env_entries


class TestSecretAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = SecretAuditor()

    def test_aws_key_detection(self):
        dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        content = f"AWS_ACCESS_KEY_ID={dummy_aws}\nAWS_SECRET=secret"
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC001", rule_ids)

    def test_github_token_detection(self):
        dummy_gh = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12"
        content = f"GH_TOKEN={dummy_gh}"
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC002", rule_ids)

    def test_stripe_key_detection(self):
        dummy_stripe = "sk_" + "live_" + "51A2B3C4D5E6F7G8H9I0J1K2L3M"
        content = f"STRIPE_KEY={dummy_stripe}"
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC005", rule_ids)

    def test_openai_key_detection(self):
        dummy_openai = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz01234567890abcdefghijkl"
        content = f"OPENAI_API_KEY={dummy_openai}"
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC006", rule_ids)

    def test_private_key_detection(self):
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        footer = "-----END " + "RSA PRIVATE KEY-----"
        content = f"""
        PRIVATE_KEY="{header}
MIIEowIBAAKCAQEA0Y1o
{footer}"
        """
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC011", rule_ids)

    def test_database_credential_detection(self):
        content = "DB_URL=postgres://app_user:SuperSecretPass!@db.internal:5432/production"
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SEC013", rule_ids)

    def test_high_entropy_token_detection(self):
        # A completely random 32-char hex string
        content = "RANDOM_HASH=4f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c"
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        self.assertTrue(any(f.rule_id == "SEC_ENTROPY" or f.rule_id == "SEC_SENSITIVE_KEY" for f in findings))

    def test_placeholder_exemption(self):
        content = """
        AWS_ACCESS_KEY_ID=<your_aws_access_key>
        STRIPE_KEY=changeme
        OPENAI_API_KEY=your_key_here
        DB_PASSWORD=dummy
        API_TOKEN=xxx
        EMPTY_SECRET=
        """
        entries = parse_env_entries(content)
        findings = self.auditor.audit_entries(entries)
        self.assertEqual(len(findings), 0, [f.rule_name for f in findings])

    def test_ignore_rules_and_keys(self):
        auditor = SecretAuditor(ignored_rules={"SEC001"}, ignored_keys={"GH_TOKEN"})
        dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        dummy_gh = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12"
        content = f"""
        AWS_ACCESS_KEY_ID={dummy_aws}
        GH_TOKEN={dummy_gh}
        """
        entries = parse_env_entries(content)
        findings = auditor.audit_entries(entries)
        self.assertEqual(len(findings), 0)

    def test_audit_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = os.path.join(tmpdir, ".env")
            file2 = os.path.join(tmpdir, ".env.production")
            file3 = os.path.join(tmpdir, "ignored.txt")

            dummy_aws = "AKIA" + "IOSFODNN7EXAMPLE"
            with open(file1, "w") as f:
                f.write(f"AWS_KEY={dummy_aws}\n")
            with open(file2, "w") as f:
                f.write("SAFE_VAR=hello\n")
            with open(file3, "w") as f:
                f.write(f"NOT_SCANNED={dummy_aws}\n")

            findings = self.auditor.audit_directory(tmpdir, env_files_only=True)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].file_path, file1)


if __name__ == "__main__":
    unittest.main()
