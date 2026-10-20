"""Unit tests for schema validator."""

import unittest
from env_guard.parser import parse_env_entries
from env_guard.validator import SchemaValidator


class TestSchemaValidator(unittest.TestCase):
    def setUp(self):
        self.schema = {
            "variables": {
                "PORT": {"type": "port", "required": True},
                "NODE_ENV": {"type": "string", "enum": ["development", "production", "test"], "required": True},
                "DATABASE_URL": {"type": "url", "required": True},
                "DEBUG": {"type": "boolean", "default": "false"},
                "MAX_WORKERS": {"type": "integer", "min": 1, "max": 64},
                "ALERT_EMAIL": {"type": "email"},
                "SERVER_IP": {"type": "ip"},
                "CONFIG_JSON": {"type": "json"},
                "API_KEY": {"type": "string", "pattern": r"^app_[a-zA-Z0-9]{8}$"},
                "AUTH_TOKEN": {"type": "base64"},
                "CLIENT_ID": {"type": "uuid"},
            }
        }
        self.validator = SchemaValidator(self.schema)

    def test_valid_environment(self):
        env_content = """
        PORT=3000
        NODE_ENV=production
        DATABASE_URL=postgresql://user:secret@localhost:5432/app
        DEBUG=true
        MAX_WORKERS=8
        ALERT_EMAIL=ops@company.com
        SERVER_IP=192.168.1.1
        CONFIG_JSON={"rate_limit": 100}
        API_KEY=app_abc12345
        AUTH_TOKEN=c2VjcmV0dG9rZW4=
        CLIENT_ID=123e4567-e89b-12d3-a456-426614174000
        """
        entries = parse_env_entries(env_content)
        errors = self.validator.validate_entries(entries)
        self.assertEqual(len(errors), 0, [e.message for e in errors])

    def test_missing_required_variables(self):
        env_content = """
        DEBUG=true
        """
        entries = parse_env_entries(env_content)
        errors = self.validator.validate_entries(entries)
        error_keys = [e.key for e in errors]
        self.assertIn("PORT", error_keys)
        self.assertIn("NODE_ENV", error_keys)
        self.assertIn("DATABASE_URL", error_keys)

    def test_invalid_types(self):
        env_content = """
        PORT=999999
        NODE_ENV=staging
        DATABASE_URL=not-a-valid-url
        DEBUG=not_a_bool
        MAX_WORKERS=100
        ALERT_EMAIL=invalid-email
        SERVER_IP=999.999.999.999
        CONFIG_JSON={broken-json
        API_KEY=too_short
        AUTH_TOKEN=!!!notbase64!!!
        CLIENT_ID=invalid-uuid
        """
        entries = parse_env_entries(env_content)
        errors = self.validator.validate_entries(entries)
        self.assertTrue(len(errors) >= 10)

    def test_disallow_extra_keys(self):
        strict_validator = SchemaValidator(
            {"variables": {"PORT": {"type": "port", "required": True}}},
            disallow_extra_keys=True,
        )
        env_content = "PORT=8080\nEXTRA_VAR=123"
        entries = parse_env_entries(env_content)
        errors = strict_validator.validate_entries(entries)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].error_type, "UNEXPECTED_KEY")
        self.assertEqual(errors[0].key, "EXTRA_VAR")


if __name__ == "__main__":
    unittest.main()
