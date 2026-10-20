"""Unit tests for example template generator."""

import unittest
from env_guard.generator import ExampleGenerator
from env_guard.parser import parse_env
from env_guard.validator import SchemaValidator


class TestExampleGenerator(unittest.TestCase):
    def test_generate_from_env_content(self):
        env_content = """
        # Server settings
        PORT=3000
        HOST=localhost

        # Database credentials
        DATABASE_URL=postgres://user:secret@localhost:5432/mydb
        SECRET_KEY=supersecretkey12345
        DEBUG=true
        """
        generator = ExampleGenerator()
        example_output = generator.generate_from_env_content(env_content)
        parsed = parse_env(example_output)

        self.assertIn("PORT", parsed)
        self.assertIn("DATABASE_URL", parsed)
        self.assertIn("SECRET_KEY", parsed)
        # Verify real secret was stripped and replaced with safe placeholder
        self.assertNotIn("secret", parsed["DATABASE_URL"])
        self.assertNotIn("supersecretkey12345", parsed["SECRET_KEY"])
        self.assertTrue(parsed["SECRET_KEY"].startswith("<your_secret_key>"))

    def test_generate_from_schema(self):
        schema = {
            "variables": {
                "PORT": {"type": "port", "required": True, "description": "HTTP Port"},
                "LOG_LEVEL": {"type": "string", "enum": ["debug", "info", "warn", "error"], "default": "info"},
                "API_KEY": {"type": "string", "required": True, "secret": True},
            }
        }
        validator = SchemaValidator(schema)
        generator = ExampleGenerator()
        output = generator.generate_from_schema(validator)

        parsed = parse_env(output)
        self.assertIn("PORT", parsed)
        self.assertEqual(parsed["LOG_LEVEL"], "info")
        self.assertTrue(parsed["API_KEY"].startswith("<your_api_key>"))
        self.assertIn("# HTTP Port", output)

    def test_empty_flag(self):
        env_content = "PORT=8080\nAPI_KEY=my_key"
        generator = ExampleGenerator(empty_values=True)
        output = generator.generate_from_env_content(env_content)
        parsed = parse_env(output)
        self.assertEqual(parsed["PORT"], "")
        self.assertEqual(parsed["API_KEY"], "")


if __name__ == "__main__":
    unittest.main()
