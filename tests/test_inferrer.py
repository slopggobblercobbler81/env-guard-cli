"""Unit tests for schema inferrer."""

import unittest
from env_guard.inferrer import SchemaInferrer
from env_guard.parser import parse_env_entries


class TestSchemaInferrer(unittest.TestCase):
    def setUp(self):
        self.inferrer = SchemaInferrer()

    def test_infer_various_types(self):
        content = """
        APP_PORT=3000
        DEBUG=true
        DATABASE_URL=postgres://user:pass@localhost:5432/db
        MAX_RETRIES=5
        RATIO=3.14
        ADMIN_EMAIL=admin@example.com
        SERVER_HOST=127.0.0.1
        METRICS_CONFIG={"enabled": true}
        DEVICE_UUID=123e4567-e89b-12d3-a456-426614174000
        AUTH_SECRET=longsecretphrase
        """
        entries = parse_env_entries(content)
        schema = self.inferrer.infer_from_entries(entries)
        vars_map = schema["variables"]

        self.assertEqual(vars_map["APP_PORT"]["type"], "port")
        self.assertEqual(vars_map["DEBUG"]["type"], "boolean")
        self.assertEqual(vars_map["DATABASE_URL"]["type"], "url")
        self.assertEqual(vars_map["MAX_RETRIES"]["type"], "integer")
        self.assertEqual(vars_map["RATIO"]["type"], "number")
        self.assertEqual(vars_map["ADMIN_EMAIL"]["type"], "email")
        self.assertEqual(vars_map["SERVER_HOST"]["type"], "ip")
        self.assertEqual(vars_map["METRICS_CONFIG"]["type"], "json")
        self.assertEqual(vars_map["DEVICE_UUID"]["type"], "uuid")
        self.assertTrue(vars_map["AUTH_SECRET"].get("secret", False))


if __name__ == "__main__":
    unittest.main()
