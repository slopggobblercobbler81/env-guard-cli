"""Unit tests for the dotenv parser."""

import unittest
from env_guard.parser import (
    parse_env,
    parse_env_entries,
    expand_variables,
    DotenvParseError,
)


class TestDotenvParser(unittest.TestCase):
    def test_basic_parsing(self):
        content = """
        # Database config
        DB_HOST=localhost
        DB_PORT=5432
        DB_NAME="test_db"
        EMPTY_VAR=
        """
        env = parse_env(content)
        self.assertEqual(env["DB_HOST"], "localhost")
        self.assertEqual(env["DB_PORT"], "5432")
        self.assertEqual(env["DB_NAME"], "test_db")
        self.assertEqual(env["EMPTY_VAR"], "")

    def test_export_prefix(self):
        content = "export API_KEY=secret_key_123\nexport PORT=3000"
        entries = parse_env_entries(content)
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0].has_export)
        self.assertEqual(entries[0].key, "API_KEY")
        self.assertEqual(entries[0].value, "secret_key_123")

    def test_quotes_and_escapes(self):
        content = r'''
        SINGLE_QUOTED='hello\nworld'
        DOUBLE_QUOTED="hello\nworld"
        TAB_QUOTED="foo\tbar"
        ESCAPED_QUOTE="quote\"inside"
        '''
        env = parse_env(content)
        self.assertEqual(env["SINGLE_QUOTED"], r"hello\nworld")
        self.assertEqual(env["DOUBLE_QUOTED"], "hello\nworld")
        self.assertEqual(env["TAB_QUOTED"], "foo\tbar")
        self.assertEqual(env["ESCAPED_QUOTE"], 'quote"inside')

    def test_multiline_quotes(self):
        content = '''
        CERT="-----BEGIN CERT-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERT-----"
        '''
        env = parse_env(content)
        self.assertIn("BEGIN CERT", env["CERT"])
        self.assertIn("END CERT", env["CERT"])

    def test_inline_comments(self):
        content = """
        PORT=8080 # The default web port
        NAME=Alice # Developer name
        """
        entries = parse_env_entries(content)
        vars_dict = {e.key: e for e in entries if e.is_variable}
        self.assertEqual(vars_dict["PORT"].value, "8080")
        self.assertEqual(vars_dict["PORT"].comment, "The default web port")
        self.assertEqual(vars_dict["NAME"].value, "Alice")
        self.assertEqual(vars_dict["NAME"].comment, "Developer name")

    def test_variable_expansion(self):
        env = {
            "BASE_URL": "https://api.example.com",
            "VERSION": "v1",
            "ENDPOINT": "${BASE_URL}/${VERSION}/users",
            "PORT": "8080",
            "HOST": "$PORT",
        }
        expanded = expand_variables(env)
        self.assertEqual(expanded["ENDPOINT"], "https://api.example.com/v1/users")
        self.assertEqual(expanded["HOST"], "8080")

    def test_invalid_syntax(self):
        content = "123INVALID=value"
        with self.assertRaises(DotenvParseError):
            parse_env_entries(content)


if __name__ == "__main__":
    unittest.main()
