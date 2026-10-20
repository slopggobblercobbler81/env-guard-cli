"""Schema inferrer that deduces schemas and types from existing .env files."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict
from urllib.parse import urlparse

from .parser import EnvEntry, parse_env_entries
from .patterns import is_sensitive_key_name


class SchemaInferrer:
    """Infers schema specifications from concrete environment files."""

    @staticmethod
    def infer_type(key: str, value: str) -> tuple[str, Dict[str, Any]]:
        k = key.upper()
        v = value.strip()
        extra: Dict[str, Any] = {}

        if not v:
            return "string", extra

        # Port detection
        if ("PORT" in k or k.endswith("_PORT")) and v.isdigit():
            iv = int(v)
            if 1 <= iv <= 65535:
                return "port", extra

        # Boolean
        if v.lower() in ("true", "false", "yes", "no"):
            return "boolean", extra

        # Integer
        if re.match(r"^-?\d+$", v):
            return "integer", extra

        # Float / Number
        if re.match(r"^-?\d+\.\d+$", v):
            return "number", extra

        # URL
        parsed = urlparse(v)
        if parsed.scheme in ("http", "https", "postgres", "postgresql", "mysql", "mongodb", "redis", "amqp", "ws", "wss"):
            return "url", extra

        # Email
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            return "email", extra

        # IP
        try:
            ipaddress.ip_address(v)
            return "ip", extra
        except ValueError:
            pass

        # JSON
        if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
            try:
                json.loads(v)
                return "json", extra
            except ValueError:
                pass

        # UUID
        if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", v):
            return "uuid", extra

        return "string", extra

    def infer_from_entries(self, entries: list[EnvEntry], mark_all_required: bool = False) -> Dict[str, Any]:
        variables: Dict[str, Any] = {}

        for entry in entries:
            if not entry.is_variable or not entry.key:
                continue

            v_type, extra = self.infer_type(entry.key, entry.value or "")
            var_spec: Dict[str, Any] = {
                "type": v_type,
                "required": mark_all_required or bool(entry.value),
            }

            if is_sensitive_key_name(entry.key):
                var_spec["secret"] = True

            if entry.comment:
                var_spec["description"] = entry.comment

            var_spec.update(extra)
            variables[entry.key] = var_spec

        return {
            "$schema": "https://raw.githubusercontent.com/slopggobblercobbler81/env-guard-cli/main/schemas/env-guard.schema.json",
            "version": "1.0",
            "variables": variables,
        }

    def infer_from_file(self, file_path: str, mark_all_required: bool = False) -> Dict[str, Any]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        entries = parse_env_entries(content)
        return self.infer_from_entries(entries, mark_all_required=mark_all_required)
