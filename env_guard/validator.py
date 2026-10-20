"""Schema validation engine for environment variables."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .parser import EnvEntry, parse_env_entries


@dataclass
class ValidationError:
    key: str
    line_number: Optional[int]
    error_type: str  # MISSING, INVALID_TYPE, OUT_OF_RANGE, PATTERN_MISMATCH, NOT_IN_ENUM, UNEXPECTED_KEY
    message: str
    expected: Optional[str] = None
    actual: Optional[str] = None


@dataclass
class VariableSchema:
    name: str
    type: str = "string"
    required: bool = False
    default: Optional[str] = None
    description: Optional[str] = None
    enum: Optional[List[str]] = None
    pattern: Optional[str] = None
    min_val: Optional[float] = None
    max_val: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    secret: bool = False


class SchemaValidator:
    def __init__(
        self,
        schema: Dict[str, Any],
        disallow_extra_keys: bool = False,
        allow_empty_strings: bool = False,
    ):
        self.disallow_extra_keys = disallow_extra_keys
        self.allow_empty_strings = allow_empty_strings
        self.variables: Dict[str, VariableSchema] = self._load_schema(schema)

    def _load_schema(self, raw_schema: Dict[str, Any]) -> Dict[str, VariableSchema]:
        vars_dict: Dict[str, VariableSchema] = {}
        items = raw_schema.get("variables", raw_schema)

        if not isinstance(items, dict):
            raise ValueError("Schema must contain a dictionary of variables")

        for name, spec in items.items():
            if name in ("$schema", "version", "description", "title"):
                continue
            if not isinstance(spec, dict):
                # Shorthand: "PORT": "integer"
                spec = {"type": str(spec)}

            v_type = spec.get("type", "string").lower()
            min_val = spec.get("min")
            max_val = spec.get("max")
            min_len = spec.get("min_length") or spec.get("minLength")
            max_len = spec.get("max_length") or spec.get("maxLength")

            vars_dict[name] = VariableSchema(
                name=name,
                type=v_type,
                required=bool(spec.get("required", False)),
                default=str(spec["default"]) if "default" in spec and spec["default"] is not None else None,
                description=spec.get("description"),
                enum=spec.get("enum") or spec.get("choices"),
                pattern=spec.get("pattern"),
                min_val=float(min_val) if min_val is not None else None,
                max_val=float(max_val) if max_val is not None else None,
                min_length=int(min_len) if min_len is not None else None,
                max_length=int(max_len) if max_len is not None else None,
                secret=bool(spec.get("secret", False)),
            )

        return vars_dict

    def validate_entries(self, entries: List[EnvEntry]) -> List[ValidationError]:
        errors: List[ValidationError] = []
        found_vars: Dict[str, EnvEntry] = {}

        for entry in entries:
            if entry.is_variable and entry.key:
                found_vars[entry.key] = entry

        # 1. Check required variables
        for name, schema in self.variables.items():
            if schema.required:
                if name not in found_vars:
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=None,
                            error_type="MISSING",
                            message=f"Missing required variable '{name}'",
                            expected=f"type: {schema.type}",
                        )
                    )
                elif not self.allow_empty_strings and found_vars[name].value == "":
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=found_vars[name].line_number,
                            error_type="MISSING",
                            message=f"Required variable '{name}' is defined but empty",
                            expected="non-empty value",
                            actual="",
                        )
                    )

        # 2. Check each defined variable
        for name, entry in found_vars.items():
            schema = self.variables.get(name)
            if not schema:
                if self.disallow_extra_keys:
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=entry.line_number,
                            error_type="UNEXPECTED_KEY",
                            message=f"Variable '{name}' is not allowed by schema",
                            actual=entry.value,
                        )
                    )
                continue

            val = entry.value or ""
            if not val:
                # If value is empty and not required, we skip type checks
                continue

            # Validate type & constraints
            type_err = self._validate_value(name, val, schema, entry.line_number)
            if type_err:
                errors.extend(type_err)

        return errors

    def _validate_value(
        self, name: str, val: str, schema: VariableSchema, line_number: int
    ) -> List[ValidationError]:
        errors: List[ValidationError] = []

        # Check enum
        if schema.enum is not None:
            if val not in [str(e) for e in schema.enum]:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="NOT_IN_ENUM",
                        message=f"Value '{val}' not in allowed choices: {schema.enum}",
                        expected=str(schema.enum),
                        actual=val,
                    )
                )

        # Check regex pattern
        if schema.pattern:
            try:
                if not re.search(schema.pattern, val):
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=line_number,
                            error_type="PATTERN_MISMATCH",
                            message=f"Value does not match required regex pattern: '{schema.pattern}'",
                            expected=f"pattern {schema.pattern}",
                            actual=val if not schema.secret else "***",
                        )
                    )
            except re.error as e:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="SCHEMA_ERROR",
                        message=f"Invalid regex in schema pattern: {e}",
                    )
                )

        # Check length constraints
        if schema.min_length is not None and len(val) < schema.min_length:
            errors.append(
                ValidationError(
                    key=name,
                    line_number=line_number,
                    error_type="OUT_OF_RANGE",
                    message=f"Value length {len(val)} is below minimum length {schema.min_length}",
                    expected=f">= {schema.min_length} chars",
                    actual=f"{len(val)} chars",
                )
            )

        if schema.max_length is not None and len(val) > schema.max_length:
            errors.append(
                ValidationError(
                    key=name,
                    line_number=line_number,
                    error_type="OUT_OF_RANGE",
                    message=f"Value length {len(val)} exceeds maximum length {schema.max_length}",
                    expected=f"<= {schema.max_length} chars",
                    actual=f"{len(val)} chars",
                )
            )

        # Check types
        t = schema.type
        if t in ("int", "integer"):
            try:
                iv = int(val)
                if schema.min_val is not None and iv < schema.min_val:
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=line_number,
                            error_type="OUT_OF_RANGE",
                            message=f"Integer {iv} is less than min {schema.min_val}",
                            expected=f">= {schema.min_val}",
                            actual=str(iv),
                        )
                    )
                if schema.max_val is not None and iv > schema.max_val:
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=line_number,
                            error_type="OUT_OF_RANGE",
                            message=f"Integer {iv} is greater than max {schema.max_val}",
                            expected=f"<= {schema.max_val}",
                            actual=str(iv),
                        )
                    )
            except ValueError:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid integer",
                        expected="integer",
                        actual=val,
                    )
                )

        elif t in ("float", "number"):
            try:
                fv = float(val)
                if schema.min_val is not None and fv < schema.min_val:
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=line_number,
                            error_type="OUT_OF_RANGE",
                            message=f"Number {fv} is less than min {schema.min_val}",
                            expected=f">= {schema.min_val}",
                            actual=str(fv),
                        )
                    )
                if schema.max_val is not None and fv > schema.max_val:
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=line_number,
                            error_type="OUT_OF_RANGE",
                            message=f"Number {fv} is greater than max {schema.max_val}",
                            expected=f"<= {schema.max_val}",
                            actual=str(fv),
                        )
                    )
            except ValueError:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid number",
                        expected="number",
                        actual=val,
                    )
                )

        elif t in ("bool", "boolean"):
            normalized = val.strip().lower()
            if normalized not in ("true", "false", "1", "0", "yes", "no", "t", "f", "on", "off"):
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid boolean (expected true/false/1/0/yes/no)",
                        expected="boolean",
                        actual=val,
                    )
                )

        elif t == "port":
            try:
                pv = int(val)
                if not (1 <= pv <= 65535):
                    errors.append(
                        ValidationError(
                            key=name,
                            line_number=line_number,
                            error_type="OUT_OF_RANGE",
                            message=f"Port number {pv} is outside valid range (1-65535)",
                            expected="1-65535",
                            actual=str(pv),
                        )
                    )
            except ValueError:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Port '{val}' must be an integer between 1 and 65535",
                        expected="port",
                        actual=val,
                    )
                )

        elif t == "url":
            parsed = urlparse(val)
            if not (parsed.scheme and (parsed.netloc or parsed.path)):
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid URL (must have scheme e.g. http://, postgres://)",
                        expected="valid URL",
                        actual=val,
                    )
                )

        elif t == "email":
            email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
            if not re.match(email_regex, val):
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid email address",
                        expected="email",
                        actual=val,
                    )
                )

        elif t == "ip":
            try:
                ipaddress.ip_address(val)
            except ValueError:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid IPv4 or IPv6 address",
                        expected="IP address",
                        actual=val,
                    )
                )

        elif t == "json":
            try:
                json.loads(val)
            except ValueError as e:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value is not valid JSON: {e}",
                        expected="valid JSON",
                        actual=val,
                    )
                )

        elif t == "base64":
            try:
                base64.b64decode(val.encode("ascii"), validate=True)
            except Exception:
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message="Value is not valid base64",
                        expected="valid base64",
                        actual=val,
                    )
                )

        elif t == "uuid":
            uuid_regex = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            if not re.match(uuid_regex, val):
                errors.append(
                    ValidationError(
                        key=name,
                        line_number=line_number,
                        error_type="INVALID_TYPE",
                        message=f"Value '{val}' is not a valid UUID",
                        expected="UUID",
                        actual=val,
                    )
                )

        return errors

    @classmethod
    def from_file(
        cls,
        schema_path: str,
        disallow_extra_keys: bool = False,
        allow_empty_strings: bool = False,
    ) -> SchemaValidator:
        with open(schema_path, "r", encoding="utf-8") as f:
            content = f.read()

        if schema_path.endswith((".yaml", ".yml")):
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                raise RuntimeError("PyYAML required for yaml schemas. Run: pip install pyyaml")
        else:
            data = json.loads(content)

        return cls(data, disallow_extra_keys=disallow_extra_keys, allow_empty_strings=allow_empty_strings)
