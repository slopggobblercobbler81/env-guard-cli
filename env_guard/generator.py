"""Safe .env.example generator from .env files or schema definitions."""

from __future__ import annotations

import os
from typing import Dict, List, Optional

from .parser import EnvEntry, parse_env_entries
from .validator import SchemaValidator, VariableSchema


def get_default_placeholder(key: str, var_type: Optional[str] = None) -> str:
    """Generate a safe, intuitive placeholder value for a variable."""
    k = key.upper()
    t = (var_type or "").lower()

    if t == "port" or "PORT" in k:
        return "8080"
    if t == "bool" or t == "boolean" or k.startswith("ENABLE_") or k.startswith("DISABLE_") or "DEBUG" in k:
        return "false"
    if t == "url" or "URL" in k or "URI" in k:
        if "DB" in k or "DATABASE" in k or "POSTGRES" in k:
            return "postgresql://user:password@localhost:5432/mydb"
        if "REDIS" in k:
            return "redis://localhost:6379/0"
        if "MONGO" in k:
            return "mongodb://localhost:27017/mydb"
        return "https://example.com/api"
    if t == "email" or "EMAIL" in k or "MAIL" in k:
        return "admin@example.com"
    if t in ("int", "integer"):
        return "10"
    if t in ("float", "number"):
        return "1.0"
    if t == "ip" or "HOST" in k or "IP" in k:
        return "127.0.0.1"
    if "ENV" in k:
        return "development"

    # Default placeholder
    clean_k = key.lower().replace("-", "_")
    return f"<your_{clean_k}>"


class ExampleGenerator:
    """Generates sanitized, safe .env.example templates."""

    def __init__(
        self,
        schema_validator: Optional[SchemaValidator] = None,
        empty_values: bool = False,
        annotate: bool = True,
    ):
        self.schema_validator = schema_validator
        self.empty_values = empty_values
        self.annotate = annotate

    def generate_from_env_content(self, content: str) -> str:
        entries = parse_env_entries(content)
        lines: List[str] = []

        for entry in entries:
            if entry.is_empty_line:
                lines.append("")
                continue

            if entry.is_comment_only:
                lines.append(f"#{entry.comment}" if entry.comment else "#")
                continue

            if entry.is_variable and entry.key:
                schema: Optional[VariableSchema] = None
                if self.schema_validator:
                    schema = self.schema_validator.variables.get(entry.key)

                # Determine placeholder value
                if self.empty_values:
                    val = ""
                elif schema and schema.default is not None:
                    val = schema.default
                elif schema and schema.enum:
                    val = schema.enum[0]
                else:
                    v_type = schema.type if schema else None
                    val = get_default_placeholder(entry.key, v_type)

                prefix = "export " if entry.has_export else ""

                # Optional annotations
                if self.annotate and schema:
                    meta = []
                    if schema.required:
                        meta.append("required")
                    if schema.type:
                        meta.append(f"type: {schema.type}")
                    if schema.enum:
                        meta.append(f"choices: [{', '.join(schema.enum)}]")
                    desc_prefix = f"# [{', '.join(meta)}] " if meta else "# "
                    if schema.description:
                        lines.append(f"{desc_prefix}{schema.description}")
                    elif meta:
                        lines.append(f"# [{', '.join(meta)}]")

                line_str = f"{prefix}{entry.key}={val}"
                if entry.comment and not self.annotate:
                    line_str += f" #{entry.comment}"
                lines.append(line_str)

        return "\n".join(lines) + "\n"

    def generate_from_schema(self, validator: SchemaValidator) -> str:
        lines: List[str] = [
            "# ===================================================================",
            "# Auto-generated environment template by env-guard-cli",
            "# ===================================================================",
            "",
        ]

        # Group required first, then optional
        req_vars = [v for v in validator.variables.values() if v.required]
        opt_vars = [v for v in validator.variables.values() if not v.required]

        if req_vars:
            lines.append("# --- REQUIRED CONFIGURATION ---")
            for var in req_vars:
                lines.extend(self._render_schema_var(var))
            lines.append("")

        if opt_vars:
            lines.append("# --- OPTIONAL CONFIGURATION ---")
            for var in opt_vars:
                lines.extend(self._render_schema_var(var))

        return "\n".join(lines) + "\n"

    def _render_schema_var(self, var: VariableSchema) -> List[str]:
        out = []
        meta = [f"type: {var.type}"]
        if var.required:
            meta.insert(0, "required")
        if var.enum:
            meta.append(f"enum: [{', '.join(var.enum)}]")

        if var.description:
            out.append(f"# {var.description}")
        out.append(f"# [{', '.join(meta)}]")

        if self.empty_values:
            val = ""
        elif var.default is not None:
            val = var.default
        elif var.enum:
            val = var.enum[0]
        else:
            val = get_default_placeholder(var.name, var.type)

        out.append(f"{var.name}={val}")
        out.append("")
        return out
