"""Dotenv file parser with AST-like entry preservation and accurate line numbers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class EnvEntry:
    key: Optional[str] = None
    value: Optional[str] = None
    raw_value: Optional[str] = None
    line_number: int = 1
    comment: Optional[str] = None
    is_comment_only: bool = False
    is_empty_line: bool = False
    has_export: bool = False

    @property
    def is_variable(self) -> bool:
        return self.key is not None and not self.is_comment_only and not self.is_empty_line


class DotenvParseError(ValueError):
    """Raised when parsing fails."""

    def __init__(self, message: str, line_number: int):
        super().__init__(f"Line {line_number}: {message}")
        self.line_number = line_number


def parse_env_entries(content: str) -> List[EnvEntry]:
    """Parse .env content into a list of structured EnvEntry items.
    
    Preserves comments and blank lines to allow safe round-trip reconstruction.
    Handles single/double quoted multiline strings, escape sequences, and inline comments.
    """
    entries: List[EnvEntry] = []
    lines = content.splitlines(keepends=False)
    idx = 0
    total = len(lines)

    while idx < total:
        line_num = idx + 1
        line = lines[idx]
        stripped = line.strip()

        # Empty line
        if not stripped:
            entries.append(EnvEntry(line_number=line_num, is_empty_line=True))
            idx += 1
            continue

        # Comment line
        if stripped.startswith("#"):
            comment_text = stripped.lstrip("#").strip()
            entries.append(
                EnvEntry(
                    line_number=line_num,
                    comment=comment_text,
                    is_comment_only=True,
                )
            )
            idx += 1
            continue

        # Possible variable definition
        working_line = stripped
        has_export = False
        if working_line.startswith("export "):
            has_export = True
            working_line = working_line[7:].strip()

        if "=" not in working_line:
            # Key with no value (valueless key) or syntax error
            key = working_line.strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                entries.append(
                    EnvEntry(
                        key=key,
                        value="",
                        raw_value="",
                        line_number=line_num,
                        has_export=has_export,
                    )
                )
                idx += 1
                continue
            else:
                raise DotenvParseError(f"Invalid environment variable format: '{line}'", line_num)

        key, remainder = working_line.split("=", 1)
        key = key.strip()

        if not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", key):
            raise DotenvParseError(f"Invalid variable identifier '{key}'", line_num)

        remainder = remainder.strip()

        # Handle quoted or unquoted values, including multiline
        if remainder.startswith('"'):
            # Double quoted
            idx, value, raw_val, inline_comment = _parse_quoted(
                lines, idx, quote_char='"', initial_remainder=remainder
            )
            entries.append(
                EnvEntry(
                    key=key,
                    value=value,
                    raw_value=raw_val,
                    line_number=line_num,
                    comment=inline_comment,
                    has_export=has_export,
                )
            )
            idx += 1
        elif remainder.startswith("'"):
            # Single quoted
            idx, value, raw_val, inline_comment = _parse_quoted(
                lines, idx, quote_char="'", initial_remainder=remainder
            )
            entries.append(
                EnvEntry(
                    key=key,
                    value=value,
                    raw_value=raw_val,
                    line_number=line_num,
                    comment=inline_comment,
                    has_export=has_export,
                )
            )
            idx += 1
        else:
            # Unquoted
            value, inline_comment = _parse_unquoted(remainder)
            entries.append(
                EnvEntry(
                    key=key,
                    value=value,
                    raw_value=remainder,
                    line_number=line_num,
                    comment=inline_comment,
                    has_export=has_export,
                )
            )
            idx += 1

    return entries


def _parse_quoted(
    lines: List[str], current_idx: int, quote_char: str, initial_remainder: str
) -> tuple[int, str, str, Optional[str]]:
    """Parse single or double quoted values, possibly spanning multiple lines."""
    content_parts: List[str] = []
    line_idx = current_idx
    line_remainder = initial_remainder[1:]  # strip leading quote

    while True:
        escaped = False
        i = 0
        found_closing = False
        parsed_in_line = []

        while i < len(line_remainder):
            char = line_remainder[i]
            if quote_char == '"' and char == "\\" and not escaped:
                escaped = True
                i += 1
                continue

            if char == quote_char and not escaped:
                found_closing = True
                # The rest of the line is after closing quote
                after_quote = line_remainder[i + 1 :].strip()
                inline_comment = None
                if after_quote.startswith("#"):
                    inline_comment = after_quote.lstrip("#").strip()
                content_parts.append("".join(parsed_in_line))
                raw_str = quote_char + "".join(content_parts) + quote_char
                parsed_val = "".join(content_parts)
                if quote_char == '"':
                    parsed_val = _unescape_double_quotes(parsed_val)
                return line_idx, parsed_val, raw_str, inline_comment

            if escaped:
                if quote_char == '"':
                    # Keep escape sequences in buffer for unescaping later
                    parsed_in_line.append("\\" + char)
                else:
                    parsed_in_line.append("\\" + char)
                escaped = False
            else:
                parsed_in_line.append(char)
            i += 1

        content_parts.append("".join(parsed_in_line))
        line_idx += 1
        if line_idx >= len(lines):
            # Unclosed quote reached EOF
            val = "".join(content_parts)
            return line_idx - 1, val, quote_char + val, None
        content_parts.append("\n")
        line_remainder = lines[line_idx]


def _unescape_double_quotes(text: str) -> str:
    """Unescape standard double-quote escape sequences."""
    replacements = {
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r'\"': '"',
        r"\\": "\\",
    }
    for esc, rep in replacements.items():
        text = text.replace(esc, rep)
    return text


def _parse_unquoted(remainder: str) -> tuple[str, Optional[str]]:
    """Parse unquoted value and extract potential inline comment."""
    # Check for inline comment preceded by space and #
    # e.g., PORT=8080 # default port
    comment = None
    if " #" in remainder:
        val, comm = remainder.split(" #", 1)
        return val.strip(), comm.strip()
    return remainder.strip(), comment


def parse_env(content: str) -> Dict[str, str]:
    """Parse .env content into a plain dictionary of key-value pairs."""
    entries = parse_env_entries(content)
    result: Dict[str, str] = {}
    for entry in entries:
        if entry.is_variable and entry.key is not None:
            result[entry.key] = entry.value or ""
    return result


def expand_variables(env_vars: Dict[str, str]) -> Dict[str, str]:
    """Expand ${VAR} or $VAR references using existing variables."""
    expanded = dict(env_vars)
    pattern = re.compile(r"\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))")

    for _ in range(5):  # up to 5 passes for nested interpolation
        changed = False
        for k, v in list(expanded.items()):
            def replacer(match: re.Match[str]) -> str:
                var_name = match.group(1) or match.group(2)
                return expanded.get(var_name, match.group(0))

            new_v = pattern.sub(replacer, v)
            if new_v != v:
                expanded[k] = new_v
                changed = True
        if not changed:
            break

    return expanded
