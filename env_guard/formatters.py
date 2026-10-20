"""Output formatting for CLI: colorized console output and structured JSON."""

from __future__ import annotations

import json
import sys
from typing import Any, List

from .auditor import AuditFinding
from .differ import DiffResult
from .validator import ValidationError


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"

    @classmethod
    def disable(cls):
        cls.RESET = ""
        cls.BOLD = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.GRAY = ""


# Auto-disable colors if stdout is not a tty
if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
    # Only disable if NO_COLOR env var is set or on dumb terminals
    pass


def format_validation_results(
    errors: List[ValidationError], file_path: str, as_json: bool = False
) -> str:
    if as_json:
        data = {
            "file": file_path,
            "status": "fail" if errors else "pass",
            "error_count": len(errors),
            "errors": [
                {
                    "key": e.key,
                    "line": e.line_number,
                    "type": e.error_type,
                    "message": e.message,
                    "expected": e.expected,
                    "actual": e.actual,
                }
                for e in errors
            ],
        }
        return json.dumps(data, indent=2)

    lines: List[str] = []
    if not errors:
        lines.append(f"{Colors.GREEN}[PASS]{Colors.RESET} {file_path} matches schema perfectly. No issues found.")
        return "\n".join(lines)

    lines.append(
        f"{Colors.RED}{Colors.BOLD}[FAIL]{Colors.RESET} Found {len(errors)} validation issue(s) in {file_path}:"
    )
    lines.append("")

    for err in errors:
        loc = f":{err.line_number}" if err.line_number else ""
        lines.append(f"  {Colors.RED}* {Colors.BOLD}{err.key}{Colors.RESET}{Colors.GRAY}{loc}{Colors.RESET}")
        lines.append(f"    {Colors.YELLOW}{err.message}{Colors.RESET}")
        if err.expected:
            lines.append(f"    {Colors.GRAY}Expected:{Colors.RESET} {err.expected}")
        if err.actual is not None:
            lines.append(f"    {Colors.GRAY}Actual:  {Colors.RESET} {err.actual}")
        lines.append("")

    return "\n".join(lines)


def format_audit_results(
    findings: List[AuditFinding], as_json: bool = False
) -> str:
    if as_json:
        data = {
            "status": "clean" if not findings else "secrets_detected",
            "count": len(findings),
            "findings": [
                {
                    "file": f.file_path,
                    "line": f.line_number,
                    "key": f.key,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "description": f.description,
                    "sample": f.masked_sample(),
                    "entropy": round(f.entropy, 2),
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2)

    lines: List[str] = []
    if not findings:
        lines.append(f"{Colors.GREEN}[CLEAN]{Colors.RESET} No committed secrets, high-entropy tokens, or exposed credentials detected.")
        return "\n".join(lines)

    lines.append(
        f"{Colors.RED}{Colors.BOLD}[ALERT]{Colors.RESET} Detected {len(findings)} potential secret(s) or sensitive credential(s):"
    )
    lines.append("")

    for f in findings:
        sev_color = Colors.RED if f.severity == "HIGH" else (Colors.YELLOW if f.severity == "MEDIUM" else Colors.BLUE)
        badge = f"{sev_color}[{f.severity}]{Colors.RESET}"
        loc = f"{f.file_path}:{f.line_number}"
        key_str = f" ({f.key})" if f.key else ""

        lines.append(f"  {badge} {Colors.BOLD}{f.rule_name}{Colors.RESET} at {Colors.CYAN}{loc}{Colors.RESET}{key_str}")
        lines.append(f"    {Colors.GRAY}Rule:   {Colors.RESET}{f.rule_id} - {f.description}")
        lines.append(f"    {Colors.GRAY}Sample: {Colors.RESET}{Colors.MAGENTA}{f.masked_sample()}{Colors.RESET} (entropy: {f.entropy:.2f})")
        lines.append("")

    return "\n".join(lines)


def format_diff_results(diff: DiffResult, as_json: bool = False) -> str:
    if as_json:
        data = {
            "source": diff.source_path,
            "target": diff.target_path,
            "has_differences": diff.has_differences,
            "missing_in_target": diff.missing_in_target,
            "missing_in_source": diff.missing_in_source,
            "value_differences": {
                k: {"source": v[0], "target": v[1]} for k, v in diff.value_differences.items()
            },
            "identical_keys_count": len(diff.identical_keys),
        }
        return json.dumps(data, indent=2)

    lines: List[str] = []
    lines.append(f"Comparing {Colors.CYAN}{diff.source_path}{Colors.RESET} -> {Colors.CYAN}{diff.target_path}{Colors.RESET}")

    if not diff.has_differences:
        lines.append(f"{Colors.GREEN}[IN SYNC]{Colors.RESET} Both files have identical variable definitions.")
        return "\n".join(lines)

    if diff.missing_in_target:
        lines.append(f"\n{Colors.YELLOW}[MISSING IN {diff.target_path}]{Colors.RESET}")
        for k in diff.missing_in_target:
            lines.append(f"  {Colors.RED}- {k}{Colors.RESET}")

    if diff.missing_in_source:
        lines.append(f"\n{Colors.YELLOW}[MISSING IN {diff.source_path}]{Colors.RESET}")
        for k in diff.missing_in_source:
            lines.append(f"  {Colors.GREEN}+ {k}{Colors.RESET}")

    if diff.value_differences:
        lines.append(f"\n{Colors.YELLOW}[VALUE DIFFERENCES]{Colors.RESET}")
        for k, (v1, v2) in diff.value_differences.items():
            lines.append(f"  * {k}: '{v1}' != '{v2}'")

    return "\n".join(lines)
