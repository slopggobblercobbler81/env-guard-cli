"""Command-line interface for env-guard-cli."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .auditor import SecretAuditor
from .differ import EnvDiffer
from .formatters import (
    Colors,
    format_audit_results,
    format_diff_results,
    format_validation_results,
)
from .generator import ExampleGenerator
from .inferrer import SchemaInferrer
from .parser import parse_env_entries
from .validator import SchemaValidator


def create_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="Disable colored output")
    common.add_argument("--json", action="store_true", help="Format output as JSON")

    parser = argparse.ArgumentParser(
        prog="env-guard",
        description="env-guard: Validate .env against schemas, audit for committed secrets, and generate safe .env.example files.",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", title="commands", description="Available operations")

    # Command: validate
    val_p = subparsers.add_parser(
        "validate", parents=[common], help="Validate .env file against a schema definition"
    )
    val_p.add_argument("env_file", nargs="?", default=".env", help="Path to .env file (default: .env)")
    val_p.add_argument(
        "-s", "--schema", default="env.schema.json", help="Path to schema JSON/YAML (default: env.schema.json)"
    )
    val_p.add_argument(
        "--disallow-extra",
        action="store_true",
        help="Reject variables present in .env that are not defined in the schema",
    )
    val_p.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow required variables to have empty string values",
    )

    # Command: audit
    aud_p = subparsers.add_parser(
        "audit", parents=[common], help="Audit .env file or repository directory for exposed secrets"
    )
    aud_p.add_argument("target", nargs="?", default=".env", help="File or directory path to audit (default: .env)")
    aud_p.add_argument(
        "--entropy-threshold",
        type=float,
        default=3.8,
        help="Shannon entropy threshold for random token detection (default: 3.8)",
    )
    aud_p.add_argument(
        "--all-files",
        action="store_true",
        help="When scanning directory, scan all files rather than only .env variants",
    )
    aud_p.add_argument(
        "--fail-on",
        choices=["HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Exit with error if findings meet or exceed this severity (default: HIGH)",
    )
    aud_p.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        help="Ignore specific rule ID (can be used multiple times)",
    )
    aud_p.add_argument(
        "--ignore-key",
        action="append",
        default=[],
        help="Ignore specific variable key name (can be used multiple times)",
    )

    # Command: generate
    gen_p = subparsers.add_parser(
        "generate", parents=[common], help="Generate safe .env.example template from .env or schema"
    )
    gen_p.add_argument("env_file", nargs="?", default=".env", help="Path to source .env file (optional)")
    gen_p.add_argument(
        "-s", "--schema", default=None, help="Optional schema file to infer descriptions and types from"
    )
    gen_p.add_argument("-o", "--output", default=".env.example", help="Output file path (default: .env.example)")
    gen_p.add_argument(
        "--empty",
        action="store_true",
        help="Generate empty values (KEY=) instead of smart placeholder hints",
    )
    gen_p.add_argument(
        "--stdout",
        action="store_true",
        help="Print generated template directly to standard output instead of saving to file",
    )

    # Command: infer
    inf_p = subparsers.add_parser(
        "infer", parents=[common], help="Infer a schema JSON definition from an existing .env file"
    )
    inf_p.add_argument("env_file", nargs="?", default=".env", help="Source .env file (default: .env)")
    inf_p.add_argument(
        "-o", "--output", default="env.schema.json", help="Output schema path (default: env.schema.json)"
    )
    inf_p.add_argument(
        "--all-required",
        action="store_true",
        help="Mark every inferred variable as required",
    )
    inf_p.add_argument(
        "--stdout",
        action="store_true",
        help="Print inferred schema to stdout",
    )

    # Command: diff
    diff_p = subparsers.add_parser(
        "diff", parents=[common], help="Compare two .env files for missing or mismatched variables"
    )
    diff_p.add_argument("source", help="Source environment file (e.g. .env.example)")
    diff_p.add_argument("target", help="Target environment file (e.g. .env)")
    diff_p.add_argument(
        "--values",
        action="store_true",
        help="Also check and display value discrepancies",
    )

    # Command: redact
    red_p = subparsers.add_parser(
        "redact", parents=[common], help="Mask secret values in a .env file for safe sharing or logs"
    )
    red_p.add_argument("env_file", nargs="?", default=".env", help="Source .env file (default: .env)")
    red_p.add_argument("-o", "--output", default=None, help="Output destination (default: stdout)")

    return parser


def cmd_validate(args: argparse.Namespace) -> int:
    env_file = args.env_file
    schema_file = args.schema

    if not os.path.exists(env_file):
        print(f"Error: Environment file not found: {env_file}", file=sys.stderr)
        return 2

    if not os.path.exists(schema_file):
        print(f"Error: Schema file not found: {schema_file}", file=sys.stderr)
        return 2

    try:
        validator = SchemaValidator.from_file(
            schema_file,
            disallow_extra_keys=args.disallow_extra,
            allow_empty_strings=args.allow_empty,
        )
        with open(env_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        entries = parse_env_entries(content)
        errors = validator.validate_entries(entries)
    except Exception as e:
        print(f"Error during validation: {e}", file=sys.stderr)
        return 2

    print(format_validation_results(errors, env_file, as_json=args.json))
    return 1 if errors else 0


def cmd_audit(args: argparse.Namespace) -> int:
    target = args.target
    if not os.path.exists(target):
        print(f"Error: Target path not found: {target}", file=sys.stderr)
        return 2

    auditor = SecretAuditor(
        entropy_threshold=args.entropy_threshold,
        ignored_keys=set(args.ignore_key),
        ignored_rules=set(args.ignore_rule),
    )

    try:
        if os.path.isdir(target):
            findings = auditor.audit_directory(
                target,
                env_files_only=not args.all_files,
            )
        else:
            findings = auditor.audit_file(target)
    except Exception as e:
        print(f"Error auditing target: {e}", file=sys.stderr)
        return 2

    print(format_audit_results(findings, as_json=args.json))

    # Check failure severity
    sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    fail_threshold = sev_order.get(args.fail_on, 3)

    for f in findings:
        if sev_order.get(f.severity, 1) >= fail_threshold:
            return 1

    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    schema_validator = None
    if args.schema and os.path.exists(args.schema):
        schema_validator = SchemaValidator.from_file(args.schema)

    env_path = args.env_file
    generator = ExampleGenerator(
        schema_validator=schema_validator,
        empty_values=args.empty,
        annotate=True,
    )

    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        output = generator.generate_from_env_content(content)
    elif schema_validator:
        output = generator.generate_from_schema(schema_validator)
    else:
        print(
            f"Error: Neither .env file '{env_path}' nor schema file were found to generate from.",
            file=sys.stderr,
        )
        return 2

    if args.stdout:
        sys.stdout.write(output)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Generated safe example file at: {args.output}")

    return 0


def cmd_infer(args: argparse.Namespace) -> int:
    env_file = args.env_file
    if not os.path.exists(env_file):
        print(f"Error: Environment file not found: {env_file}", file=sys.stderr)
        return 2

    inferrer = SchemaInferrer()
    schema_data = inferrer.infer_from_file(env_file, mark_all_required=args.all_required)
    output_str = json.dumps(schema_data, indent=2) + "\n"

    if args.stdout:
        sys.stdout.write(output_str)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Inferred schema written to: {args.output}")

    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    source = args.source
    target = args.target

    if not os.path.exists(source):
        print(f"Error: Source file not found: {source}", file=sys.stderr)
        return 2
    if not os.path.exists(target):
        print(f"Error: Target file not found: {target}", file=sys.stderr)
        return 2

    diff = EnvDiffer.compare(source, target, compare_values=args.values)
    print(format_diff_results(diff, as_json=args.json))
    return 1 if diff.has_differences else 0


def cmd_redact(args: argparse.Namespace) -> int:
    env_file = args.env_file
    if not os.path.exists(env_file):
        print(f"Error: Environment file not found: {env_file}", file=sys.stderr)
        return 2

    with open(env_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    entries = parse_env_entries(content)
    redacted_lines = []
    for entry in entries:
        if entry.is_empty_line:
            redacted_lines.append("")
        elif entry.is_comment_only:
            redacted_lines.append(f"#{entry.comment}" if entry.comment else "#")
        elif entry.is_variable and entry.key:
            prefix = "export " if entry.has_export else ""
            val = entry.value or ""
            if not val:
                masked = ""
            elif len(val) <= 4:
                masked = "****"
            else:
                masked = val[:2] + ("*" * (len(val) - 4)) + val[-2:]
            line_str = f"{prefix}{entry.key}={masked}"
            if entry.comment:
                line_str += f" #{entry.comment}"
            redacted_lines.append(line_str)

    output = "\n".join(redacted_lines) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Redacted environment written to: {args.output}")
    else:
        sys.stdout.write(output)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        Colors.disable()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "validate":
        return cmd_validate(args)
    elif args.command == "audit":
        return cmd_audit(args)
    elif args.command == "generate":
        return cmd_generate(args)
    elif args.command == "infer":
        return cmd_infer(args)
    elif args.command == "diff":
        return cmd_diff(args)
    elif args.command == "redact":
        return cmd_redact(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
