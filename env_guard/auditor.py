"""Secret auditing engine using rule-based pattern matching and entropy analysis."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional, Set

from .patterns import (
    SECRET_RULES,
    calculate_shannon_entropy,
    is_placeholder_value,
    is_sensitive_key_name,
)
from .parser import EnvEntry, parse_env_entries


@dataclass
class AuditFinding:
    file_path: str
    line_number: int
    key: Optional[str]
    rule_id: str
    rule_name: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    sample: str
    entropy: float = 0.0

    def masked_sample(self) -> str:
        s = self.sample.strip()
        if len(s) <= 8:
            return "*" * len(s)
        return s[:4] + ("*" * (len(s) - 8)) + s[-4:]


class SecretAuditor:
    def __init__(
        self,
        entropy_threshold: float = 3.8,
        min_entropy_length: int = 20,
        ignored_keys: Optional[Set[str]] = None,
        ignored_rules: Optional[Set[str]] = None,
    ):
        self.entropy_threshold = entropy_threshold
        self.min_entropy_length = min_entropy_length
        self.ignored_keys = {k.upper() for k in (ignored_keys or set())}
        self.ignored_rules = set(ignored_rules or set())

    def audit_entries(self, entries: List[EnvEntry], file_path: str = ".env") -> List[AuditFinding]:
        findings: List[AuditFinding] = []

        for entry in entries:
            if not entry.is_variable or not entry.key:
                continue

            if entry.key.upper() in self.ignored_keys:
                continue

            val = entry.value or ""
            if not val or is_placeholder_value(val):
                continue

            # 1. Check known secret patterns
            rule_matched = False
            for rule in SECRET_RULES:
                match = rule.pattern.search(val)
                if match:
                    # If it's a database URI, check if credentials are placeholders
                    if rule.rule_id == "SEC013":
                        matched_uri = match.group(0)
                        from urllib.parse import urlparse
                        try:
                            parsed_u = urlparse(matched_uri)
                            if parsed_u.password and is_placeholder_value(parsed_u.password):
                                continue
                        except Exception:
                            pass

                    rule_matched = True
                    if rule.rule_id not in self.ignored_rules:
                        findings.append(
                            AuditFinding(
                                file_path=file_path,
                                line_number=entry.line_number,
                                key=entry.key,
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                description=rule.description,
                                sample=match.group(0),
                                entropy=calculate_shannon_entropy(match.group(0)),
                            )
                        )

            if rule_matched:
                continue

            # 2. Check Shannon Entropy on suspicious or long values
            entropy = calculate_shannon_entropy(val)
            # Hex strings have a theoretical max entropy of 4.0; scale threshold accordingly
            is_hex = all(c in "0123456789abcdefABCDEF" for c in val)
            effective_threshold = 3.5 if is_hex else self.entropy_threshold
            is_common_uri = any(
                val.startswith(pfx)
                for pfx in ("http://", "https://", "redis://", "postgres://", "postgresql://", "mongodb://", "amqp://", "ws://", "wss://")
            )

            if (
                "SEC_ENTROPY" not in self.ignored_rules
                and len(val) >= self.min_entropy_length
                and entropy >= effective_threshold
                and not is_common_uri
            ):
                findings.append(
                    AuditFinding(
                        file_path=file_path,
                        line_number=entry.line_number,
                        key=entry.key,
                        rule_id="SEC_ENTROPY",
                        rule_name="High-Entropy Secret Value",
                        severity="MEDIUM",
                        description=f"Value exhibits high Shannon entropy ({entropy:.2f} >= {effective_threshold:.2f})",
                        sample=val,
                        entropy=entropy,
                    )
                )
                continue

            # 3. Check sensitive key names with non-trivial values
            if (
                "SEC_SENSITIVE_KEY" not in self.ignored_rules
                and is_sensitive_key_name(entry.key)
                and len(val) >= 12
                and not is_placeholder_value(val)
            ):
                findings.append(
                    AuditFinding(
                        file_path=file_path,
                        line_number=entry.line_number,
                        key=entry.key,
                        rule_id="SEC_SENSITIVE_KEY",
                        rule_name="Plaintext Sensitive Key",
                        severity="LOW",
                        description=f"Variable '{entry.key}' matches sensitive naming convention and holds a raw value",
                        sample=val,
                        entropy=entropy,
                    )
                )

        return findings

    def audit_file(self, file_path: str) -> List[AuditFinding]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        entries = parse_env_entries(content)
        return self.audit_entries(entries, file_path=file_path)

    def audit_directory(
        self,
        dir_path: str,
        recursive: bool = True,
        env_files_only: bool = True,
    ) -> List[AuditFinding]:
        all_findings: List[AuditFinding] = []
        skip_dirs = {".git", ".svn", "node_modules", "venv", ".venv", "__pycache__", "build", "dist", ".pytest_cache"}

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                if env_files_only:
                    if not (file == ".env" or file.startswith(".env.") or file.endswith(".env")):
                        continue
                full_path = os.path.join(root, file)
                try:
                    all_findings.extend(self.audit_file(full_path))
                except Exception:
                    continue
            if not recursive:
                break

        return all_findings
