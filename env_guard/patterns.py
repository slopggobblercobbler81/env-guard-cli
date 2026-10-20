"""Known secret pattern definitions, heuristics, and entropy calculations."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import List, Optional, Pattern


@dataclass
class SecretRule:
    rule_id: str
    name: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW
    pattern: Pattern[str]


SECRET_RULES: List[SecretRule] = [
    SecretRule(
        rule_id="SEC001",
        name="AWS Access Key ID",
        description="Identifies Amazon Web Services Access Key identifiers",
        severity="HIGH",
        pattern=re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ),
    SecretRule(
        rule_id="SEC002",
        name="GitHub Personal Access Token",
        description="Identifies GitHub classic or fine-grained personal access tokens",
        severity="HIGH",
        pattern=re.compile(
            r"\b(ghp_[A-Za-z0-9]{30,50}|github_pat_[A-Za-z0-9_]{60,100}|gho_[A-Za-z0-9]{30,50}|ghu_[A-Za-z0-9]{30,50}|ghs_[A-Za-z0-9]{30,50}|ghr_[A-Za-z0-9]{30,50})\b"
        ),
    ),
    SecretRule(
        rule_id="SEC003",
        name="GitLab Personal Access Token",
        description="Identifies GitLab personal access tokens",
        severity="HIGH",
        pattern=re.compile(r"\bglpat-[A-Za-z0-9\-]{20,30}\b"),
    ),
    SecretRule(
        rule_id="SEC004",
        name="Slack Token",
        description="Identifies Slack bot, user, or app tokens",
        severity="HIGH",
        pattern=re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b"),
    ),
    SecretRule(
        rule_id="SEC005",
        name="Stripe Secret / Restricted Key",
        description="Identifies Stripe live secret keys or restricted keys",
        severity="HIGH",
        pattern=re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34}|rk_live_[0-9a-zA-Z]{24,34})\b"),
    ),
    SecretRule(
        rule_id="SEC006",
        name="OpenAI API Key",
        description="Identifies OpenAI legacy or project API secret keys",
        severity="HIGH",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{30,60}|sk-proj-[A-Za-z0-9_\-]{40,160})\b"),
    ),
    SecretRule(
        rule_id="SEC007",
        name="Anthropic API Key",
        description="Identifies Anthropic Claude API keys",
        severity="HIGH",
        pattern=re.compile(r"\bsk-ant-api03-[A-Za-z0-9_\-]{80,110}\b"),
    ),
    SecretRule(
        rule_id="SEC008",
        name="Google Cloud API Key",
        description="Identifies Google Cloud API keys",
        severity="HIGH",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    SecretRule(
        rule_id="SEC009",
        name="SendGrid API Key",
        description="Identifies SendGrid email service API keys",
        severity="HIGH",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ),
    SecretRule(
        rule_id="SEC010",
        name="Twilio API Secret / Token",
        description="Identifies Twilio API key secrets",
        severity="HIGH",
        pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    ),
    SecretRule(
        rule_id="SEC011",
        name="Private Cryptographic Key",
        description="Identifies RSA, EC, DSA, or OPENSSH private keys",
        severity="HIGH",
        pattern=re.compile(r"-----BEGIN\s+(?:[A-Z0-9_\-]+\s+)*KEY-----", re.IGNORECASE),
    ),
    SecretRule(
        rule_id="SEC012",
        name="JSON Web Token (JWT)",
        description="Identifies compact JSON Web Tokens with signature",
        severity="MEDIUM",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    SecretRule(
        rule_id="SEC013",
        name="Database URI with Credentials",
        description="Identifies connection strings exposing database passwords",
        severity="HIGH",
        pattern=re.compile(
            r"\b(?:postgres|postgresql|mysql|mariadb|mongodb|redis|amqp|mssql):\/\/[^:\s]+:[^@\s]+@[^\s]+\b",
            re.IGNORECASE,
        ),
    ),
]

# Common placeholder substrings that indicate mock or placeholder values
COMMON_PLACEHOLDERS = {
    "",
    "xxx",
    "xxxx",
    "test",
    "testing",
    "dev",
    "development",
    "local",
    "dummy",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "your_key",
    "your_secret",
    "your_password",
    "your_token",
    "secret",
    "password",
    "null",
    "none",
    "undefined",
    "00000000",
    "123456",
    "admin",
    "<your_key>",
    "<your_secret>",
    "<your_password>",
    "${SECRET}",
    "$SECRET",
}

SENSITIVE_KEY_PATTERNS = [
    re.compile(
        r".*(SECRET|PASSWORD|PASSWD|PWD|TOKEN|PRIVATE_KEY|AUTH_KEY|CREDENTIAL|ACCESS_KEY|API_KEY).*",
        re.IGNORECASE,
    )
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per symbol) for string data."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder_value(value: str) -> bool:
    """Check if value is an obvious placeholder or dummy string."""
    clean = value.strip().strip("'\"").lower()
    if clean in COMMON_PLACEHOLDERS:
        return True
    if clean.startswith("<") and clean.endswith(">"):
        return True
    if clean.startswith("your_") or clean.startswith("your-") or clean.startswith("your_key"):
        return True
    if clean.startswith("${") and clean.endswith("}"):
        return True
    return False


def is_sensitive_key_name(key: str) -> bool:
    """Check if the environment variable name implies sensitive credentials."""
    return any(pattern.match(key) for pattern in SENSITIVE_KEY_PATTERNS)
