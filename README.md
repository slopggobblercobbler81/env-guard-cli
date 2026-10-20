# 🛡️ env-guard-cli

[![CI](https://github.com/slopggobblercobbler81/env-guard-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/env-guard-cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> A modern, zero-dependency developer CLI to validate `.env` files against schema definitions, audit for committed credentials & high-entropy secrets, and generate safe `.env.example` files.

---

## ✨ Features

- 🛡️ **Schema Validation (`validate`)**: Strongly type-check your environment variables against strict schema definitions. Supports ports, URLs, booleans, integers, floats, emails, IPs, UUIDs, JSON, enums, and custom regex patterns.
- 🔍 **Committed Secret Detection (`audit`)**: Scan local `.env` files or entire project directories for accidental plain-text secrets (AWS, GitHub PATs, Slack, Stripe, OpenAI, Anthropic, private keys, database URIs) and high Shannon entropy random tokens.
- 📝 **Safe Example Generation (`generate`)**: Auto-generate clean, committed `.env.example` templates directly from your active `.env` or schema with smart, descriptive placeholders—without leaking production secrets.
- 🪄 **Schema Inference (`infer`)**: Instant bootstrapping! Infer an `env.schema.json` blueprint automatically from an existing `.env` file.
- ⚖️ **Environment Diffing (`diff`)**: Compare environments (e.g. `.env.example` vs `.env`, or `.env.staging` vs `.env.production`) to pinpoint missing or extra keys before deploying.
- 🎭 **Safe Masking / Redaction (`redact`)**: Safely mask secret credentials for debugging, bug reports, and console logging.
- ⚡ **Zero Mandatory Dependencies**: Runs anywhere on standard Python 3.8+ without third-party package requirements (optional PyYAML for `.yaml` schemas).
- 🤖 **CI/CD & Git Hook Ready**: Emits ANSI colors or machine-readable `--json` with standard UNIX exit codes (0 = clean, 1 = issues found, 2 = usage error).

---

## 🚀 Installation

### Using pip
```bash
pip install env-guard-cli
```

### From source
```bash
git clone https://github.com/slopggobblercobbler81/env-guard-cli.git
cd env-guard-cli
pip install -e .
```

### Standalone (Zero-Install)
You can run `env-guard` directly with standard Python without installing anything:
```bash
python -m env_guard --help
```

---

## 🛠️ CLI Commands & Usage

### 1. Validate `.env` Against a Schema

Ensure that all required variables are set, formatted correctly, and satisfy range or regex constraints:

```bash
# Validate .env against env.schema.json
env-guard validate

# Validate specific files with strict rules (reject undeclared keys)
env-guard validate .env.production --schema schemas/production.json --disallow-extra

# Output machine-readable JSON for CI pipelines
env-guard validate .env --json
```

Sample output:
```text
[FAIL] Found 2 validation issue(s) in .env:

  * PORT:12
    Port number 99999 is outside valid range (1-65535)
    Expected: 1-65535
    Actual:   99999

  * DATABASE_URL:18
    Value 'not-a-url' is not a valid URL (must have scheme e.g. http://, postgres://)
    Expected: valid URL
    Actual:   not-a-url
```

---

### 2. Audit for Secrets and Credentials

Scan your repository or environment files before committing to prevent credential leaks:

```bash
# Audit standard .env file
env-guard audit

# Recursively audit all .env files across the project directory
env-guard audit .

# Audit all files (code, config, logs) for secrets
env-guard audit . --all-files

# Ignore specific false-positive keys or rules
env-guard audit .env --ignore-key PUBLIC_ANALYTICS_KEY --ignore-rule SEC_ENTROPY
```

Sample output:
```text
[ALERT] Detected 2 potential secret(s) or sensitive credential(s):

  [HIGH] AWS Access Key ID at .env:14 (AWS_ACCESS_KEY_ID)
    Rule:   SEC001 - Identifies Amazon Web Services Access Key identifiers
    Sample: AKIA************MPLE (entropy: 3.68)

  [MEDIUM] High-Entropy Secret Value at .env:22 (SESSION_SECRET)
    Rule:   SEC_ENTROPY - Value exhibits high Shannon entropy (4.45 >= 3.80)
    Sample: 9f82************7b2a (entropy: 4.45)
```

---

### 3. Generate Safe `.env.example` Files

Strip live production values and generate a safe `.env.example` with descriptive placeholders:

```bash
# Generate from existing .env
env-guard generate .env -o .env.example

# Generate directly from a schema definition
env-guard generate --schema env.schema.json -o .env.example

# Generate with blank values (KEY=)
env-guard generate .env -o .env.example --empty
```

Generated `.env.example` output:
```bash
# --- REQUIRED CONFIGURATION ---
# Port on which the service listens
# [required, type: port]
PORT=8080

# Main database connection string
# [required, type: url]
DATABASE_URL=postgresql://user:password@localhost:5432/mydb

# Cryptographic key for signing sessions
# [required, type: string]
API_SECRET_KEY=<your_api_secret_key>
```

---

### 4. Infer Schema from Existing `.env`

Bootstrap schema definitions in seconds:

```bash
env-guard infer .env -o env.schema.json
```

This analyzes variable values and generates:
```json
{
  "$schema": "https://raw.githubusercontent.com/slopggobblercobbler81/env-guard-cli/main/schemas/env-guard.schema.json",
  "version": "1.0",
  "variables": {
    "PORT": {
      "type": "port",
      "required": true
    },
    "DATABASE_URL": {
      "type": "url",
      "required": true
    },
    "JWT_SECRET": {
      "type": "string",
      "required": true,
      "secret": true
    }
  }
}
```

---

### 5. Compare & Diff Environment Files

Verify synchronization between `.env.example` and developer `.env` files:

```bash
# Verify developer has all variables defined in .env.example
env-guard diff .env.example .env

# Check differences including values
env-guard diff .env.staging .env.production --values
```

---

### 6. Mask / Redact Credentials

Print or export a safe, masked version of your `.env` for logs and debugging:

```bash
# Print redacted variables to stdout
env-guard redact .env

# Export to a safe sanitized file
env-guard redact .env -o .env.sanitized
```

---

## 📋 Schema Definition Reference

| Field | Type | Description |
|---|---|---|
| `type` | string | `string`, `int`/`integer`, `float`/`number`, `bool`/`boolean`, `port`, `url`, `email`, `ip`, `json`, `base64`, `uuid` |
| `required` | boolean | Variable must be present and non-empty |
| `default` | string/any | Default value placeholder |
| `enum` | array | List of permissible literal values |
| `pattern` | string | Regular expression that value must match |
| `min` / `max` | number | Numeric value boundary |
| `min_length` / `max_length` | integer | String length boundary |
| `secret` | boolean | Flags variable as containing sensitive credentials |
| `description` | string | Documentation string for humans and generated examples |

---

## 🔍 Built-in Secret Detection Rules

| Rule ID | Detector | Severity |
|---|---|---|
| `SEC001` | Amazon Web Services (AWS) Access Key ID | **HIGH** |
| `SEC002` | GitHub Personal Access Tokens (`ghp_`, `github_pat_`) | **HIGH** |
| `SEC003` | GitLab Personal Access Tokens (`glpat-`) | **HIGH** |
| `SEC004` | Slack Bot / User / App Tokens (`xoxb-`, `xoxp-`) | **HIGH** |
| `SEC005` | Stripe Secret & Restricted Keys (`sk_live_`, `rk_live_`) | **HIGH** |
| `SEC006` | OpenAI API Keys (`sk-`, `sk-proj-`) | **HIGH** |
| `SEC007` | Anthropic Claude API Keys (`sk-ant-`) | **HIGH** |
| `SEC008` | Google Cloud API Keys (`AIza...`) | **HIGH** |
| `SEC009` | SendGrid API Keys (`SG...`) | **HIGH** |
| `SEC010` | Twilio API Secret Keys (`SK...`) | **HIGH** |
| `SEC011` | RSA / EC / OPENSSH Private Keys (`-----BEGIN...KEY-----`) | **HIGH** |
| `SEC012` | JSON Web Tokens (JWT) (`eyJ...`) | **MEDIUM** |
| `SEC013` | Database URI Exposing Plaintext Passwords | **HIGH** |
| `SEC_ENTROPY` | High Shannon Entropy Random String Heuristic | **MEDIUM** |
| `SEC_SENSITIVE_KEY` | Plaintext Credential in Sensitive Variable Name | **LOW** |

---

## 🛡️ Git Pre-Commit Hook Integration

Add `env-guard` to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: env-guard-audit
        name: env-guard secret audit
        entry: env-guard audit
        args: [".", "--fail-on", "HIGH"]
        language: python
        files: ^\.env
```

---

## 🐍 Python SDK API Usage

You can also use `env-guard` as a Python library inside your application:

```python
from env_guard import SchemaValidator, SecretAuditor, parse_env_entries

# Validate environment
validator = SchemaValidator.from_file("env.schema.json")
with open(".env") as f:
    entries = parse_env_entries(f.read())

errors = validator.validate_entries(entries)
if errors:
    print(f"Validation failed: {errors[0].message}")

# Audit for secrets
auditor = SecretAuditor()
findings = auditor.audit_entries(entries)
for finding in findings:
    print(f"[{finding.severity}] {finding.rule_name} on line {finding.line_number}")
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Feel free to check [issues page](https://github.com/slopggobblercobbler81/env-guard-cli/issues).

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/amazing-feature`)
3. Commit your Changes (`git commit -m 'feat: Add amazing feature'`)
4. Push to the Branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
