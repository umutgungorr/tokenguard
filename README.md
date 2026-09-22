# TokenGuard 🛡️

[![CI](https://github.com/umutgungorr/tokenguard/actions/workflows/ci.yml/badge.svg)](https://github.com/umutgungorr/tokenguard/actions/workflows/ci.yml)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-blue?logo=github)](https://docs.github.com/en/code-security/code-scanning)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20external-success.svg)]()

> **Lightweight, zero-dependency Git pre-commit secret scanner with native SARIF & baseline suppression.**  
> Prevent accidental leaks of API tokens, cloud credentials, private keys, and high-entropy secrets *before* they hit your Git history or pull requests.

---

## 🌟 Why TokenGuard?

Accidentally committing secrets (API keys, private keys, cloud tokens) to Git repositories is one of the most widespread security vulnerabilities. Once pushed, revoking tokens and rewriting Git history is costly, noisy, and error-prone.

**TokenGuard** delivers enterprise-ready secret prevention in a lightweight, zero-runtime-dependency Python package:
- **Zero External Dependencies**: Built strictly on the Python Standard Library (`re`, `math`, `argparse`, `pathlib`, `hashlib`, `json`, `subprocess`).
- **Native SARIF v2.1.0**: Generates standard OASIS SARIF reports directly consumable by GitHub Code Scanning Alerts and CI security dashboards.
- **Fingerprinted Baseline Suppression**: Generate a `.tokenguard.baseline` file to grandfather existing legacy or test mock keys without breaking CI builds.
- **Actionable Remediation & Confidence**: Findings include granular confidence ratings (`HIGH`, `MEDIUM`, `LOW`) and exact remediation steps (e.g. key rotation guides).
- **Deterministic Exit Codes**: Seamlessly integrates into CI/CD pipelines (`0` = clean, `1` = unbaselined secrets, `2` = argument / I/O error).
- **Safe Output Masking**: Secrets are automatically masked (e.g. `ghp_************14TeR`) to avoid leaking values into CI terminal logs.

---

## 🔍 Supported Secret Signatures

| Rule ID | Name | Severity | Confidence | Description |
|---------|------|----------|------------|-------------|
| `SEC-001` | AWS Access Key ID | CRITICAL | HIGH | AWS IAM & STS access keys (`AKIA...`, `ASIA...`) |
| `SEC-002` | AWS Secret Access Key | CRITICAL | HIGH | Declared AWS secret access key pairs |
| `SEC-003` | GitHub Access Token | CRITICAL | HIGH | Classic & fine-grained personal access tokens (`ghp_...`, `github_pat_...`) |
| `SEC-004` | OpenAI API Key | CRITICAL | HIGH | OpenAI secret keys (`sk-...`, `sk-proj-...`) |
| `SEC-005` | Slack Bot/User Token | CRITICAL | HIGH | Slack bot, workspace, or user tokens (`xoxb-...`, `xoxp-...`) |
| `SEC-006` | Private Encryption Key | CRITICAL | HIGH | Raw PEM/OpenSSH private key blocks |
| `SEC-007` | Generic API Key Assignment | HIGH | MEDIUM | Hardcoded generic API keys & client secrets |
| `SEC-008` | JSON Web Token (JWT) | MEDIUM | LOW | Raw authorization headers or JWT tokens |
| `ENTROPY-001` | High Shannon Entropy Token | HIGH | HIGH | Arbitrary base64/hex tokens (Entropy $\ge 4.2$) |

---

## 🚀 Quick Start

### 1. Installation

Install via pip in your development environment:

```bash
pip install .
```

Or run directly without installation:

```bash
python -m tokenguard --help
```

### 2. Install as a Git Pre-Commit Hook

Install directly into your repository:

```bash
tokenguard --install-hook
```

This creates an executable `.git/hooks/pre-commit` hook that scans staged changes before every commit.

### 3. Baseline Legacy or Mock Secrets

If your repo contains accepted mock credentials or existing legacy keys, create a baseline:

```bash
# Record all current findings to .tokenguard.baseline
tokenguard --update-baseline

# Future scans will suppress baselined secrets and only fail on NEW leaks!
tokenguard
```

### 4. GitHub Actions & Code Scanning (SARIF)

Generate a SARIF report for GitHub Code Scanning:

```bash
tokenguard --format sarif -o results.sarif
```

#### Option A: Hard Gate / Enforcement (Fails PR on Secrets)
Recommended for security enforcement. Fails the build immediately if unbaselined secrets are detected, while always uploading findings to GitHub Code Scanning:

```yaml
name: TokenGuard Secret Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  tokenguard-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run TokenGuard
        run: |
          python -m tokenguard --format sarif -o results.sarif .

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

> **Why permissions matter**: `security-events: write` is required by GitHub for actions to submit SARIF alerts to the Security tab. `contents: read` is required for repository checkout.

#### Option B: Advisory / Non-blocking Mode
Report findings to the Security tab without failing the CI pipeline:

```yaml
      - name: Run TokenGuard (Advisory)
        run: |
          python -m tokenguard --format sarif -o results.sarif .
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

#### Option C: Official GitHub Marketplace Action
You can also run TokenGuard via its official Marketplace Action:

```yaml
      - name: Run TokenGuard Action
        uses: umutgungorr/tokenguard@v0.2.0
        with:
          format: 'sarif'
          output: 'results.sarif'
```

---

## ⚙️ CLI Options & Flags

```text
usage: tokenguard [-h] [--version] [--staged] [--install-hook]
                  [--format {text,json,sarif}] [-o OUTPUT]
                  [--baseline BASELINE] [--update-baseline]
                  [--entropy-threshold FLOAT] [--ignore-rule RULE_ID]
                  [--no-color] [-q] [-v] [--dry-run]
                  [paths ...]

positional arguments:
  paths                 Files or directories to scan (default: current directory or git staged)

options:
  -h, --help            Show this help message and exit
  --version             Show program's version number and exit
  --staged              Scan git staged files before commit
  --install-hook        Install TokenGuard into local .git/hooks/pre-commit
  --format {text,json,sarif}
                        Report format (default: text)
  -o, --output PATH     Write report output to specified file
  --baseline PATH       Path to baseline file (default: .tokenguard.baseline if present)
  --update-baseline     Record current findings to baseline file and exit 0
  --entropy-threshold FLOAT
                        Shannon entropy threshold for unknown tokens (default: 4.2, 0 to disable)
  --ignore-rule RULE_ID Ignore specific rule (e.g. SEC-008)
  --no-color            Disable ANSI color codes
  -q, --quiet           Suppress scan headers and info messages
  -v, --verbose         Verbose mode
  --dry-run             Simulate execution without returning failure exit codes
```

### Deterministic Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success: Clean (or all findings baselined / dry-run) |
| `1` | Secrets detected: Unbaselined credentials found |
| `2` | Error: Invalid arguments or I/O failure |

---

## 🧪 Running Tests

```bash
uv run --with pytest pytest
```

---

## 🔒 Security & Privacy

TokenGuard runs 100% locally. It never transmits code, tokens, or telemetry over the network.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
