# TokenGuard 🛡️

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-11%20passed-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20external-success.svg)]()

> **Lightweight, zero-dependency Git pre-commit secret and token scanner.**  
> Prevent accidental leaks of API tokens, cloud credentials, private keys, and high-entropy secrets *before* they hit your Git history.

---

## 🌟 Why TokenGuard?

Accidentally committing secrets (API keys, private keys, cloud tokens) to public or private Git repositories is one of the most common security breaches. Once pushed, revoking tokens and rewriting Git history is painful and error-prone.

**TokenGuard** solves this by acting as both a standalone scanner and a seamless Git pre-commit hook:
- **Zero External Dependencies**: Built strictly using the Python Standard Library (`re`, `math`, `argparse`, `pathlib`, `subprocess`).
- **Pre-Commit Hook Integration**: Single command setup (`--install-hook`) blocks risky commits instantly.
- **Dual-Engine Detection**: Combines deterministic high-precision Regex signatures with Shannon Entropy analysis to catch both known key formats and arbitrary random tokens.
- **Safe CLI Output**: Secrets are automatically masked (e.g. `ghp_************14TeR`) to avoid leaking values into your terminal logs or CI output.
- **Staged Git Changes Only**: With `--staged`, only files queued for commit are scanned for maximum speed.

---

## 🔍 Supported Secret Signatures

| Rule ID | Name | Severity | Example Pattern |
|---------|------|----------|-----------------|
| `SEC-001` | AWS Access Key ID | CRITICAL | `AKIA...` (20 chars) |
| `SEC-002` | GitHub Personal Access Token | CRITICAL | `ghp_...`, `gho_...`, `ghu_...` |
| `SEC-003` | Slack Bot/User Token | CRITICAL | `xoxb-...`, `xoxp-...` |
| `SEC-004` | RSA / OpenSSH Private Key | CRITICAL | `-----BEGIN (RSA\|OPENSSH\|EC) PRIVATE KEY-----` |
| `SEC-005` | OpenAI API Key | HIGH | `sk-proj-...`, `sk-...` |
| `SEC-006` | Generic API Secret Assignment | HIGH | `api_key = "..."`, `secret_token: "..."` |
| `SEC-007` | JSON Web Token (JWT) | MEDIUM | `eyJhbGci...eyJ...` |
| `ENTROPY-001` | High Shannon Entropy Token | HIGH | Arbitrary base64/hex random tokens (Entropy $\ge 4.2$) |

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

Run this inside any Git repository:

```bash
python -m tokenguard --install-hook
```

This creates executable `.git/hooks/pre-commit` which automatically runs TokenGuard on every `git commit`. If secrets are detected, the commit is blocked with an exit code of `1`.

### 3. Scanning Git Staged Files

Scan only the files currently staged for commit:

```bash
python -m tokenguard --staged
```

### 4. Scanning Files or Directories

Scan a specific file or recursively scan an entire project directory:

```bash
# Scan a specific file
python -m tokenguard config/settings.py

# Recursively scan a folder
python -m tokenguard ./src
```

---

## ⚙️ CLI Options & Flags

```text
usage: tokenguard [-h] [--staged] [--install-hook] [--entropy-threshold FLOAT]
                  [--dry-run] [paths ...]

TokenGuard - Git Pre-Commit Secret and Token Scanner

positional arguments:
  paths                 Paths to files or directories to scan (default: current directory)

options:
  -h, --help            show this help message and exit
  --staged              Scan only git staged files (via git diff --cached)
  --install-hook        Install TokenGuard as a git pre-commit hook in .git/hooks/
  --entropy-threshold FLOAT
                        Shannon entropy threshold for random token detection (default: 4.2, 0 to disable)
  --dry-run             Scan files without failing with exit code 1 (audit mode)
```

---

## 🧪 Running Tests

TokenGuard has a complete test suite covering all secret rules, Shannon entropy algorithms, git staged scanning, and CLI contracts:

```bash
# Run tests with pytest
pytest tests contract_tests -v
```

---

## 🔒 Security & Privacy

TokenGuard runs 100% locally on your machine. It makes zero network requests and does not transmit code, tokens, or telemetry anywhere.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
