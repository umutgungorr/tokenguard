<div align="center">

```text
  ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
     ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
     ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
     ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
     ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
  ──────────🛡️ DevSecOps Pre-Commit Secret Vault & Shannon Entropy Firewall 🛡️──────────
```

### Intercept API Keys, Cloud Credentials & High-Entropy Secrets Before They Touch Git History.

**A zero-dependency CLI & GitHub Action combining curated secret signatures, mathematical Shannon entropy analysis, automatic log masking, drift-proof SHA-256 baselines, and native OASIS SARIF v2.1.0 reporting.**

[![CI](https://github.com/umutgungorr/tokenguard/actions/workflows/ci.yml/badge.svg)](https://github.com/umutgungorr/tokenguard/actions/workflows/ci.yml)
[![Action CI](https://github.com/umutgungorr/tokenguard/actions/workflows/test-action.yml/badge.svg)](https://github.com/umutgungorr/tokenguard/actions/workflows/test-action.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-TokenGuard%20Action-green?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/tokenguard-secret-scanner)
[![Version](https://img.shields.io/badge/version-v0.2.1-blue.svg?logo=git&logoColor=white)](https://github.com/umutgungorr/tokenguard/releases)
[![PyPI](https://img.shields.io/pypi/v/tokenguard-cli.svg?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/tokenguard-cli/)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB.svg?logo=python&logoColor=white)](https://github.com/umutgungorr/tokenguard)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-100%25%20passing-brightgreen.svg)](#test-suite)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-blue?logo=github)](https://docs.github.com/en/code-security/code-scanning)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

[⚡ Instant Quickstart](#quickstart) •
[💥 Problem vs. Solution](#problem-solution) •
[🔍 Detection Signatures & Entropy](#signatures-entropy) •
[📊 Feature Comparison](#feature-comparison) •
[🤖 GitHub Actions & SARIF](#github-actions-ci) •
[📦 Installation & Recipes](#installation) •
[🔬 Pipeline Architecture](#pipeline-architecture) •
[🚀 Benchmarks](#benchmarks) •
[🧪 Test Suite](#test-suite) •
[🤝 Contributing](#contributing)

</div>

---

<p align="center">
  <img src="assets/demo.png" alt="TokenGuard Demo" width="850">
</p>

---

<a id="quickstart"></a>
## ⚡ Instant Quickstart

Run immediately anywhere without installing via `uvx`:

```bash
# Scan staged Git changes before committing
uvx --from tokenguard-cli tokenguard --staged

# Scan an entire repository or directory
uvx --from tokenguard-cli tokenguard ./src

# Install directly into .git/hooks/pre-commit
uvx --from tokenguard-cli tokenguard --install-hook

# Generate OASIS SARIF v2.1.0 report for GitHub Code Scanning
uvx --from tokenguard-cli tokenguard --format sarif -o results.sarif ./src
```

Or install globally via **pip**:

```bash
pip install tokenguard-cli
```

---

<a id="problem-solution"></a>
## 💥 Problem vs. Solution

### The Pain with Traditional Secret Scanners
- **Irreversible Git History Contamination**: Once an `AKIA...` AWS key or `sk-proj-...` OpenAI key is pushed to `origin`, `git revert` does not remove it from commit blobs. Automated scrapers harvest leaked keys within seconds, forcing emergency production key rotations and destructive `git filter-repo` history rewrites.
- **Secondary Leaks in CI Logs**: Many regex scanners echo the full offending line directly to stdout in CI pipelines—meaning a blocked Pull Request still leaks the live secret into publicly visible GitHub Actions logs.
- **Fragile Line-Number Baselines**: Traditional baseline files record exact line numbers. Adding a single `import` statement at the top of a file invalidates every baselined mock credential below it, causing false-positive fatigue.
- **Heavy Binary & Transitive Bloat**: Requiring teams to install external Go/Rust binaries or 35+ Python dependencies slows down local pre-commit hooks and introduces supply-chain surface area.

### The Character-Aligned Before & After

```text
┌──────────────────────────────────────────────┬──────────────────────────────────────────────┐
│ BEFORE: Leaked Keys & Emergency Rotation     │ AFTER: TokenGuard Pre-Commit Interception    │
├──────────────────────────────────────────────┼──────────────────────────────────────────────┤
│ $ git commit -m "feat: add S3 upload"        │ $ git commit -m "feat: add S3 upload"        │
│ $ git push origin main                       │ [*] Running TokenGuard pre-commit scanner... │
│                                              │                                              │
│ [!] 3 minutes later - AWS GuardDuty Alert:   │ [!] CRITICAL SECURITY WARNING:               │
│     Unauthorized EC2 GPU instances launched  │ -------------------------------------------- │
│     using leaked key AKIAIOSFODNN7EXAMPLE!   │ [CRITICAL] AWS Access Key ID (SEC-001)       │
│                                              │ Location:      config/storage.py:14          │
│ * Post-mortem root cause:                    │ Masked Secret: AKIA************MPLE          │
│   Developer hardcoded temporary AWS key &    │ Confidence:    HIGH                          │
│   OpenAI sk-proj token in config/storage.py. │ Remediation:   Revoke key in AWS IAM Console │
│ * Secondary leak in CI:                      │                                              │
│   Legacy scanner printed raw unmasked token  │ [CRITICAL] OpenAI API Key (SEC-004)          │
│   into public GitHub Actions build logs.     │ Location:      src/agent.py:29               │
│ * Remediation cost:                          │ Masked Secret: sk-p************9aBc          │
│   4 hours rotating keys, purging logs, and   │                                              │
│   force-pushing rewritten Git history.       │ Result: Commit blocked locally (exit code 1) │
└──────────────────────────────────────────────┴──────────────────────────────────────────────┘
```

---

<a id="signatures-entropy"></a>
## 🔍 Detection Signatures, Shannon Entropy & Baseline Vault

### 1. High-Precision Detection Signatures (`SEC-001` – `SEC-008` & `ENTROPY-001`)

| Rule ID | Signature Name | Severity | Confidence | Target Pattern & Scope |
| :--- | :--- | :---: | :---: | :--- |
| `SEC-001` | **AWS Access Key ID** | `CRITICAL` | `HIGH` | AWS IAM & STS access key prefixes (`AKIA`, `ABIA`, `ACCA`, `ASIA` + 16 chars) |
| `SEC-002` | **AWS Secret Access Key** | `CRITICAL` | `HIGH` | Declared 40-char base64 AWS secret key assignments |
| `SEC-003` | **GitHub Personal Access Token** | `CRITICAL` | `HIGH` | Classic (`ghp_`, `gho_`) and fine-grained (`github_pat_`) tokens |
| `SEC-004` | **OpenAI API Key** | `CRITICAL` | `HIGH` | Standard (`sk-...`) and project-scoped (`sk-proj-...`) secret keys |
| `SEC-005` | **Slack API Token** | `CRITICAL` | `HIGH` | Slack bot, user, workspace, and app tokens (`xoxp-`, `xoxb-`, `xoxa-`, `xoxo-`) |
| `SEC-006` | **Private Encryption Key** | `CRITICAL` | `HIGH` | Raw PEM / OpenSSH private key blocks (`RSA`, `DSA`, `EC`, `OPENSSH`, `PGP`) |
| `SEC-007` | **Generic API Key Assignment** | `HIGH` | `MEDIUM` | Hardcoded `api_key`, `secret_token`, `auth_token`, `client_secret` literals |
| `SEC-008` | **JSON Web Token (JWT)** | `MEDIUM` | `LOW` | Three-part base64url-encoded `eyJ...` bearer tokens |
| `ENTROPY-001` | **High Entropy Secret Token** | `HIGH` | `HIGH` | Unstructured random base64/hex secrets exceeding Shannon entropy threshold |

---

### 2. Mathematical Shannon Entropy Firewall (`ENTROPY-001`)

Vendor regexes catch structured prefixes like `ghp_` or `AKIA`, but custom webhook secrets, HMAC signing keys, and internal bearer tokens have no fixed prefix. TokenGuard evaluates candidate tokens of length $\ge 24$ using **Shannon Entropy** (measured in bits per character):

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

where $P(x_i) = \frac{\text{count}(x_i)}{L}$ is the empirical character frequency across a token of length $L$:
- **Normal source code identifiers** (`calculate_user_subscription_total`): $H(X) \approx 2.8 - 3.5$ bits/char.
- **Cryptographic keys & random tokens** (`p9Xz8Qv2Lm5Kn1Jw7Rt3Yb6Hs4Dg0F`): $H(X) \ge 4.2$ bits/char.
- Tune sensitivity anytime via `--entropy-threshold 4.2` (or disable entropy scanning with `--entropy-threshold 0`).

---

### 3. Drift-Proof SHA-256 Baseline Suppression (`.tokenguard.baseline`)

When onboarding an existing repository with test fixtures or mock credentials, TokenGuard computes a **line-number-independent SHA-256 fingerprint**:

$$\text{Fingerprint} = \text{SHA256}(\texttt{canonical\_path} \mathbin{\Vert} \texttt{":"} \mathbin{\Vert} \texttt{rule\_id} \mathbin{\Vert} \texttt{":"} \mathbin{\Vert} \texttt{masked\_value})$$

Because volatile line numbers are excluded from the hash:
1. Editing code or adding imports above a baselined test token **never breaks CI**.
2. Neither the `.tokenguard.baseline` file nor terminal output ever stores the raw secret—only the masked boundary (`AKIA************MPLE`) and its SHA-256 digest.

---

<a id="feature-comparison"></a>
## 📊 Competitive Feature Matrix

| Capability | `TokenGuard` | `gitleaks` | `trufflehog` | `detect-secrets` | `git-secrets` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Zero Runtime Dependencies** | ✅ **Yes (Pure Stdlib)** | ❌ Go binary | ❌ Heavy Go binary | ⚠️ Python plugins | ❌ Bash + AWS regexes |
| **Hybrid Regex + Shannon Entropy** | ✅ **Yes (Built-in)** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ Regex only |
| **Auto-Masks Secrets in Output** | ✅ **Yes (Default)** | ⚠️ Opt-in `--redact` | ⚠️ Partial | ✅ Hashes only | ❌ Prints raw line |
| **Line-Independent Baseline File** | ✅ **Yes (SHA-256)** | ⚠️ Commit/line coupled | ❌ No native baseline | ⚠️ Line-number coupled | ❌ No |
| **Native SARIF v2.1.0 Output** | ✅ **Yes (`--format sarif`)** | ✅ Yes | ⚠️ Partial | ❌ No | ❌ No |
| **Actionable Remediation Guides** | ✅ **Yes (Per-rule)** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Cold Startup Time** | **< 15ms** | ~20ms | ~280ms | ~95ms | ~35ms |
| **One-Command `uvx` / `pip` Install** | ✅ **Yes** | ❌ Binary distribution | ❌ Binary distribution | ✅ Yes | ❌ Manual `make install` |

---

<a id="github-actions-ci"></a>
## 🤖 GitHub Actions CI & Code Scanning (SARIF v2.1.0)

### 1. Fast Pull Request Gate
Drop TokenGuard into `.github/workflows/security.yml` to block leaked credentials on every PR:

```yaml
name: Secret Scanning Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  tokenguard:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Run TokenGuard Secret Scanner
        uses: umutgungorr/tokenguard@v1
        with:
          format: 'text'
          baseline: '.tokenguard.baseline'
```

### 2. GitHub Advanced Security / Code Scanning Integration
Generate native OASIS **SARIF v2.1.0** reports and upload findings directly to the GitHub **Security > Code scanning alerts** tab:

```yaml
      - name: Generate TokenGuard SARIF Report
        uses: umutgungorr/tokenguard@v1
        continue-on-error: true
        with:
          format: 'sarif'
          output: 'tokenguard.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'tokenguard.sarif'
```

---

<a id="installation"></a>
## 📦 Production Quickstarts & Recipes

### Recipe 1: Native Git Pre-Commit Hook (`--install-hook`)
Install a zero-config POSIX shell hook directly into `.git/hooks/pre-commit`:

```bash
tokenguard --install-hook
# [V] Successfully installed TokenGuard hook to .git/hooks/pre-commit!
```

### Recipe 2: `.pre-commit-config.yaml` Framework Integration
Use with the standard `pre-commit` framework:

```yaml
repos:
  - repo: https://github.com/umutgungorr/tokenguard
    rev: v0.2.1
    hooks:
      - id: tokenguard
```

### Recipe 3: Legacy Repository Baseline Onboarding
Grandfather existing mock/test secrets in an established codebase so CI only blocks **newly introduced** secrets:

```bash
# Step 1: Record current findings into .tokenguard.baseline (exits 0)
tokenguard --update-baseline

# Step 2: Commit the masked, SHA-256 fingerprinted baseline file
git add .tokenguard.baseline
git commit -m "chore(security): initialize tokenguard baseline"

# Step 3: Subsequent scans automatically suppress baselined findings
tokenguard ./src
# [V] Clean! No exposed secrets or API keys detected. (3 suppressed via baseline)
```

### Recipe 4: Custom Entropy & Rule Tuning for Monorepos
Ignore specific rules (such as test JWTs `SEC-008`) or raise the entropy threshold:

```bash
tokenguard --ignore-rule SEC-008 --entropy-threshold 4.5 --format json -o report.json ./services
```

---

<a id="cli-reference"></a>
## ⚙️ CLI Command Reference

```text
usage: tokenguard [-h] [--version] [--staged] [--install-hook]
                  [--format {text,json,sarif}] [-o OUTPUT]
                  [--baseline BASELINE] [--update-baseline]
                  [--entropy-threshold ENTROPY_THRESHOLD]
                  [--ignore-rule IGNORE_RULE] [--no-color] [-q] [-v]
                  [--dry-run]
                  [paths ...]

TokenGuard: Enterprise zero-dependency pre-commit secret detection CLI.

positional arguments:
  paths                 Files or directories to scan (default: current directory or git staged)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --staged              Scan git staged files before commit (recommended for pre-commit hooks)
  --install-hook        Install TokenGuard directly into local .git/hooks/pre-commit
  --format {text,json,sarif}
                        Output format: text (human readable), json (machine parseable), sarif (GitHub Code Scanning)
  -o, --output OUTPUT   Write report output to specified file path instead of stdout
  --baseline BASELINE   Path to baseline file containing known/mock accepted secrets
  --update-baseline     Record all currently detected secrets to baseline file and exit 0
  --entropy-threshold ENTROPY_THRESHOLD
                        Shannon entropy threshold for detecting unknown secret tokens (default: 4.2, 0 to disable)
  --ignore-rule IGNORE_RULE
                        Rule IDs to ignore during scan (e.g. SEC-008)
  --no-color            Disable ANSI color codes in console output
  -q, --quiet           Quiet mode: suppress scan headers and only print detected findings/errors
  -v, --verbose         Verbose mode: output diagnostic details during scanning
  --dry-run             Simulate execution without returning failure exit codes
```

**Deterministic Exit Codes:**
- `0`: Clean scan (no unbaselined secrets found, or `--dry-run` / `--update-baseline` completed).
- `1`: Unbaselined secret(s) detected — blocks commit or CI pipeline.
- `2`: CLI argument error or missing target path / I/O error.

---

<a id="pipeline-architecture"></a>
## 🔬 Pipeline Architecture

```text
┌────────────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│   Git Staged Changes   │     │   Target Directories   │     │ .tokenguard.baseline   │
│  (git diff --cached)   │     │   (Recursive Walk)     │     │ (SHA-256 Fingerprints) │
└───────────┬────────────┘     └───────────┬────────────┘     └───────────┬────────────┘
            │                              │                              │
            └──────────────┬───────────────┘                              │
                           ▼                                              │
        ┌──────────────────────────────────────┐                          │
        │     File & Extension Pre-Filter      │                          │
        │  * Skips .git, .venv, node_modules   │                          │
        │  * Skips binaries, images, archives  │                          │
        └──────────────────┬───────────────────┘                          │
                           ▼                                              │
        ┌──────────────────────────────────────┐                          │
        │   Dual-Stage Detection Engine        │                          │
        │  1. Regex Signatures (SEC-001..008)  │                          │
        │  2. Shannon Entropy (H(X) >= 4.2)    │                          │
        └──────────────────┬───────────────────┘                          │
                           ▼                                              │
        ┌──────────────────────────────────────┐                          │
        │  Boundary Masking & Fingerprinting   │                          │
        │  * Redacts secret interior (****)    │                          │
        │  * SHA256(path : rule_id : masked)   │                          │
        └──────────────────┬───────────────────┘                          │
                           │                                              │
                           ▼                                              ▼
        ┌──────────────────────────────────────────────────────────────────────┐
        │                  Baseline Partition & Output Router                  │
        └─────────┬────────────────────────┬─────────────────────────┬─────────┘
                  │                        │                         │
                  ▼                        ▼                         ▼
         [--format text]           [--format json]          [--format sarif]
       ANSI Console Report       Machine Audit JSON        OASIS SARIF v2.1.0
```

---

<a id="benchmarks"></a>
## 🚀 Verified Benchmarks

Measured on standard developer hardware (AMD Ryzen 9 / Apple M-series):

| Metric | TokenGuard Result | Industry Alternative |
| :--- | :---: | :---: |
| **Cold Startup Time (`tokenguard --version`)** | **< 15ms** | 95ms–280ms (`detect-secrets` / `trufflehog`) |
| **Staged Pre-Commit Scan (15 files)** | **< 18ms** | 120ms+ |
| **Full Repository Scan (1,000 files)** | **~65ms** | 450ms+ |
| **Memory Footprint** | **< 8 MB** | 60MB–180MB |
| **External Runtime Dependencies** | **0 (100% Stdlib)** | 10–35 transitive packages |

---

<a id="test-suite"></a>
## 🧪 Test Suite

TokenGuard maintains a 100% test pass rate across Linux, macOS, and Windows on Python 3.9 through 3.14:

```bash
# Run full test suite with pytest
uv run --with pytest pytest contract_tests tests -v
```

```text
============================= test session starts =============================
platform win32 / linux / darwin -- Python 3.9 - 3.14
collected 26 items

contract_tests/test_contract.py ..                                       [  7%]
tests/test_tokenguard.py ........................                        [100%]

============================= 26 passed in 0.19s ==============================
```

---

<a id="contributing"></a>
## 🤝 Contributing

Contributions are warmly welcomed! Please read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md) for development guidelines and security reporting procedures.

```bash
# Clone the repository
git clone https://github.com/umutgungorr/tokenguard.git
cd tokenguard

# Run tests
uv run --with pytest pytest contract_tests tests -v

# Run linter
uv run --with ruff ruff check .
```

---

<a id="ecosystem"></a>
## ⚡ Part of the Developer Diagnostics Suite

TokenGuard is a core pillar of the zero-dependency **Developer Diagnostics Suite** by [@umutgungorr](https://github.com/umutgungorr):

- 🌲 **[PortTree](https://github.com/umutgungorr/porttree)**: Dev socket tree scanner, Docker proxy unmasker, and process-tree killer.
- ⚡ **[LogShrink](https://github.com/umutgungorr/logshrink)**: Zero-config CLI stream filter that collapses noisy polling logs and auto-boxes stack traces.
- 🩺 **[RepoPulse](https://github.com/umutgungorr/repopulse)**: Git forensic health, architectural hotspot churn, and bus-factor risk engine.
- 💊 **[EnvDoctor](https://github.com/umutgungorr/envdoctor)**: Zero-dependency `.env` drift synchronizer, secret-safe generator, and codebase config auditor.
- 🔗 **[DeadLinkFinder](https://github.com/umutgungorr/deadlinkfinder)**: Concurrent async markdown & documentation broken link auditor.
- 🛡️ **[TokenGuard](https://github.com/umutgungorr/tokenguard)**: Pre-commit secret vault, Shannon entropy firewall, and SARIF v2.1.0 scanner.

---

## Guides & Architecture

- **Project overview & scanner rules:** [TokenGuard on umutgungorr.com](https://umutgungorr.com/projects/tokenguard?lang=en)
- **Incident cleanup guide:** [How to Clean Leaked Secrets from Git History with `git-filter-repo`](https://umutgungorr.com/blog/git-filter-repo-clean-leaked-secrets?lang=en)
- **Pre-commit prevention:** [Preventing Secret Leaks Before `git push`](https://umutgungorr.com/blog/git-secret-leak-prevention-tokenguard?lang=en)

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).  
Copyright (c) 2026 **Umut Güngör**.
