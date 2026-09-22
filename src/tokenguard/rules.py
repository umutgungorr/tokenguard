"""Secret patterns, entropy calculation, and masking rules for TokenGuard."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


# Shannon entropy calculation
def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_secret(secret: str) -> str:
    """Mask a sensitive secret, leaving only small boundary clues."""
    secret = secret.strip()
    if len(secret) <= 8:
        return "*" * len(secret)
    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_middle = "*" * (len(secret) - prefix_len - suffix_len)
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"


# High-precision regular expression rules
RULES: list[SecretRule] = [
    SecretRule(
        rule_id="SEC-001",
        name="AWS Access Key ID",
        pattern=re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        description="Identifies AWS IAM and STS access keys.",
    ),
    SecretRule(
        rule_id="SEC-002",
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"""(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""
        ),
        severity=Severity.CRITICAL,
        description="Identifies declared AWS Secret Access Keys.",
    ),
    SecretRule(
        rule_id="SEC-003",
        name="GitHub Personal Access Token",
        pattern=re.compile(
            r"\b(ghp_[A-Za-z0-9_]{30,40}|gho_[A-Za-z0-9_]{30,40}|github_pat_[A-Za-z0-9_]{70,90})\b"
        ),
        severity=Severity.CRITICAL,
        description="Identifies classic and fine-grained GitHub personal access tokens.",
    ),
    SecretRule(
        rule_id="SEC-004",
        name="OpenAI API Key",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{32,48}|sk-proj-[A-Za-z0-9_-]{48,})\b"),
        severity=Severity.CRITICAL,
        description="Identifies OpenAI secret API keys.",
    ),
    SecretRule(
        rule_id="SEC-005",
        name="Slack API Token",
        pattern=re.compile(r"\b(xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34})\b"),
        severity=Severity.CRITICAL,
        description="Identifies Slack bot, user, or workspace tokens.",
    ),
    SecretRule(
        rule_id="SEC-006",
        name="Private Encryption Key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
            re.MULTILINE,
        ),
        severity=Severity.CRITICAL,
        description="Identifies raw PEM/OpenSSH private key blocks.",
    ),
    SecretRule(
        rule_id="SEC-007",
        name="Generic API Key Assignment",
        pattern=re.compile(
            r"""(?i)(?:api_key|apikey|secret_token|auth_token|client_secret)\s*[:=]\s*["']([A-Za-z0-9_\-.~+/=]{20,})["']"""
        ),
        severity=Severity.HIGH,
        description="Identifies hardcoded generic API keys or authentication secrets.",
    ),
    SecretRule(
        rule_id="SEC-008",
        name="JSON Web Token (JWT)",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.MEDIUM,
        description="Identifies hardcoded JWT authorization headers or tokens.",
    ),
]
