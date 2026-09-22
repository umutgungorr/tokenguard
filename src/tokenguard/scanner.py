"""Scanner implementation for searching files, directories, and git commits for secrets."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .baseline import compute_fingerprint
from .rules import (
    RULES,
    Confidence,
    Severity,
    calculate_shannon_entropy,
    mask_secret,
)

IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".pytest-tmp",
    "dist",
    "build",
}

IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".exe",
    ".dll",
    ".pyc",
    ".lock",
}


@dataclass(frozen=True, slots=True)
class Finding:
    file_path: str
    line_number: int
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: Confidence
    remediation: str
    masked_value: str
    line_snippet: str
    fingerprint: str


class Scanner:
    """Detects credentials and high-entropy tokens across text streams and files."""

    def __init__(
        self,
        *,
        entropy_threshold: float = 3.8,
        min_entropy_len: int = 24,
        ignored_rules: set[str] | None = None,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_entropy_len = min_entropy_len
        self.ignored_rules = ignored_rules or set()

    def scan_text(self, text: str, source_name: str = "<stdin>") -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            # 1. Check Regex Rules
            matched_rule = False
            for rule in RULES:
                if rule.rule_id in self.ignored_rules:
                    continue
                match = rule.pattern.search(line)
                if match:
                    secret_val = match.group(0)
                    masked = mask_secret(secret_val)
                    fp = compute_fingerprint(source_name, rule.rule_id, masked)
                    findings.append(
                        Finding(
                            file_path=source_name,
                            line_number=idx,
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            remediation=rule.remediation,
                            masked_value=masked,
                            line_snippet=self._sanitize_snippet(line),
                            fingerprint=fp,
                        )
                    )
                    matched_rule = True
                    break

            # 2. Check High Entropy Tokens in word candidates
            if not matched_rule and self.entropy_threshold > 0:
                candidates = re.findall(
                    r"['\"]([A-Za-z0-9+/=_-]{16,})['\"]|\b([A-Za-z0-9+/=_-]{20,})\b",
                    line,
                )
                for cand_tuple in candidates:
                    cleaned_word = cand_tuple[0] or cand_tuple[1]
                    if not cleaned_word:
                        continue
                    if (
                        len(cleaned_word) >= self.min_entropy_len
                        and not cleaned_word.startswith("http")
                        and "/" not in cleaned_word
                        and "\\" not in cleaned_word
                    ):
                        ent = calculate_shannon_entropy(cleaned_word)
                        if ent >= self.entropy_threshold:
                            masked = mask_secret(cleaned_word)
                            fp = compute_fingerprint(source_name, "ENTROPY-001", masked)
                            findings.append(
                                Finding(
                                    file_path=source_name,
                                    line_number=idx,
                                    rule_id="ENTROPY-001",
                                    rule_name="High Entropy Secret Token",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    remediation="Store secret token in an external secrets manager or .env file.",
                                    masked_value=masked,
                                    line_snippet=self._sanitize_snippet(line),
                                    fingerprint=fp,
                                )
                            )
                            break
        return findings

    def scan_file(self, path: Path) -> list[Finding]:
        if not path.is_file() or path.suffix.lower() in IGNORED_EXTENSIONS:
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return self.scan_text(content, source_name=str(path))
        except OSError:
            return []

    def scan_path(self, target: Path) -> list[Finding]:
        if target.is_file():
            return self.scan_file(target)

        findings: list[Finding] = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
            for file in files:
                file_path = Path(root) / file
                findings.extend(self.scan_file(file_path))
        return findings

    def scan_git_staged(self, repo_dir: Path | None = None) -> list[Finding]:
        """Scan staged git changes using git diff."""
        cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
        cwd = str(repo_dir) if repo_dir else None
        try:
            output = subprocess.check_output(cmd, cwd=cwd, text=True, stderr=subprocess.DEVNULL)
            staged_files = [line.strip() for line in output.splitlines() if line.strip()]
        except (subprocess.SubprocessError, OSError):
            return []

        findings: list[Finding] = []
        base = repo_dir or Path.cwd()
        for rel in staged_files:
            full_path = base / rel
            if full_path.exists():
                findings.extend(self.scan_file(full_path))
        return findings

    @staticmethod
    def _sanitize_snippet(line: str) -> str:
        snippet = line.strip()
        if len(snippet) > 80:
            snippet = f"{snippet[:77]}..."
        return snippet
