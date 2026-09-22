"""TokenGuard - Git Pre-Commit Secret and Token Security Scanner CLI."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .scanner import Finding, Scanner


def build_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="tokenguard",
        description="TokenGuard: Fast pre-commit secret detection CLI to prevent leaking API keys and tokens.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan git staged files before commit (recommended for pre-commit hooks)",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install TokenGuard directly into local .git/hooks/pre-commit",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.2,
        help="Shannon entropy threshold for detecting unknown secret tokens (default: 4.2, 0 to disable)",
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        help="Rule IDs to ignore during scan (e.g. SEC-008)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without returning failure exit codes",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=[],
        help="Files or directories to scan (default: current directory or git staged)",
    )
    return parser


def install_git_hook() -> int:
    """Install TokenGuard as a pre-commit git hook."""
    git_dir = Path(".git")
    if not git_dir.exists() or not git_dir.is_dir():
        print("❌ Error: Not a git repository (.git folder not found). Run inside a git repo root.")
        return 1

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    hook_content = (
        "#!/bin/sh\n"
        "# TokenGuard pre-commit security hook\n"
        "echo '🛡️  Running TokenGuard pre-commit secret scanner...'\n"
        "tokenguard --staged\n"
        "EXIT_CODE=$?\n"
        "if [ $EXIT_CODE -ne 0 ]; then\n"
        "  echo '🚨 Commit blocked by TokenGuard! Remove exposed secrets before committing.'\n"
        "  exit 1\n"
        "fi\n"
        "exit 0\n"
    )

    hook_file.write_text(hook_content, encoding="utf-8")
    try:
        hook_file.chmod(0o755)
    except OSError:
        pass

    print("[V] Successfully installed TokenGuard hook to .git/hooks/pre-commit!")
    return 0


def format_findings(findings: list[Finding]) -> str:
    """Format detected findings with clear visual hierarchy."""
    lines: list[str] = [
        "",
        "[!] CRITICAL SECURITY WARNING: Secrets detected in staged/scanned files!",
        "-" * 70,
    ]

    for f in findings:
        lines.append(f"  [{f.severity.value}] {f.rule_name} ({f.rule_id})")
        lines.append(f"  Location:      {f.file_path}:{f.line_number}")
        lines.append(f"  Masked Secret: {f.masked_value}")
        lines.append(f"  Snippet:       {f.line_snippet}")
        lines.append("")

    lines.append("-" * 70)
    lines.append(f"Found {len(findings)} secret(s). Please sanitize your files before committing!\n")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run TokenGuard CLI and return exit code."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code if exc.code is not None else 0)

    if args.install_hook:
        return install_git_hook()

    scanner = Scanner(
        entropy_threshold=args.entropy_threshold,
        ignored_rules=set(args.ignore_rule),
    )

    findings: list[Finding] = []

    if args.staged:
        print("[*] Scanning git staged changes for secrets...")
        findings = scanner.scan_git_staged()
    elif args.paths:
        for p in args.paths:
            findings.extend(scanner.scan_path(Path(p)))
    else:
        # Default: scan current directory
        print("[*] Scanning directory for secrets...")
        findings = scanner.scan_path(Path("."))

    if findings:
        print(format_findings(findings))
        if args.dry_run:
            print("[i] Dry-run mode: Returning 0 despite findings.")
            return 0
        return 1

    print("[V] Clean! No exposed secrets or API keys detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
