"""TokenGuard - Git Pre-Commit Secret and Token Security Scanner CLI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from .baseline import filter_baseline, load_baseline, save_baseline
from .sarif import to_sarif_json
from .scanner import Finding, Scanner

VERSION = "0.2.0"
DEFAULT_BASELINE_FILE = ".tokenguard.baseline"


def build_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="tokenguard",
        description="TokenGuard: Enterprise zero-dependency pre-commit secret detection CLI.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
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
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format: text (human readable), json (machine parseable), sarif (GitHub Code Scanning)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write report output to specified file path instead of stdout",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Path to baseline file containing known/mock accepted secrets (default: .tokenguard.baseline if present)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Record all currently detected secrets to baseline file and exit 0",
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
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode: suppress scan headers and only print detected findings/errors",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose mode: output diagnostic details during scanning",
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
        print("Error: Not a git repository (.git folder not found). Run inside a git repo root.", file=sys.stderr)
        return 2

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    hook_content = (
        "#!/bin/sh\n"
        "# TokenGuard pre-commit security hook\n"
        "echo '[*] Running TokenGuard pre-commit secret scanner...'\n"
        "tokenguard --staged\n"
        "EXIT_CODE=$?\n"
        "if [ $EXIT_CODE -ne 0 ]; then\n"
        "  echo '[!] Commit blocked by TokenGuard! Remove exposed secrets before committing.'\n"
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


def format_text_findings(findings: list[Finding], baselined_count: int, no_color: bool = False) -> str:
    """Format detected findings with clear visual hierarchy."""
    red = "" if no_color else "\033[91m"
    yellow = "" if no_color else "\033[93m"
    cyan = "" if no_color else "\033[96m"
    bold = "" if no_color else "\033[1m"
    reset = "" if no_color else "\033[0m"

    lines: list[str] = [
        "",
        f"{red}{bold}[!] CRITICAL SECURITY WARNING: Secrets detected in staged/scanned files!{reset}",
        "-" * 72,
    ]

    for f in findings:
        sev_color = red if f.severity.value == "CRITICAL" else yellow
        lines.append(f"  {sev_color}[{f.severity.value}]{reset} {bold}{f.rule_name}{reset} ({f.rule_id}) [Confidence: {f.confidence.value}]")
        lines.append(f"  Location:      {cyan}{f.file_path}:{f.line_number}{reset}")
        lines.append(f"  Masked Secret: {bold}{f.masked_value}{reset}")
        lines.append(f"  Snippet:       {f.line_snippet}")
        lines.append(f"  Fingerprint:   {f.fingerprint[:16]}...")
        lines.append(f"  Remediation:   {f.remediation}")
        lines.append("")

    lines.append("-" * 72)
    summary_text = f"Found {len(findings)} unbaselined secret(s)."
    if baselined_count > 0:
        summary_text += f" ({baselined_count} suppressed via baseline)"
    lines.append(f"{summary_text} Please sanitize your files before committing!\n")
    return "\n".join(lines)


def format_json_findings(findings: list[Finding], baselined_count: int) -> str:
    """Format findings as structured JSON."""
    data = {
        "version": VERSION,
        "findings_count": len(findings),
        "baselined_count": baselined_count,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "remediation": f.remediation,
                "file_path": f.file_path.replace("\\", "/"),
                "line_number": f.line_number,
                "masked_value": f.masked_value,
                "snippet": f.line_snippet,
                "fingerprint": f.fingerprint,
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2)


def main(argv: Sequence[str] | None = None) -> int:
    """Run TokenGuard CLI and return exit code (0: clean, 1: findings, 2: error)."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2

    if args.install_hook:
        return install_git_hook()

    # Determine color output
    use_no_color = args.no_color or ("NO_COLOR" in os.environ)

    # Determine baseline path
    baseline_path: Path | None = args.baseline
    if baseline_path is None and Path(DEFAULT_BASELINE_FILE).is_file():
        baseline_path = Path(DEFAULT_BASELINE_FILE)

    scanner = Scanner(
        entropy_threshold=args.entropy_threshold,
        ignored_rules=set(args.ignore_rule),
    )

    findings: list[Finding] = []

    try:
        if args.staged:
            if not args.quiet and args.format == "text":
                print("[*] Scanning git staged changes for secrets...")
            findings = scanner.scan_git_staged()
        elif args.paths:
            for p in args.paths:
                path_obj = Path(p)
                if not path_obj.exists():
                    print(f"Error: Target path does not exist: {p}", file=sys.stderr)
                    return 2
                findings.extend(scanner.scan_path(path_obj))
        else:
            if not args.quiet and args.format == "text":
                print("[*] Scanning directory for secrets...")
            findings = scanner.scan_path(Path("."))
    except Exception as exc:
        print(f"Error during scan: {exc}", file=sys.stderr)
        return 2

    # Handle update-baseline
    if args.update_baseline:
        target_baseline = args.baseline or Path(DEFAULT_BASELINE_FILE)
        try:
            save_baseline(target_baseline, findings)
            if not args.quiet:
                print(f"[V] Baseline updated: recorded {len(findings)} finding(s) to {target_baseline}")
            return 0
        except OSError as exc:
            print(f"Error writing baseline file {target_baseline}: {exc}", file=sys.stderr)
            return 2

    # Filter findings against baseline if present
    baselined_fps: set[str] = set()
    if baseline_path and baseline_path.is_file():
        baselined_fps = load_baseline(baseline_path)

    unbaselined, baselined = filter_baseline(findings, baselined_fps)
    baselined_count = len(baselined)

    # Generate output
    output_content = ""
    if args.format == "sarif":
        output_content = to_sarif_json(unbaselined)
    elif args.format == "json":
        output_content = format_json_findings(unbaselined, baselined_count)
    else:  # text
        if unbaselined:
            output_content = format_text_findings(unbaselined, baselined_count, no_color=use_no_color)
        elif not args.quiet:
            msg = "[V] Clean! No exposed secrets or API keys detected."
            if baselined_count > 0:
                msg += f" ({baselined_count} suppressed via baseline)"
            output_content = msg

    # Write output to file or stdout
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output_content + "\n", encoding="utf-8")
            if not args.quiet and args.format == "text":
                print(f"[V] Report written to {args.output}")
        except OSError as exc:
            print(f"Error writing output to {args.output}: {exc}", file=sys.stderr)
            return 2
    elif output_content:
        print(output_content)

    if unbaselined:
        if args.dry_run:
            if not args.quiet and args.format == "text":
                print("[i] Dry-run mode: Returning 0 despite findings.")
            return 0
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
