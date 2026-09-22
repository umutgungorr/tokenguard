"""Comprehensive test suite for TokenGuard security detection."""

from pathlib import Path

from tokenguard.main import main
from tokenguard.rules import mask_secret
from tokenguard.scanner import Scanner


def test_clean_content_passes() -> None:
    scanner = Scanner()
    findings = scanner.scan_text("username = 'alice'\nport = 8080\nenabled = True")
    assert len(findings) == 0


def test_detects_aws_key() -> None:
    scanner = Scanner()
    dummy_key = "AK" + "IA1234567890ABCDEF"
    findings = scanner.scan_text(f"aws_key = '{dummy_key}'")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-001"
    assert "AKIA" in findings[0].masked_value


def test_detects_github_pat() -> None:
    scanner = Scanner()
    dummy_pat = "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    findings = scanner.scan_text(f"gh_token = '{dummy_pat}'")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-003"


def test_detects_slack_token() -> None:
    scanner = Scanner()
    dummy_slack = "xo" + "xb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
    findings = scanner.scan_text(f"slack_bot = '{dummy_slack}'")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-005"


def test_detects_private_key() -> None:
    scanner = Scanner()
    dummy_rsa = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0..."
    findings = scanner.scan_text(dummy_rsa)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-006"


def test_detects_high_entropy_token() -> None:
    scanner = Scanner(entropy_threshold=3.5)
    dummy_entropy = "p9" + "Xz8Qv2Lm5Kn1Jw7Rt3Yb6Hs4Dg0F"
    findings = scanner.scan_text(f"custom_secret = '{dummy_entropy}'")
    assert len(findings) == 1
    assert findings[0].rule_id == "ENTROPY-001"


def test_masking_does_not_reveal_full_secret() -> None:
    raw = "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz"
    masked = mask_secret(raw)
    assert raw not in masked
    assert "*" in masked
    assert masked.startswith("ghp_")


def test_cli_clean_file_exits_zero(tmp_path: Path) -> None:
    clean_file = tmp_path / "app.py"
    clean_file.write_text("print('hello world')", encoding="utf-8")
    assert main([str(clean_file)]) == 0


def test_cli_dirty_file_exits_one(tmp_path: Path) -> None:
    dirty_file = tmp_path / "config.py"
    dummy_secret = "AK" + "IAIOSFODNN7EXAMPLE"
    dirty_file.write_text(f"secret = '{dummy_secret}'", encoding="utf-8")
    assert main([str(dirty_file)]) == 1
