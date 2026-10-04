"""Comprehensive test suite for TokenGuard security detection, SARIF, and baselines."""

import json
from pathlib import Path

from tokenguard.baseline import compute_fingerprint, filter_baseline, load_baseline, save_baseline
from tokenguard.main import main
from tokenguard.rules import mask_secret
from tokenguard.sarif import generate_sarif, to_sarif_json
from tokenguard.scanner import Finding, Scanner


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
    assert findings[0].confidence.value == "HIGH"
    assert "remediation" in findings[0].remediation.lower() or len(findings[0].remediation) > 0


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


def test_sarif_generation() -> None:
    scanner = Scanner()
    dummy_key = "AK" + "IA1234567890ABCDEF"
    findings = scanner.scan_text(f"aws_key = '{dummy_key}'", source_name="config/aws.py")
    sarif = generate_sarif(findings)

    assert sarif["version"] == "2.1.0"
    assert "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master" in sarif["$schema"]
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "TokenGuard"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "SEC-001"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config/aws.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_baseline_save_load_filter(tmp_path: Path) -> None:
    scanner = Scanner()
    dummy_key = "AK" + "IA1234567890ABCDEF"
    findings = scanner.scan_text(f"aws_key = '{dummy_key}'", source_name="sample.py")
    assert len(findings) == 1

    baseline_file = tmp_path / ".tokenguard.baseline"
    save_baseline(baseline_file, findings)
    assert baseline_file.is_file()

    fps = load_baseline(baseline_file)
    assert len(fps) == 1
    assert findings[0].fingerprint in fps

    unbaselined, baselined = filter_baseline(findings, fps)
    assert len(unbaselined) == 0
    assert len(baselined) == 1


def test_cli_clean_fixture_exits_zero() -> None:
    fixture = Path(__file__).parent / "fixtures" / "clean_project" / "app.py"
    assert main([str(fixture)]) == 0


def test_cli_dirty_file_exits_one(tmp_path: Path) -> None:
    dirty_file = tmp_path / "config.py"
    dummy_secret = "AK" + "IAIOSFODNN7EXAMPLE"
    dirty_file.write_text(f"secret = '{dummy_secret}'", encoding="utf-8")
    assert main([str(dirty_file)]) == 1


def test_cli_nonexistent_path_exits_two() -> None:
    assert main(["non_existent_file_path_12345.py"]) == 2


def test_cli_format_json_and_output(tmp_path: Path, capsys) -> None:
    dirty_file = tmp_path / "config.py"
    dummy_secret = "AK" + "IAIOSFODNN7EXAMPLE"
    dirty_file.write_text(f"secret = '{dummy_secret}'", encoding="utf-8")
    out_file = tmp_path / "report.json"

    exit_code = main(["--format", "json", "-o", str(out_file), str(dirty_file)])
    assert exit_code == 1
    assert out_file.is_file()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["findings_count"] == 1
    assert data["findings"][0]["rule_id"] == "SEC-001"


def test_cli_format_sarif(tmp_path: Path) -> None:
    dirty_file = tmp_path / "config.py"
    dummy_secret = "AK" + "IAIOSFODNN7EXAMPLE"
    dirty_file.write_text(f"secret = '{dummy_secret}'", encoding="utf-8")
    sarif_file = tmp_path / "results.sarif"

    exit_code = main(["--format", "sarif", "-o", str(sarif_file), str(dirty_file)])
    assert exit_code == 1
    assert sarif_file.is_file()

    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1


def test_cli_update_baseline_workflow(tmp_path: Path) -> None:
    dirty_file = tmp_path / "config.py"
    dummy_secret = "AK" + "IAIOSFODNN7EXAMPLE"
    dirty_file.write_text(f"secret = '{dummy_secret}'", encoding="utf-8")
    baseline_file = tmp_path / ".tokenguard.baseline"

    # Step 1: Update baseline creates baseline and exits 0
    exit_code_1 = main(["--baseline", str(baseline_file), "--update-baseline", str(dirty_file)])
    assert exit_code_1 == 0
    assert baseline_file.is_file()

    # Step 2: Next scan with baseline yields 0 (suppressed)
    exit_code_2 = main(["--baseline", str(baseline_file), str(dirty_file)])
    assert exit_code_2 == 0


def test_detects_stripe_live_secret_key() -> None:
    scanner = Scanner()
    dummy_stripe_key = "sk_live_" + "a" * 24
    findings = scanner.scan_text(f"stripe_key = '{dummy_stripe_key}'")

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-009"
