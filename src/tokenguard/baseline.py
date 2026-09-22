"""Baseline suppression system for TokenGuard.

Allows teams to baseline existing legacy secrets or legitimate test mock secrets,
preventing false positives and CI breakages while blocking newly introduced secrets.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import Finding


def compute_fingerprint(file_path: str, rule_id: str, masked_value: str) -> str:
    """Compute a deterministic SHA-256 fingerprint for a secret finding.

    Does not depend on volatile line numbers, keeping the baseline valid
    when code before or after the finding is modified.
    """
    canonical_path = file_path.replace("\\", "/").lstrip("./")
    payload = f"{canonical_path}:{rule_id}:{masked_value}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_baseline(path: Path) -> set[str]:
    """Load baseline fingerprints from a JSON baseline file."""
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            fps = data.get("fingerprints", [])
            if isinstance(fps, list):
                return set(fps)
    except (json.JSONDecodeError, OSError):
        pass
    return set()


def save_baseline(path: Path, findings: list[Finding]) -> None:
    """Save detected findings into a baseline file."""
    fingerprints = sorted({f.fingerprint for f in findings})
    records = [
        {
            "file_path": f.file_path.replace("\\", "/").lstrip("./"),
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "fingerprint": f.fingerprint,
            "masked_value": f.masked_value,
        }
        for f in findings
    ]
    payload = {
        "version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "count": len(fingerprints),
        "fingerprints": fingerprints,
        "findings": records,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def filter_baseline(
    findings: list[Finding],
    baseline_fingerprints: set[str],
) -> tuple[list[Finding], list[Finding]]:
    """Partition findings into (unbaselined, baselined)."""
    if not baseline_fingerprints:
        return findings, []

    unbaselined: list[Finding] = []
    baselined: list[Finding] = []

    for f in findings:
        if f.fingerprint in baseline_fingerprints:
            baselined.append(f)
        else:
            unbaselined.append(f)

    return unbaselined, baselined
