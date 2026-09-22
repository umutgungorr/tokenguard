"""SARIF v2.1.0 generator for TokenGuard.

Enables native GitHub Code Scanning Alerts integration and CI/CD security dashboards.
"""

from __future__ import annotations

import json
from typing import Any

from .rules import RULES, Severity
from .scanner import Finding

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_VERSION = "0.2.0"


def generate_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Generate a standard SARIF v2.1.0 report object."""
    # Build unique rules list based on predefined rules and entropy rule
    sarif_rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for rule in RULES:
        if rule.rule_id in seen_rules:
            continue
        seen_rules.add(rule.rule_id)
        sarif_rules.append(
            {
                "id": rule.rule_id,
                "name": rule.name,
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.description},
                "help": {
                    "text": f"Remediation: {rule.remediation}",
                    "markdown": f"### Remediation\n\n{rule.remediation}",
                },
                "defaultConfiguration": {
                    "level": "error" if rule.severity == Severity.CRITICAL else "warning"
                },
                "properties": {
                    "confidence": rule.confidence.value,
                    "tags": ["security", "secrets", "credentials"],
                },
            }
        )

    # Add Entropy rule if not present
    sarif_rules.append(
        {
            "id": "ENTROPY-001",
            "name": "High Entropy Secret Token",
            "shortDescription": {"text": "High entropy secret token detected"},
            "fullDescription": {"text": "Detected high-entropy random string resembling an API key, session secret, or private token."},
            "help": {
                "text": "Remediation: Store token in secure environment variables or vault.",
                "markdown": "### Remediation\n\nStore token in secure environment variables or vault.",
            },
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "confidence": "HIGH",
                "tags": ["security", "entropy", "secrets"],
            },
        }
    )

    results: list[dict[str, Any]] = []
    for f in findings:
        normalized_uri = f.file_path.replace("\\", "/").lstrip("./")
        level = "error" if f.severity == Severity.CRITICAL else "warning"

        result = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {
                "text": f"{f.rule_name} detected ({f.masked_value}). {f.remediation}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": normalized_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                "confidence": f.confidence.value,
                "fingerprint": f.fingerprint,
                "maskedValue": f.masked_value,
            },
        }
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "TokenGuard",
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": "https://github.com/umutgungorr/tokenguard",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif_json(findings: list[Finding], indent: int = 2) -> str:
    """Format findings as SARIF v2.1.0 JSON string."""
    return json.dumps(generate_sarif(findings), indent=indent)
