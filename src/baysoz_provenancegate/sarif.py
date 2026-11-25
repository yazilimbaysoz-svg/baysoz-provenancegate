# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""SARIF 2.1.0 serialization by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

from . import ATTRIBUTION, PROJECT, __version__
from .models import RULES, Report


def render(report: Report, artifact: str | Path) -> dict[str, object]:
    used_rules = sorted({item.rule_id for item in report.findings})
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": RULES[rule_id]},
            "properties": {"attribution": ATTRIBUTION},
        }
        for rule_id in used_rules
    ]
    uri = Path(artifact).name
    results = [
        {
            "ruleId": item.rule_id,
            "level": item.severity,
            "message": {"text": item.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1, "startColumn": 1},
                        "contextRegion": {"startLine": 1, "endLine": 1},
                    },
                    "logicalLocations": [{"name": item.location}],
                }
            ],
            "properties": {"attribution": ATTRIBUTION},
        }
        for item in report.sorted_findings()
    ]
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": PROJECT,
                        "version": __version__,
                        "organization": ATTRIBUTION,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"verdict": report.verdict, "attribution": ATTRIBUTION},
            }
        ],
    }
