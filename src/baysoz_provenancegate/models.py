# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Finding and report models by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import ATTRIBUTION, PROJECT

RULES: dict[str, str] = {
    "PROV001": "Malformed attestation input",
    "PROV002": "Unsupported DSSE payload type",
    "PROV003": "No cryptographically valid signature",
    "PROV004": "Invalid signature in signature set",
    "PROV005": "Disallowed signing key algorithm",
    "PROV006": "Signer identity is not trusted",
    "PROV007": "OIDC issuer is not trusted",
    "PROV008": "Builder id is not trusted",
    "PROV009": "Weak or malformed subject digest",
    "PROV010": "Subject digest does not match the artifact",
    "PROV011": "Ambiguous artifact subject",
    "PROV012": "Predicate type is not allowed",
    "PROV013": "Source repository is not trusted",
    "PROV014": "Source ref is not allowed",
    "PROV015": "Source commit is not allowed",
    "PROV016": "Workflow path is not allowed",
    "PROV017": "Build event is not allowed",
    "PROV018": "Build type is not allowed",
    "PROV019": "Self-hosted runner is denied",
    "PROV020": "Required provenance claim is missing",
    "PROV021": "Inconsistent build timestamps",
    "PROV022": "Invalid verification policy",
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    message: str
    location: str = "/"
    severity: str = "error"

    def __post_init__(self) -> None:
        if self.rule_id not in RULES:
            msg = f"unknown rule {self.rule_id}"
            raise ValueError(msg)
        if self.severity not in {"error", "warning", "note"}:
            msg = f"unknown severity {self.severity}"
            raise ValueError(msg)

    def as_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "title": RULES[self.rule_id],
            "message": self.message,
            "location": self.location,
            "severity": self.severity,
        }


@dataclass(slots=True)
class Report:
    verdict: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, rule_id: str, message: str, location: str = "/") -> None:
        self.findings.append(Finding(rule_id, message, location))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda item: (item.rule_id, item.message, item.location))

    def as_dict(self) -> dict[str, object]:
        return {
            "tool": PROJECT,
            "attribution": ATTRIBUTION,
            "verdict": self.verdict,
            "counts": {
                "error": sum(1 for item in self.findings if item.severity == "error"),
                "warning": sum(1 for item in self.findings if item.severity == "warning"),
            },
            "findings": [item.as_dict() for item in self.sorted_findings()],
        }
