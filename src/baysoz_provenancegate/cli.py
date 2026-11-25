# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Command-line interface by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from . import ATTRIBUTION, PROJECT, __version__, gate, sarif
from .models import Report

EXIT_CODES = {"PASS": 0, "FAIL": 1, "ERROR": 2}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROJECT,
        description=(
            "Offline SLSA provenance trust gate: verify DSSE signatures, artifact digests, "
            "builder identity and build parameters. Built by Baysöz Labs <baysozlabs@proton.me>."
        ),
        epilog=f"{ATTRIBUTION} — {PROJECT} {__version__}. Fail-closed, deterministic, no network access.",
    )
    parser.add_argument("--version", action="version", version=f"{PROJECT} {__version__} — {ATTRIBUTION}")
    parser.add_argument("--artifact", required=True, help="artifact whose digest must match the in-toto subject")
    parser.add_argument("--attestation", required=True, help="DSSE envelope or Sigstore bundle JSON file")
    parser.add_argument("--policy", required=True, help="fail-closed trust policy JSON file")
    parser.add_argument("--key", help="PEM public key for bare DSSE envelopes without verification material")
    parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text", help="report format (default: text)"
    )
    parser.add_argument("--output", help="write report to this file instead of stdout")
    return parser


def render_text(report: Report, artifact: str) -> str:
    lines = [f"verdict: {report.verdict}", f"artifact: {artifact}"]
    for item in report.sorted_findings():
        lines.append(f"[{item.rule_id}] {item.message} ({item.location})")
    if not report.findings:
        lines.append("all provenance checks passed")
    lines.append(f"{ATTRIBUTION} — {PROJECT} {__version__}")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = gate.evaluate(args.attestation, args.artifact, args.policy, args.key)
    if args.format == "json":
        payload = json.dumps(report.as_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    elif args.format == "sarif":
        payload = (
            json.dumps(sarif.render(report, args.attestation), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
    else:
        payload = render_text(report, args.artifact)
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return EXIT_CODES[report.verdict]


if __name__ == "__main__":
    raise SystemExit(main())
