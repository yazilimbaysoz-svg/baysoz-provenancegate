# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Deterministic trust evaluation by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import bundle, dsse, policy, statement
from .errors import InputError
from .models import Finding, Report

SELF_HOSTED_MARKERS = ("self-hosted", "self_hosted")


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _contains_self_hosted(data: dict[str, object]) -> bool:
    text = json.dumps(data, sort_keys=True).lower()
    return any(marker in text for marker in SELF_HOSTED_MARKERS)


def _verify_signatures(
    attestation: bundle.Attestation, pol: policy.Policy, key_path: str | None, report: Report
) -> None:
    if len(attestation.signatures) > pol.maximum_signatures:
        report.add(
            "PROV004",
            f"signature count {len(attestation.signatures)} exceeds policy maximum {pol.maximum_signatures}",
            "/signatures",
        )
    candidates: list[object] = []
    if attestation.public_key is not None:
        candidates.append(attestation.public_key)
    if key_path is not None:
        try:
            raw = Path(key_path).read_bytes()
        except OSError as exc:
            msg = f"cannot read key {key_path}: {exc.strerror or exc}"
            raise InputError(msg) from exc
        candidates.append(dsse.load_public_key_pem(raw, key_path))
    if not candidates:
        report.add("PROV003", "no verification key is available in the bundle or via --key", "/signatures")
        return
    signed = attestation.signed_bytes()
    valid = 0
    for index, signature in enumerate(attestation.signatures):
        accepted = False
        for key in candidates:
            algorithm = dsse.key_algorithm(key)
            if algorithm not in pol.allowed_key_types:
                report.add("PROV005", f"signing key algorithm {algorithm} is not allowed", f"/signatures/{index}")
                continue
            if dsse.verify_signature(key, signed, signature):
                accepted = True
        if accepted:
            valid += 1
        elif pol.require_all_signatures:
            report.add("PROV004", f"signature {index} is not cryptographically valid", f"/signatures/{index}")
    if valid == 0:
        report.add("PROV003", "no signature verifies over the DSSE pre-authentication encoding", "/signatures")


def _check_identity(attestation: bundle.Attestation, pol: policy.Policy, report: Report) -> None:
    if pol.identity is not None:
        if attestation.identity is None:
            report.add(
                "PROV006",
                "policy requires a signer identity but the bundle provides no X.509 SAN URI",
                "/verificationMaterial/certificate",
            )
        elif attestation.identity != pol.identity:
            report.add(
                "PROV006",
                f"signer identity {attestation.identity!r} does not match policy {pol.identity!r}",
                "/verificationMaterial/certificate",
            )
    if pol.issuer is not None:
        if attestation.issuer is None:
            report.add(
                "PROV007",
                "policy requires an OIDC issuer but the certificate has no Fulcio issuer extension",
                "/verificationMaterial/certificate",
            )
        elif attestation.issuer != pol.issuer:
            report.add(
                "PROV007",
                f"OIDC issuer {attestation.issuer!r} does not match policy {pol.issuer!r}",
                "/verificationMaterial/certificate",
            )


def _check_claims(statement_data: statement.Statement, pol: policy.Policy, report: Report) -> None:
    if statement_data.predicate_type not in pol.predicate_types:
        report.add("PROV012", f"predicate type {statement_data.predicate_type!r} is not allowed", "/predicateType")
    if statement_data.builder is None:
        report.add("PROV020", "provenance has no builder identity", "/predicate")
    else:
        builder = statement_data.builder.value
        if not isinstance(builder, str) or builder not in pol.builder_ids:
            report.add(
                "PROV008", f"builder id {builder!r} is not in the trusted builder set", statement_data.builder.location
            )
    if statement_data.build_type is None:
        report.add("PROV020", "provenance has no buildType", "/predicate")
    elif pol.build_type is not None and statement_data.build_type.value != pol.build_type:
        report.add(
            "PROV018",
            f"build type {statement_data.build_type.value!r} does not match policy",
            statement_data.build_type.location,
        )

    claims = statement.source_claims(statement_data)
    uri_claim = claims["uri"]
    if uri_claim is None:
        report.add(
            "PROV020", "provenance does not name a source repository", "/predicate/buildDefinition/externalParameters"
        )
    else:
        actual_uri = statement.normalize_repository(uri_claim.value)
        if actual_uri != pol.source_uri:
            report.add("PROV013", f"source {actual_uri!r} does not match policy {pol.source_uri!r}", uri_claim.location)
    expectations = (
        ("ref", pol.source_ref, PROV_EXPECTED_REF, PROV_MISMATCH_REF),
        ("commit", pol.source_commit, PROV_EXPECTED_COMMIT, PROV_MISMATCH_COMMIT),
        ("workflow", pol.source_workflow, PROV_EXPECTED_WORKFLOW, PROV_MISMATCH_WORKFLOW),
        ("event", pol.build_event, PROV_EXPECTED_EVENT, PROV_MISMATCH_EVENT),
    )
    for name, expected, missing_rule, mismatch_rule in expectations:
        if expected is None:
            continue
        claim = claims[name]
        if claim is None:
            report.add(
                missing_rule,
                f"provenance does not contain the expected {name}",
                "/predicate/buildDefinition/externalParameters",
            )
        elif claim.value != expected:
            report.add(mismatch_rule, f"{name} {claim.value!r} does not match policy {expected!r}", claim.location)

    if pol.deny_self_hosted and _contains_self_hosted(statement_data.internal):
        report.add(
            "PROV019",
            "provenance internal parameters indicate a self-hosted runner",
            "/predicate/buildDefinition/internalParameters",
        )
    metadata = statement_data.metadata
    started = _timestamp(metadata.get("buildStartedOn"))
    finished = _timestamp(metadata.get("buildFinishedOn"))
    if started is not None and finished is not None and started > finished:
        report.add("PROV021", "buildStartedOn is later than buildFinishedOn", "/predicate/runDetails/metadata")


PROV_EXPECTED_REF = "PROV020"
PROV_MISMATCH_REF = "PROV014"
PROV_EXPECTED_COMMIT = "PROV020"
PROV_MISMATCH_COMMIT = "PROV015"
PROV_EXPECTED_WORKFLOW = "PROV020"
PROV_MISMATCH_WORKFLOW = "PROV016"
PROV_EXPECTED_EVENT = "PROV020"
PROV_MISMATCH_EVENT = "PROV017"


def evaluate(attestation_path: str, artifact_path: str, policy_path: str, key_path: str | None = None) -> Report:
    report = Report("PASS")
    try:
        pol = policy.load(policy_path)
    except InputError as exc:
        report.verdict = "ERROR"
        report.add("PROV022", str(exc), "/policy")
        return report
    try:
        attestation = bundle.load(attestation_path)
    except InputError as exc:
        report.verdict = "ERROR"
        report.add("PROV001", str(exc), "/")
        return report
    if attestation.payload_type != dsse.PAYLOAD_TYPE:
        report.add("PROV002", f"payload type {attestation.payload_type!r} is not an in-toto statement", "/payloadType")
    try:
        parsed = statement.parse(attestation.payload)
    except InputError as exc:
        report.verdict = "ERROR"
        report.add("PROV001", str(exc), "/payload")
        return report
    try:
        _verify_signatures(attestation, pol, key_path, report)
        computed = statement.file_digests(artifact_path)
    except InputError as exc:
        report.verdict = "ERROR"
        report.add("PROV001", str(exc), "/")
        return report
    _check_identity(attestation, pol, report)
    _check_claims(parsed, pol, report)
    matches, digest_problems = statement.verify_subjects(parsed, computed, pol.digest_algorithms)
    for location, message in digest_problems:
        if "does not match artifact" in message:
            report.add("PROV010", message, location)
        else:
            report.add("PROV009", message, location)
    if matches == 0:
        report.add("PROV010", "no subject digest matches the artifact", "/subject")
    elif matches > 1:
        report.add("PROV011", f"{matches} subjects match the artifact; provenance is ambiguous", "/subject")
    if any(item.severity == "error" for item in report.findings):
        report.verdict = "FAIL"
    return report


def from_findings(rule_id: str, message: str, location: str = "/") -> Report:
    return Report("ERROR", [Finding(rule_id, message, location)])
