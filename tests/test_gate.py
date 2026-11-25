# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Trust-gate behavior tests by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from baysoz_provenancegate import cli, dsse, gate, sarif
from conftest import (
    bundle,
    certificate,
    digest,
    ec_key,
    envelope,
    policy_data,
    statement_payload,
)


def rule_ids(report: gate.Report) -> set[str]:
    return {item.rule_id for item in report.findings}


def write_json(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def check(attestation: Path, artifact: Path, sample: dict[str, Path]) -> gate.Report:
    return gate.evaluate(str(attestation), str(artifact), str(sample["policy"]), str(sample["key"]))


def test_pass_with_bare_dsse_envelope(sample: dict[str, Path]) -> None:
    report = check(sample["attestation"], sample["artifact"], sample)
    assert report.verdict == "PASS"
    assert report.findings == []


def test_pass_with_sigstore_bundle_and_certificate_identity(artifact: Path, tmp_path: Path) -> None:
    key = ec_key()
    cert = certificate(key)
    attestation = write_json(
        tmp_path / "bundle.json", bundle(envelope(statement_payload(artifact.read_bytes()), key), cert)
    )
    policy = write_json(tmp_path / "policy.json", policy_data())
    report = gate.evaluate(str(attestation), str(artifact), str(policy))
    assert report.verdict == "PASS"


def test_tampered_artifact_is_rejected(sample: dict[str, Path]) -> None:
    sample["artifact"].write_bytes(b"tampered")
    assert "PROV010" in rule_ids(check(sample["attestation"], sample["artifact"], sample))


def test_forged_signature_is_rejected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    forged = ec_key()
    raw = json.dumps(statement_payload(artifact.read_bytes()), sort_keys=True).encode()
    signed = dsse.pae(dsse.PAYLOAD_TYPE, raw)
    signature = forged.sign(signed, ec.ECDSA(hashes.SHA256()))
    forged_envelope = {
        "payloadType": dsse.PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode(),
        "signatures": [{"sig": base64.b64encode(signature).decode()}],
    }
    attestation = write_json(tmp_path / "forged.json", forged_envelope)
    assert "PROV003" in rule_ids(check(attestation, artifact, sample))


def test_claim_mismatches_are_detected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    changes = [
        ({"predicate": {"runDetails": {"builder": {"id": "https://evil.example/builder"}}}}, "PROV008"),
        ({"repository": "https://github.com/evil/fork"}, "PROV013"),
        ({"ref": "refs/heads/main"}, "PROV014"),
        ({"sha": "b" * 40}, "PROV015"),
        ({"workflow": ".github/workflows/other.yml"}, "PROV016"),
        ({"event_name": "push"}, "PROV017"),
        ({"predicate": {"buildDefinition": {"buildType": "https://evil.example/build"}}}, "PROV018"),
    ]
    for overrides, expected in changes:
        payload = statement_payload(artifact.read_bytes(), **overrides)
        attestation = write_json(tmp_path / f"{expected}.json", envelope(payload, key))
        assert expected in rule_ids(check(attestation, artifact, sample)), expected


def test_self_hosted_runner_is_rejected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    payload = statement_payload(artifact.read_bytes())
    payload["predicate"]["buildDefinition"]["internalParameters"] = {"github": {"runner_environment": "self-hosted"}}
    attestation = write_json(tmp_path / "selfhosted.json", envelope(payload, key))
    assert "PROV019" in rule_ids(check(attestation, artifact, sample))


def test_weak_and_malformed_digests_are_rejected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    values = ({"md5": digest(artifact.read_bytes(), "md5")}, {"sha256": "xyz"})
    for index, value in enumerate(values):
        payload = statement_payload(artifact.read_bytes(), subject=[{"name": "artifact.bin", "digest": value}])
        attestation = write_json(tmp_path / f"digest{index}.json", envelope(payload, key))
        assert "PROV009" in rule_ids(check(attestation, artifact, sample))


def test_ambiguous_subject_is_rejected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    subject = {"name": "artifact.bin", "digest": {"sha256": digest(artifact.read_bytes())}}
    payload = statement_payload(artifact.read_bytes(), subject=[subject, dict(subject)])
    attestation = write_json(tmp_path / "ambiguous.json", envelope(payload, key))
    assert "PROV011" in rule_ids(check(attestation, artifact, sample))


def bare_policy(tmp_path: Path) -> Path:
    data = policy_data()
    del data["trust"]["identity"]
    del data["trust"]["issuer"]
    return write_json(tmp_path / "bare-policy.json", data)


def test_rsa_key_is_rejected(artifact: Path, tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attestation = write_json(tmp_path / "rsa.json", envelope(statement_payload(artifact.read_bytes()), key))
    policy = bare_policy(tmp_path)
    key_path = tmp_path / "rsa.pem"
    key_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    report = gate.evaluate(str(attestation), str(artifact), str(policy), str(key_path))
    assert "PROV005" in rule_ids(report)


def test_ed25519_key_is_accepted(artifact: Path, tmp_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    attestation = write_json(tmp_path / "ed.json", envelope(statement_payload(artifact.read_bytes()), key))
    policy = bare_policy(tmp_path)
    key_path = tmp_path / "ed.pem"
    key_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    report = gate.evaluate(str(attestation), str(artifact), str(policy), str(key_path))
    assert report.verdict == "PASS"


def test_identity_and_issuer_mismatches_are_rejected(artifact: Path, tmp_path: Path) -> None:
    key = ec_key()
    cert = certificate(
        key,
        identity="https://github.com/evil/fork/.github/workflows/x.yml@refs/heads/main",
        issuer="https://evil.example",
    )
    attestation = write_json(
        tmp_path / "bundle.json", bundle(envelope(statement_payload(artifact.read_bytes()), key), cert)
    )
    policy = write_json(tmp_path / "policy.json", policy_data())
    report = gate.evaluate(str(attestation), str(artifact), str(policy))
    assert {"PROV006", "PROV007"} <= rule_ids(report)


def test_missing_required_claim_and_bad_predicate(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    payload = statement_payload(artifact.read_bytes(), predicateType="https://slsa.dev/provenance/v0.2")
    payload["predicate"].pop("buildDefinition")
    attestation = write_json(tmp_path / "missing.json", envelope(payload, key))
    report = check(attestation, artifact, sample)
    assert {"PROV012", "PROV020"} <= rule_ids(report)


def test_timestamp_inversion_is_rejected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    payload = statement_payload(artifact.read_bytes())
    payload["predicate"]["runDetails"]["metadata"] = {
        "buildStartedOn": "2026-11-25T11:00:00Z",
        "buildFinishedOn": "2026-11-25T10:00:00Z",
    }
    attestation = write_json(tmp_path / "time.json", envelope(payload, key))
    assert "PROV021" in rule_ids(check(attestation, artifact, sample))


def test_multiple_signatures_fail_closed(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    env = envelope(statement_payload(artifact.read_bytes()), key)
    env["signatures"].append({"sig": env["signatures"][0]["sig"][:-4] + "AAAA"})
    attestation = write_json(tmp_path / "multi.json", env)
    assert "PROV004" in rule_ids(check(attestation, artifact, sample))


def test_unsupported_payload_type_is_rejected(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    key = ec_key()
    env = envelope(statement_payload(artifact.read_bytes()), key, payload_type="application/json")
    attestation = write_json(tmp_path / "payloadtype.json", env)
    assert "PROV002" in rule_ids(check(attestation, artifact, sample))


def test_malformed_inputs_are_reported(artifact: Path, tmp_path: Path, sample: dict[str, Path]) -> None:
    bad_attestation = tmp_path / "bad.json"
    bad_attestation.write_text("{not json", encoding="utf-8")
    report = gate.evaluate(str(bad_attestation), str(artifact), str(tmp_path / "missing-policy.json"))
    assert report.verdict == "ERROR" and "PROV022" in rule_ids(report)
    report = gate.evaluate(str(bad_attestation), str(artifact), str(sample["policy"]))
    assert report.verdict == "ERROR" and "PROV001" in rule_ids(report)


def test_sarif_and_json_reports_carry_attribution(sample: dict[str, Path]) -> None:
    report = check(sample["attestation"], sample["artifact"], sample)
    sarif_data = sarif.render(report, sample["attestation"])
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["organization"] == "Baysöz Labs <baysozlabs@proton.me>"
    assert report.as_dict()["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"


def test_cli_version_help_and_exit_codes(sample: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as version_exit:
        cli.main(["--version"])
    assert version_exit.value.code == 0
    assert "Baysöz Labs" in capsys.readouterr().out
    with pytest.raises(SystemExit) as help_exit:
        cli.main(["--help"])
    assert help_exit.value.code == 0
    assert "baysozlabs@proton.me" in capsys.readouterr().out
    args = [
        "--artifact",
        str(sample["artifact"]),
        "--attestation",
        str(sample["attestation"]),
        "--policy",
        str(sample["policy"]),
        "--key",
        str(sample["key"]),
    ]
    assert cli.main(args + ["--format", "json"]) == 0
    assert "Baysöz Labs" in capsys.readouterr().out
    sample["artifact"].write_bytes(b"changed")
    assert cli.main(args) == 1
    assert "PROV010" in capsys.readouterr().out
