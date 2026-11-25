# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Adversarial test fixtures by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from baysoz_provenancegate import dsse
from baysoz_provenancegate.bundle import ISSUER_OID

BUILDER = "https://github.com/actions/runner-github/.github/workflows/release.yml@refs/heads/main"
SOURCE = "github.com/acme/widget"
REF = "refs/tags/v1.4.0"
COMMIT = "a" * 40
WORKFLOW = ".github/workflows/release.yml"
EVENT = "release"
BUILD_TYPE = "https://github.com/slsa-framework/github-actions-build@v1"
IDENTITY = "https://github.com/acme/widget/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def digest(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def statement_payload(artifact: bytes, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin", "digest": {"sha256": digest(artifact)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "github": {
                        "repository": "https://github.com/acme/widget",
                        "ref": REF,
                        "sha": COMMIT,
                        "workflow": WORKFLOW,
                        "event_name": EVENT,
                    }
                },
                "internalParameters": {"github": {"runner_environment": "github-hosted"}},
            },
            "runDetails": {
                "builder": {"id": BUILDER},
                "metadata": {
                    "buildStartedOn": "2026-11-25T10:00:00Z",
                    "buildFinishedOn": "2026-11-25T10:05:00Z",
                },
            },
        },
    }
    for key, value in overrides.items():
        if key in {"subject", "predicateType"}:
            payload[key] = value
        elif key == "predicate":
            payload["predicate"].update(value)
        else:
            section = (
                payload["predicate"]["buildDefinition"].setdefault("externalParameters", {}).setdefault("github", {})
            )
            section[key] = value
    return payload


def sign(payload: dict[str, Any], key: object, payload_type: str = dsse.PAYLOAD_TYPE) -> list[dict[str, str]]:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed = dsse.pae(payload_type, raw)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(signed)
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return [{"keyid": "test-key", "sig": encode(signature)}]


def envelope(payload: dict[str, Any], key: object, payload_type: str = dsse.PAYLOAD_TYPE) -> dict[str, Any]:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"payloadType": payload_type, "payload": encode(raw), "signatures": sign(payload, key, payload_type)}


def certificate(key: object, identity: str = IDENTITY, issuer: str = ISSUER) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "baysoz-provenancegate test signer")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), critical=False)
        .add_extension(x509.UnrecognizedExtension(ISSUER_OID, issuer.encode("utf-8")), critical=False)
    )
    return builder.sign(key, hashes.SHA256())


def bundle(envelope_data: dict[str, Any], cert: x509.Certificate) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "dsseEnvelope": envelope_data,
        "verificationMaterial": {
            "certificate": {"rawBytes": encode(cert.public_bytes(serialization.Encoding.DER))},
            "tlogEntries": [],
        },
    }


def policy_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "version": 1,
        "trust": {"builder_ids": [BUILDER], "identity": IDENTITY, "issuer": ISSUER},
        "source": {"uri": SOURCE, "ref": REF, "commit": COMMIT, "workflow": WORKFLOW},
        "build": {"type": BUILD_TYPE, "event": EVENT, "deny_self_hosted": True},
        "verify": {
            "predicate_types": ["https://slsa.dev/provenance/v1"],
            "digest_algorithms": ["sha256"],
            "allowed_key_types": ["ecdsa-p256", "ed25519"],
            "require_all_signatures": True,
            "maximum_signatures": 8,
        },
    }
    for section, values in overrides.items():
        data[section].update(values)
    return data


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"release-artifact-2026\x00\xff")
    return path


@pytest.fixture
def key() -> ec.EllipticCurvePrivateKey:
    return ec_key()


@pytest.fixture
def sample(artifact: Path, key: ec.EllipticCurvePrivateKey, tmp_path: Path) -> dict[str, Path]:
    env_path = tmp_path / "attestation.json"
    env_path.write_text(json.dumps(envelope(statement_payload(artifact.read_bytes()), key)), encoding="utf-8")
    bare_policy = policy_data()
    del bare_policy["trust"]["identity"]
    del bare_policy["trust"]["issuer"]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(bare_policy), encoding="utf-8")
    key_path = tmp_path / "public.pem"
    key_path.write_bytes(
        key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return {"attestation": env_path, "policy": policy_path, "key": key_path, "artifact": artifact}
