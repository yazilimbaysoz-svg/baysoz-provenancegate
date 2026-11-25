# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""DSSE envelope primitives by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import Certificate

from .errors import InputError

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def read_json(path: str | Path) -> Any:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        msg = f"cannot read {path}: {exc.strerror or exc}"
        raise InputError(msg) from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"invalid JSON in {path}: {exc}"
        raise InputError(msg) from exc


def decode_base64(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        msg = f"{field} must be a non-empty base64 string"
        raise InputError(msg)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = f"{field} is not valid base64"
        raise InputError(msg) from exc


def pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode()
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def key_algorithm(key: object) -> str:
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return "ecdsa-p256"
        if isinstance(key.curve, ec.SECP384R1):
            return "ecdsa-p384"
        return f"ecdsa-{key.curve.name}"
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa-pkcs1v15-sha256"
    return "unsupported"


def verify_signature(key: object, signed_bytes: bytes, signature: bytes) -> bool:
    algorithm = key_algorithm(key)
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed_bytes)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed_bytes, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return algorithm != "unsupported"


def load_public_key_pem(data: bytes, field: str) -> object:
    try:
        return serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        msg = f"{field} does not contain a valid PEM public key"
        raise InputError(msg) from exc


def public_key_from_certificate(certificate: Certificate) -> object:
    return certificate.public_key()


def certificate_from_der(data: bytes, field: str) -> Certificate:
    from cryptography import x509

    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        msg = f"{field} does not contain a valid DER certificate"
        raise InputError(msg) from exc
