# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Signed attestation input decoding by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from . import dsse
from .errors import InputError

BUNDLE_MEDIA_TYPES = {
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle.v0.2+json",
}
ISSUER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")


@dataclass(slots=True)
class Attestation:
    source: Path
    container: str
    payload_type: str
    payload: bytes
    signatures: list[bytes]
    public_key: object | None = None
    certificate: x509.Certificate | None = None
    identity: str | None = None
    issuer: str | None = None

    def signed_bytes(self) -> bytes:
        return dsse.pae(self.payload_type, self.payload)


def _envelope(data: object, container: str) -> tuple[str, bytes, list[bytes]]:
    if not isinstance(data, dict):
        msg = f"{container} must be a JSON object"
        raise InputError(msg)
    payload_type = data.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type:
        msg = f"{container}.payloadType must be a non-empty string"
        raise InputError(msg)
    payload = dsse.decode_base64(data.get("payload"), f"{container}.payload")
    raw_signatures = data.get("signatures")
    if not isinstance(raw_signatures, list) or not raw_signatures:
        msg = f"{container}.signatures must be a non-empty array"
        raise InputError(msg)
    signatures: list[bytes] = []
    for index, item in enumerate(raw_signatures):
        if not isinstance(item, dict):
            msg = f"{container}.signatures[{index}] must be an object"
            raise InputError(msg)
        signature = dsse.decode_base64(item.get("sig"), f"{container}.signatures[{index}].sig")
        signatures.append(signature)
    return payload_type, payload, signatures


def _material(data: object) -> tuple[object | None, x509.Certificate | None]:
    if not isinstance(data, dict):
        msg = "verificationMaterial must be a JSON object"
        raise InputError(msg)
    kinds = [
        key for key in ("certificate", "x509CertificateChain", "publicKey") if key in data and data[key] is not None
    ]
    if len(kinds) != 1:
        msg = "verificationMaterial must contain exactly one of certificate, x509CertificateChain, publicKey"
        raise InputError(msg)
    kind = kinds[0]
    value = data[kind]
    if not isinstance(value, dict):
        msg = f"verificationMaterial.{kind} must be a JSON object"
        raise InputError(msg)
    if kind == "publicKey":
        return dsse.load_public_key_pem(
            dsse.decode_base64(value.get("content"), "verificationMaterial.publicKey.content"),
            "verificationMaterial.publicKey.content",
        ), None
    if kind == "certificate":
        raw = value.get("rawBytes")
    else:
        certificates = value.get("certificates")
        if not isinstance(certificates, list) or not certificates or not isinstance(certificates[0], dict):
            msg = "verificationMaterial.x509CertificateChain.certificates must be a non-empty array"
            raise InputError(msg)
        raw = certificates[0].get("rawBytes")
    certificate = dsse.certificate_from_der(
        dsse.decode_base64(raw, f"verificationMaterial.{kind}.rawBytes"), f"verificationMaterial.{kind}.rawBytes"
    )
    return dsse.public_key_from_certificate(certificate), certificate


def _identity(certificate: x509.Certificate) -> tuple[str | None, str | None]:
    identity: str | None = None
    try:
        names = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = names.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            identity = uris[0]
    except x509.ExtensionNotFound:
        pass
    issuer: str | None = None
    try:
        issuer = certificate.extensions.get_extension_for_oid(ISSUER_OID).value.value.decode("utf-8")
    except (x509.ExtensionNotFound, UnicodeDecodeError):
        pass
    return identity, issuer


def load(path: str | Path) -> Attestation:
    source = Path(path)
    data = dsse.read_json(source)
    if not isinstance(data, dict):
        msg = f"{source} must contain a DSSE envelope or a Sigstore bundle object"
        raise InputError(msg)
    media_type = data.get("mediaType")
    if media_type is not None and media_type not in BUNDLE_MEDIA_TYPES:
        msg = f"unsupported Sigstore bundle mediaType: {media_type}"
        raise InputError(msg)
    if "dsseEnvelope" in data:
        container = "dsseEnvelope"
        envelope = data["dsseEnvelope"]
    elif "payloadType" in data and "signatures" in data:
        container = "envelope"
        envelope = data
    else:
        msg = f"{source} contains neither a DSSE envelope nor a Sigstore bundle dsseEnvelope"
        raise InputError(msg)
    payload_type, payload, signatures = _envelope(envelope, container)
    public_key: object | None = None
    certificate: x509.Certificate | None = None
    identity: str | None = None
    issuer: str | None = None
    if container == "dsseEnvelope":
        public_key, certificate = _material(data.get("verificationMaterial"))
        if certificate is not None:
            identity, issuer = _identity(certificate)
    return Attestation(
        source=source,
        container=container,
        payload_type=payload_type,
        payload=payload,
        signatures=signatures,
        public_key=public_key,
        certificate=certificate,
        identity=identity,
        issuer=issuer,
    )
