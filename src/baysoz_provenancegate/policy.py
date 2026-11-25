# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""Verification policy loading by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import dsse
from .errors import InputError

ALLOWED_ALGORITHMS = {"sha256", "sha512"}
ALLOWED_KEY_TYPES = {"ed25519", "ecdsa-p256", "ecdsa-p384"}
ROOT_KEYS = {"version", "trust", "source", "build", "verify"}
TRUST_KEYS = {"builder_ids", "identity", "issuer"}
SOURCE_KEYS = {"uri", "ref", "commit", "workflow"}
BUILD_KEYS = {"type", "event", "deny_self_hosted"}
VERIFY_KEYS = {
    "predicate_types",
    "digest_algorithms",
    "allowed_key_types",
    "require_all_signatures",
    "maximum_signatures",
}


@dataclass(frozen=True, slots=True)
class Policy:
    builder_ids: tuple[str, ...]
    identity: str | None
    issuer: str | None
    source_uri: str
    source_ref: str | None
    source_commit: str | None
    source_workflow: str | None
    build_type: str | None
    build_event: str | None
    deny_self_hosted: bool
    predicate_types: tuple[str, ...]
    digest_algorithms: tuple[str, ...]
    allowed_key_types: tuple[str, ...]
    require_all_signatures: bool
    maximum_signatures: int


def _section(data: dict[str, Any], key: str, allowed: set[str]) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        msg = f"policy.{key} must be an object"
        raise InputError(msg)
    unknown = set(value) - allowed
    if unknown:
        msg = f"policy.{key} has unknown keys: {sorted(unknown)}"
        raise InputError(msg)
    return value


def _string_list(value: object, field: str, required: bool = True) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        msg = f"policy.{field} must be a non-empty array of non-empty strings"
        raise InputError(msg)
    return tuple(value)


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        msg = f"policy.{field} must be a non-empty string"
        raise InputError(msg)
    return value


def load(path: str | Path) -> Policy:
    from .statement import normalize_repository

    data = dsse.read_json(path)
    if not isinstance(data, dict):
        msg = "policy must be a JSON object"
        raise InputError(msg)
    unknown = set(data) - ROOT_KEYS
    if unknown:
        msg = f"policy has unknown keys: {sorted(unknown)}"
        raise InputError(msg)
    if data.get("version") != 1:
        msg = "policy.version must be 1"
        raise InputError(msg)
    trust = _section(data, "trust", TRUST_KEYS)
    source = _section(data, "source", SOURCE_KEYS)
    build = _section(data, "build", BUILD_KEYS)
    verify = _section(data, "verify", VERIFY_KEYS)

    builder_ids = _string_list(trust.get("builder_ids"), "trust.builder_ids")
    identity = _optional_string(trust.get("identity"), "trust.identity")
    issuer = _optional_string(trust.get("issuer"), "trust.issuer")
    source_uri_raw = _optional_string(source.get("uri"), "source.uri")
    if source_uri_raw is None:
        msg = "policy.source.uri is required: provenance must name an expected source repository"
        raise InputError(msg)
    source_uri = normalize_repository(source_uri_raw)
    if not source_uri:
        msg = "policy.source.uri is not a valid repository identifier"
        raise InputError(msg)

    predicate_types = _string_list(verify.get("predicate_types"), "verify.predicate_types")
    algorithms = _string_list(verify.get("digest_algorithms"), "verify.digest_algorithms")
    if not set(algorithms) <= ALLOWED_ALGORITHMS:
        msg = f"policy.verify.digest_algorithms may only contain {sorted(ALLOWED_ALGORITHMS)}"
        raise InputError(msg)
    key_types = _string_list(verify.get("allowed_key_types"), "verify.allowed_key_types")
    if not set(key_types) <= ALLOWED_KEY_TYPES:
        msg = f"policy.verify.allowed_key_types may only contain {sorted(ALLOWED_KEY_TYPES)}"
        raise InputError(msg)
    require_all = verify.get("require_all_signatures", True)
    if not isinstance(require_all, bool):
        msg = "policy.verify.require_all_signatures must be a boolean"
        raise InputError(msg)
    maximum = verify.get("maximum_signatures", 8)
    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 64:
        msg = "policy.verify.maximum_signatures must be an integer between 1 and 64"
        raise InputError(msg)
    deny_self_hosted = build.get("deny_self_hosted", True)
    if not isinstance(deny_self_hosted, bool):
        msg = "policy.build.deny_self_hosted must be a boolean"
        raise InputError(msg)
    return Policy(
        builder_ids=builder_ids,
        identity=identity,
        issuer=issuer,
        source_uri=source_uri,
        source_ref=_optional_string(source.get("ref"), "source.ref"),
        source_commit=_optional_string(source.get("commit"), "source.commit"),
        source_workflow=_optional_string(source.get("workflow"), "source.workflow"),
        build_type=_optional_string(build.get("type"), "build.type"),
        build_event=_optional_string(build.get("event"), "build.event"),
        deny_self_hosted=deny_self_hosted,
        predicate_types=predicate_types,
        digest_algorithms=algorithms,
        allowed_key_types=key_types,
        require_all_signatures=require_all,
        maximum_signatures=maximum,
    )
