# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate
"""in-toto statement and SLSA predicate processing by Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .errors import InputError

STATEMENT_TYPES = {
    "https://in-toto.io/Statement/v1",
    "https://in-toto.io/Statement/v0.1",
}
DIGEST_LENGTHS = {"sha256": 64, "sha512": 128}
FORBIDDEN_DIGESTS = {"md5", "sha1"}


@dataclass(slots=True)
class Claim:
    value: object
    location: str


@dataclass(slots=True)
class Statement:
    statement_type: str
    subjects: list[dict[str, Any]]
    predicate_type: str
    predicate: dict[str, Any]
    builder: Claim | None
    build_type: Claim | None
    external: dict[str, Any]
    internal: dict[str, Any]
    metadata: dict[str, Any]


def nested(data: object, path: str) -> Claim | None:
    current: object = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    if current is None:
        return None
    return Claim(current, "/predicate/" + path.replace(".", "/"))


def parse(payload: bytes) -> Statement:
    import json

    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"DSSE payload is not valid UTF-8 JSON: {exc}"
        raise InputError(msg) from exc
    if not isinstance(data, dict):
        msg = "in-toto payload must be a JSON object"
        raise InputError(msg)
    statement_type = data.get("_type")
    if statement_type not in STATEMENT_TYPES:
        msg = f"unsupported in-toto statement type: {statement_type!r}"
        raise InputError(msg)
    subjects = data.get("subject")
    if not isinstance(subjects, list) or not subjects:
        msg = "in-toto statement subject must be a non-empty array"
        raise InputError(msg)
    for index, subject in enumerate(subjects):
        if not isinstance(subject, dict) or not isinstance(subject.get("name"), str) or not subject.get("name"):
            msg = f"subject[{index}] must have a non-empty name"
            raise InputError(msg)
        if not isinstance(subject.get("digest"), dict) or not subject["digest"]:
            msg = f"subject[{index}].digest must be a non-empty object"
            raise InputError(msg)
    predicate_type = data.get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type:
        msg = "predicateType must be a non-empty string"
        raise InputError(msg)
    predicate = data.get("predicate")
    if not isinstance(predicate, dict):
        msg = "predicate must be a JSON object"
        raise InputError(msg)
    v1 = predicate_type == "https://slsa.dev/provenance/v1"
    builder = nested(predicate, "runDetails.builder.id" if v1 else "builder.id")
    build_type = nested(predicate, "buildDefinition.buildType" if v1 else "buildType")
    external_claim = nested(predicate, "buildDefinition.externalParameters" if v1 else "buildParameters")
    internal_claim = nested(predicate, "buildDefinition.internalParameters" if v1 else "invocation.parameters")
    metadata_claim = nested(predicate, "runDetails.metadata" if v1 else "metadata")
    external = external_claim.value if external_claim is not None and isinstance(external_claim.value, dict) else {}
    internal = internal_claim.value if internal_claim is not None and isinstance(internal_claim.value, dict) else {}
    metadata = metadata_claim.value if metadata_claim is not None and isinstance(metadata_claim.value, dict) else {}
    return Statement(
        statement_type=statement_type,
        subjects=subjects,
        predicate_type=predicate_type,
        predicate=predicate,
        builder=builder,
        build_type=build_type,
        external=external,
        internal=internal,
        metadata=metadata,
    )


def normalize_repository(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    for prefix in ("git+https://", "https://", "http://", "ssh://", "git://"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    if text.startswith("git@"):
        text = text[4:]
    if text.startswith("github.com/"):
        text = text[len("github.com/") :]
    elif text.startswith("www.github.com/"):
        text = text[len("www.github.com/") :]
    if text.endswith(".git"):
        text = text[:-4]
    return text.strip("/").lower()


def claim_string(claims: dict[str, Any], keys: tuple[str, ...]) -> Claim | None:
    for key in keys:
        value = claims.get(key)
        if value is None:
            continue
        container = value if isinstance(value, dict) else {}
        for field in ("uri", "repository", "ref", "sha", "workflow", "path", "event_name", "sourceUri"):
            nested_value = container.get(field)
            if nested_value is not None:
                return Claim(nested_value, f"/predicate/buildDefinition/externalParameters/{key}/{field}")
        if isinstance(value, str):
            return Claim(value, f"/predicate/buildDefinition/externalParameters/{key}")
    return None


def source_claims(statement: Statement) -> dict[str, Claim | None]:
    external = statement.external
    github = external.get("github") if isinstance(external.get("github"), dict) else {}
    workflow = external.get("workflow") if isinstance(external.get("workflow"), dict) else {}
    source = external.get("source") if isinstance(external.get("source"), dict) else {}
    digest = source.get("digest") if isinstance(source.get("digest"), dict) else {}
    uri_value = source.get("uri", github.get("repository", workflow.get("repository")))
    ref_value = github.get("ref", workflow.get("ref", external.get("ref")))
    commit_value = github.get("sha", external.get("commit", digest.get("gitCommit")))
    workflow_value = github.get("workflow", workflow.get("path", external.get("workflow")))
    event_value = github.get("event_name", external.get("event_name"))
    return {
        "uri": Claim(uri_value, "/predicate/buildDefinition/externalParameters/source/uri")
        if uri_value is not None
        else None,
        "ref": Claim(ref_value, "/predicate/buildDefinition/externalParameters/github/ref")
        if ref_value is not None
        else None,
        "commit": Claim(commit_value, "/predicate/buildDefinition/externalParameters/github/sha")
        if commit_value is not None
        else None,
        "workflow": Claim(workflow_value, "/predicate/buildDefinition/externalParameters/github/workflow")
        if workflow_value is not None
        else None,
        "event": Claim(event_value, "/predicate/buildDefinition/externalParameters/github/event_name")
        if event_value is not None
        else None,
    }


def file_digests(path: str) -> dict[str, str]:
    from pathlib import Path

    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        msg = f"cannot read artifact {path}: {exc.strerror or exc}"
        raise InputError(msg) from exc
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha512": hashlib.sha512(raw).hexdigest(),
    }


def verify_subjects(
    statement: Statement, computed: dict[str, str], allowed: tuple[str, ...]
) -> tuple[int, list[tuple[str, str]]]:
    problems: list[tuple[str, str]] = []
    matches = 0
    for index, subject in enumerate(statement.subjects):
        digests = subject["digest"]
        for algorithm, value in digests.items():
            location = f"/subject/{index}/digest/{algorithm}"
            if algorithm in FORBIDDEN_DIGESTS:
                problems.append((location, f"forbidden digest algorithm {algorithm}"))
                continue
            if algorithm not in DIGEST_LENGTHS:
                problems.append((location, f"unsupported digest algorithm {algorithm}"))
                continue
            if (
                not isinstance(value, str)
                or len(value) != DIGEST_LENGTHS[algorithm]
                or any(char not in "0123456789abcdef" for char in value)
            ):
                problems.append((location, f"malformed {algorithm} digest"))
                continue
            if algorithm in allowed and value != computed[algorithm]:
                problems.append((location, f"{algorithm} digest does not match artifact"))
        if any(algorithm in allowed for algorithm in digests):
            matches += 1
    return matches, problems
