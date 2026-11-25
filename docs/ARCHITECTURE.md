# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate

# Architecture

Maintained by Baysöz Labs <baysozlabs@proton.me>.

## 1. System shape

```
artifact bytes ─┐
policy JSON ────┼──> gate.evaluate ──> Report ──> text | JSON | SARIF 2.1.0
attestation ────┘         │
                          ├── bundle: DSSE envelope + verification material
                          ├── dsse: PAE + signature verification
                          ├── statement: in-toto subject + SLSA claims
                          ├── policy: strict fail-closed validation
                          └── models: stable PROV rule catalog
```

The CLI is a thin adapter (`cli.py`) around the library entry point `gate.evaluate(...)`. The library performs all decisions; no behavior is CLI-only.

## 2. Inputs

- **Attestation**: either a bare DSSE envelope (`payloadType`, base64 `payload`, `signatures`) or a Sigstore bundle v0.3/v0.2 JSON object containing `dsseEnvelope` and exactly one kind of verification material (PEM public key, `certificate`, or `x509CertificateChain`).
- **Artifact**: any local file. SHA-256 and SHA-512 are computed over the raw bytes.
- **Policy**: version 1 JSON with required `trust.builder_ids` and `source.uri`, plus optional exact-match expectations. Unknown keys are rejected to catch policy typos.
- **Key**: optional local PEM public key for bare envelopes that carry no verification material.

## 3. Verification pipeline

1. **Structural parsing** — JSON decoding, base64 strictness, envelope shape, in-toto Statement type, subject shape, predicate shape. Failures yield `ERROR` with rule `PROV001`.
2. **Signature verification** — each signature is verified over `DSSEv1 <len(type)> <type> <len(body)> <body>` (DSSE PAE). The algorithm is derived from the key object, never from attacker-controlled metadata. RSA is outside the default allowlist; ECDSA P-256/P-384 and Ed25519 are supported. By default *every* signature must verify.
3. **Identity binding** — when the policy names a signer identity or issuer, the bundle certificate must carry the matching SAN URI and Fulcio issuer extension value (`1.3.6.1.4.1.57264.1.1`).
4. **Artifact binding** — every allowed digest in every subject is checked against the computed artifact digest; forbidden (`md5`, `sha1`), unsupported and non-canonical digests are rejected. Exactly one subject may match.
5. **Build-parameter binding** — trusted builder id and build type, normalized source repository, optional exact ref, commit, workflow and event, optional denial of self-hosted runners, and timestamp ordering.
6. **Reporting** — findings sorted by rule id, message and location. Verdict is `PASS`, `FAIL` (one or more error findings) or `ERROR` (unusable input/policy). Exit codes are 0, 1 and 2 respectively.

## 4. Trust model

The policy is the trust root. It is supplied by the verifier, not by the attestation. A statement that is perfectly signed by an untrusted builder fails. A correctly signed statement about a different source repository fails. The tool never infers trust from the presence of a signature, a Fulcio issuer alone, or a familiar-looking workflow name.

Certificate verification uses the certificate's public key to check the DSSE signature and compares its SAN URI and issuer extension to the policy. It deliberately does **not** claim to validate a Fulcio CA chain, Rekor inclusion, TUF freshness or registry referrer discovery. Consumers that need those checks must perform them in the stage that fetches the bundle, then pass the resulting local files to this gate.

## 5. Rule catalog

| Range | Area |
| --- | --- |
| PROV001–PROV002 | Input structure and payload type |
| PROV003–PROV005 | Signature validity and key algorithm |
| PROV006–PROV008 | Signer identity, issuer and builder |
| PROV009–PROV011 | Digest form, digest equality and subject ambiguity |
| PROV012 | Predicate type allowlist |
| PROV013–PROV018 | Source, ref, commit, workflow, event and build type |
| PROV019–PROV021 | Runner environment and timestamp consistency |
| PROV022 | Invalid verification policy |

## 6. Determinism guarantees

- No network access, no environment-dependent configuration, no clock-based decision.
- JSON output uses sorted keys; SARIF results and rules are sorted; text output is stable.
- Findings carry JSON-pointer-style locations from the attestation.
- No randomness in library code; tests generate ephemeral keys only in fixtures.

## 7. Extension points

The module boundaries are stable: add new predicate extractors in `statement.py`, new verification material kinds in `bundle.py`, and new policy constraints in `policy.py`/`gate.py`. Every new check must add a rule ID in `models.py`, a unit test with an adversarial fixture, and documentation.

Baysöz Labs <baysozlabs@proton.me>
