# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate

# Security Policy

Maintained by Baysöz Labs <baysozlabs@proton.me>.

## Threats addressed

| Threat | Mitigation in 1.0.0 |
| --- | --- |
| Artifact substitution after build | SHA-256/SHA-512 subject binding to the exact local bytes. |
| Forged or tampered DSSE payload | Signature verified over the DSSE pre-authentication encoding, not the raw JSON text. |
| Algorithm confusion | Algorithm derived from the loaded key object; RSA excluded from the default allowlist. |
| Signature-set weakening | Every signature must verify by default; excessive signature counts are rejected. |
| Untrusted builder or fork | Exact builder-id allowlist and normalized source-repository check. |
| Workflow substitution | Exact ref, commit, workflow path and event checks when configured. |
| Self-hosted runner misrepresentation | Deny-by-policy scan of internal parameters for self-hosted markers. |
| Ambiguous attestation | Multiple matching subjects are rejected; digest mismatch on any allowed digest fails. |
| Malformed inputs and policy typos | Strict parsing, bounded sizes, key allowlists and unknown-key rejection. |
| Silent pass on broken evidence | Any error finding fails the gate; structural failures produce `ERROR` and exit code 2. |

## Explicit non-goals

The gate does not fetch artifacts or attestations, verify Fulcio CA chains, check Rekor transparency-log inclusion, refresh TUF trust roots, validate registry referrer discovery, or attest to the safety of source code. A passing verdict means: *the supplied evidence is internally consistent, cryptographically valid under the supplied key material, and matches the supplied policy*. It does not mean the builder was not compromised.

## Safe usage

- Treat the policy file as security-critical configuration; review changes like code.
- Fetch attestations over authenticated channels, then pass immutable local paths to the CLI.
- Keep `--key` material out of world-readable locations. The tool never writes private keys.
- Use `--format sarif --output` in CI so findings are archived with deterministic rule IDs.

## Reporting vulnerabilities

Report security issues privately to baysozlabs@proton.me with reproduction steps and affected version. Do not open public issues for unpatched vulnerabilities.

Baysöz Labs <baysozlabs@proton.me>
