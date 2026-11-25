# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate

# Changelog

All notable changes to this project are documented here by Baysöz Labs <baysozlabs@proton.me>.

## 1.0.0 — 2026-11-25

- Initial release by Baysöz Labs <baysozlabs@proton.me>.
- Offline DSSE/Sigstore bundle parsing with strict JSON and base64 validation.
- Real ECDSA P-256/P-384 and Ed25519 signature verification over DSSE PAE.
- in-toto Statement subject binding with SHA-256/SHA-512, weak-digest rejection and ambiguity detection.
- Fail-closed trust policy for builder id, signer identity, issuer, source, ref, commit, workflow, event, build type and runner environment.
- Text, JSON and SARIF 2.1.0 reporting with stable `PROV001`–`PROV022` rule IDs and exit codes 0/1/2.
- Python 3.13 packaging with `uv`, pinned CI actions, 18 adversarial tests and zero lint/security findings.

Baysöz Labs <baysozlabs@proton.me>
