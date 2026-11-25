# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate

# baysoz-provenancegate

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-provenancegate/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-provenancegate/actions/workflows/ci.yml)
![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Maintained by Baysöz Labs](https://img.shields.io/badge/maintained%20by-Bays%C3%B6z%20Labs-orange)

**Offline SLSA provenance trust gate with DSSE signature verification, artifact digest binding, build-policy enforcement and SARIF 2.1.0 CI reports.**

Built and maintained by **Baysöz Labs <baysozlabs@proton.me>**.

## Why

A signature only proves that somebody signed something. A provenance check must also answer: does the attestation describe *these exact bytes*, and was the artifact built from *the source and workflow you trust*? `baysoz-provenancegate` enforces all three checks offline, with no registry, database, service or local LLM.

## Install

```bash
uv venv
uv pip install -e .
uv pip install pytest
```

Requires Python 3.13+ and `cryptography>=44`. Console entry point: `baysoz-provenancegate`.

## Policy

The policy is the trust root and is supplied by the verifier. `trust.builder_ids` and `source.uri` are mandatory; all other constraints are exact-match and optional.

```json
{
  "version": 1,
  "trust": {
    "builder_ids": ["https://github.com/actions/runner-github/.github/workflows/release.yml@refs/heads/main"],
    "identity": "https://github.com/acme/widget/.github/workflows/release.yml@refs/heads/main",
    "issuer": "https://token.actions.githubusercontent.com"
  },
  "source": {
    "uri": "github.com/acme/widget",
    "ref": "refs/tags/v1.4.0",
    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "workflow": ".github/workflows/release.yml"
  },
  "build": {
    "type": "https://github.com/slsa-framework/github-actions-build@v1",
    "event": "release",
    "deny_self_hosted": true
  },
  "verify": {
    "predicate_types": ["https://slsa.dev/provenance/v1"],
    "digest_algorithms": ["sha256"],
    "allowed_key_types": ["ecdsa-p256", "ed25519"],
    "require_all_signatures": true,
    "maximum_signatures": 8
  }
}
```

Drop `trust.identity` and `trust.issuer` when verifying a bare DSSE envelope with `--key` (no X.509 signer material).

## Run

```bash
baysoz-provenancegate \
  --artifact release.tar.gz \
  --attestation attestation.sigstore.json \
  --policy policy.json \
  --format sarif --output provenance.sarif
```

### Real CLI output — version and help

```text
$ baysoz-provenancegate --version
baysoz-provenancegate 1.0.0 — Baysöz Labs <baysozlabs@proton.me>

$ baysoz-provenancegate --help
usage: baysoz-provenancegate [-h] [--version] --artifact ARTIFACT
                             --attestation ATTESTATION --policy POLICY
                             [--key KEY] [--format {text,json,sarif}]
                             [--output OUTPUT]

Offline SLSA provenance trust gate: verify DSSE signatures, artifact digests,
builder identity and build parameters. Built by Baysöz Labs
<baysozlabs@proton.me>.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --artifact ARTIFACT   artifact whose digest must match the in-toto subject
  --attestation ATTESTATION
                        DSSE envelope or Sigstore bundle JSON file
  --policy POLICY       fail-closed trust policy JSON file
  --key KEY             PEM public key for bare DSSE envelopes without
                        verification material
  --format {text,json,sarif}
                        report format (default: text)
  --output OUTPUT       write report to this file instead of stdout

Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate 1.0.0. Fail-closed,
deterministic, no network access.
```

### Real CLI output — valid bundle

```text
$ baysoz-provenancegate --artifact release.tar.gz \
    --attestation attestation.sigstore.json --policy policy.json
verdict: PASS
artifact: release.tar.gz
all provenance checks passed
Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate 1.0.0
exit=0
```

### Real CLI output — tampered payload and forged signature

```text
$ baysoz-provenancegate --artifact release.tar.gz \
    --attestation attestation-forged.json --policy policy.json
verdict: FAIL
artifact: release.tar.gz
[PROV003] no signature verifies over the DSSE pre-authentication encoding (/signatures)
[PROV004] signature 0 is not cryptographically valid (/signatures/0)
[PROV015] commit 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' does not match policy 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' (/predicate/buildDefinition/externalParameters/github/sha)
Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate 1.0.0
exit=1
```

## Architecture

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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust model and rule ranges, [`docs/MARKET_RESEARCH.md`](docs/MARKET_RESEARCH.md) for ecosystem evidence, and [`SECURITY.md`](SECURITY.md) for threats and limits.

## Library use

```python
from baysoz_provenancegate.gate import evaluate

report = evaluate("attestation.sigstore.json", "release.tar.gz", "policy.json")
print(report.verdict)
for finding in report.sorted_findings():
    print(finding.rule_id, finding.message, finding.location)
```

## Exit codes and evidence formats

| Code | Verdict | Meaning |
| --- | --- | --- |
| 0 | `PASS` | Every configured check succeeded. |
| 1 | `FAIL` | At least one check produced an error finding. |
| 2 | `ERROR` | Attestation, policy or key input could not be parsed. |

Accepted attestation inputs: bare DSSE envelope, Sigstore bundle v0.2/v0.3 with public key, X.509 `certificate`, or `x509CertificateChain`. Reports support `text`, `json` and `sarif`.

## Limits

The gate verifies the evidence it is given. It does not fetch from registries, verify Fulcio CA chains or Rekor inclusion, refresh TUF trust roots, or judge source-code safety. Fetch and authenticate bundles in a separate stage, then pass immutable local files here.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

18 adversarial tests, zero lint findings, zero security findings.

## License

MIT © Baysöz Labs <baysozlabs@proton.me>

Baysöz Labs <baysozlabs@proton.me>
