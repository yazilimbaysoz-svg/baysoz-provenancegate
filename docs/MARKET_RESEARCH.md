# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate

# Market Research: Offline SLSA Provenance Trust Gates

Maintained by Baysöz Labs <baysozlabs@proton.me>. Research date: 2026-11-25.

## 1. Method

- Audited all 37 entries in `/home/runner/work/_temp/existing-repos.json` to exclude overlapping domains.
- Ran live `gh search repos` for `devops`, `supply chain security`, `sbom`, `opentelemetry` (sorted by stars), and read star counts with `gh api`.
- Ran live `gh search issues` for open provenance/verification issues and reviewed public ecosystem reporting dated 2026-10/11.
- Cross-checked standards behavior against SLSA v1 provenance, in-toto Statement, DSSE and Sigstore bundle v0.3 conventions.

## 2. What the existing portfolio already covers

Existing Baysöz Labs projects cover Kubernetes CEL admission, pprof regression, archive extraction confinement, Compose readiness, SSRF canonicalization, PostgreSQL DDL, trace continuity, GraphQL cost, Alertmanager routing, CSP3, MCP contracts, vulnerability reachability, PodDisruptionBudget reachability, PromQL, NetworkPolicy, HTTP request smuggling, BOLA, SLO burn rates, Gateway API precedence, JOSE algorithm confusion, Terraform plan blast radius, OpenTelemetry Collector config, ATR/Sigma parity, GitHub Actions lockfiles, telemetry cardinality, log masking and environment drift.

None of them verify the trust chain of a **build attestation**: no existing repository parses a DSSE envelope, verifies a signature over the DSSE pre-authentication encoding, binds an artifact digest to an in-toto subject, or enforces builder/source/workflow claims. This project is therefore not a rename or a shallow variant of an existing tool.

## 3. Live ecosystem signals

| Signal | Measurement | Relevance |
| --- | --- | --- |
| `anchore/syft` | 9,966 stars | SBOM generation is mainstream; downstream trust decisions still need separate verification. |
| `sigstore/cosign` | 6,476 stars | De facto signing/verification tooling; bundle-format transitions create real migration failures. |
| `guacsec/guac` | 1,583 stars | Metadata graphs are useful, but require services; an offline gate is still missing. |
| `mozilla/cargo-vet` | 1,015 stars | Shows demand for policy-driven, reviewable supply-chain assertions. |
| `chainloop-dev/chainloop` | 617 stars | Attestation orchestration is growing; promotion decisions need deterministic policy checks. |
| `slsa-framework/slsa-verifier` | 352 stars | Its README points new GitHub Actions users elsewhere; the verification story is fragmented. |
| `helm/helm` | 30,489 stars | Context: the wider DevOps ecosystem expects mature, composable CLI contracts. |

## 4. Concrete ecosystem pain points found

1. **Ambiguous failure under partial attestation discovery.** `sigstore/cosign#5216` (opened 2026-11-11) reports that `GetBundles` silently skips referrers that fail to fetch. A policy controller then cannot distinguish "no SLSA attestation" from "fetch failed", producing intermittent admission decisions. An offline gate over explicit local bundles removes that ambiguity: the input set is explicit and every missing or invalid component becomes a named finding.
2. **The third verification check is routinely skipped.** Public 2026 guidance describes three checks a provenance verifier must perform: trusted signer identity, subject digest equals artifact bytes, and expected source/workflow/build parameters. The last check is the one a command still passes when the operator omits a flag, and npm has no such flag at all. A study of 1,523 SLSA-related GitHub issues identified implementation complexity and unclear communication as the main adoption barriers.
3. **Format and tool fragmentation.** Organizations must choose between `.intoto.jsonl`, legacy attestations, Cosign bundles and Sigstore bundle v0.3. Verification flags differ per ecosystem (`gh attestation verify`, `cosign verify-attestation`, `slsa-verifier`). A deterministic single-purpose gate with an explicit policy format provides one audit surface.
4. **Air-gapped and offline promotion.** Registry fetches, TUF refresh and transparency-log lookups are unavailable or rate-limited in air-gapped promotion stages. `immich-app/immich-charts#387` documents how remote references and 429s turn into random deployment failures (a different artifact, the same operational pattern). Local bundle + local artifact verification is the only viable stage in that environment.
5. **Signature-set weakening.** Multi-signature envelopes can be accepted when only one signature verifies, and algorithm confusion can arise when the verifier trusts a claimed algorithm rather than the actual key type. The gate derives the algorithm from the key object and, by default, requires every signature to verify.
6. **Subject ambiguity.** Multiple valid subjects matching the same artifact allow an attacker to attach a second, differently-described identity to identical bytes. The gate rejects ambiguous matches.

## 5. Product decision

Build **`baysoz-provenancegate`**: a Python 3.13+ CLI/library, installed with `uv`, using only the `cryptography` package beyond the standard library. No database, broker, registry client, container runtime, web server or local LLM is required. It consumes files that were already fetched and verified by the surrounding pipeline, and emits deterministic text, JSON or SARIF 2.1.0 output suitable for CI enforcement.

Scope is deliberately narrow: *verify the evidence you already hold*. Registry access, trust-root freshness and transparency-log inclusion are explicitly out of scope and documented as such, avoiding the silent over-claiming that motivated this research.

## 6. Differentiation

- Fail-closed policy: trusted builder set and expected source repository are mandatory; optional identity, issuer, ref, commit, workflow, event and build type are exact-match only.
- Real cryptography: DSSE PAE signatures verified with ECDSA P-256/P-384 or Ed25519 keys derived from the bundle or an explicit PEM key.
- Complete artifact binding: canonical SHA-256/SHA-512 subject verification, rejection of weak digests and ambiguous subjects.
- CI-native: 22 stable rule IDs, SARIF results with JSON-pointer locations, exit codes 0/1/2.
- Auditable: deterministic ordering, no network calls, no clock-dependent decisions, attribution embedded in every report.

Baysöz Labs <baysozlabs@proton.me>
