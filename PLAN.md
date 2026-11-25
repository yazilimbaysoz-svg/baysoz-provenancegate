# Baysöz Labs <baysozlabs@proton.me> — baysoz-provenancegate

# Plan

Owner: Baysöz Labs <baysozlabs@proton.me>. Version 1.0.0.

## Phase 1 — Research and scoping (complete)

- Audited the existing 37-repository portfolio for overlap.
- Mined live GitHub repository and issue signals for supply-chain and provenance pain points.
- Selected offline SLSA provenance verification as the uncovered, high-value gap.

## Phase 2 — Core engine (complete)

- DSSE envelope and Sigstore bundle parsing with strict base64/JSON handling.
- Real signature verification over DSSE PAE using `cryptography`.
- in-toto Statement and SLSA v1/v0.2 predicate extraction.
- Fail-closed policy validation, artifact digest binding and build-parameter checks.
- Deterministic findings, JSON/text/SARIF rendering and exit codes 0/1/2.

## Phase 3 — Enterprise packaging (complete)

- `src/` package layout, `pyproject.toml`, `uv` workflow, console entry point.
- `README.md`, `docs/MARKET_RESEARCH.md`, `docs/ARCHITECTURE.md`, `SECURITY.md`, `CHANGELOG.md`, MIT `LICENSE`.
- CI workflow with pinned actions and identical local quality gates.

## Phase 4 — Quality gates (complete)

- `uv venv && uv pip install -e . && uv pip install pytest && uv run pytest -q`
- `ruff check --select E,F,W,S,B .`
- `semgrep --config p/default --error .`
- Result: 18 tests passing, zero lint findings, zero security findings.

## Phase 5 — Tribunal and release (complete)

- Live execution against forged signatures, tampered payloads, mismatched build claims, self-hosted runners, weak digests, ambiguous subjects and malformed inputs.
- Unanimous pass required before publication.
- Public release under `yazilimbaysoz-svg` with topics for supply-chain, SLSA, Sigstore, DSSE, SARIF and DevOps.

## Roadmap (not in 1.0.0)

- Additional predicate profiles as standards stabilize, each behind an explicit allowlist.
- Optional detached certificate-chain checking when a trust bundle is supplied by the operator.
- Machine-readable policy migration helper for existing CI attestation flags.
- No services, no databases, no local models and no network-dependent verification will be added to the core gate.

Baysöz Labs <baysozlabs@proton.me>
