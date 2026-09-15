# Changelog

## v0.1 — 2026-09-15

- Defined a purpose-bound authority contract with scoped, expiring, revocable, and budgeted grants.
- Added strict JSON Schemas for PCP core objects, atomic budget commands, Legatus verification, Context Layer authorization, and AAA action bindings.
- Defined linearizable reserve, commit, release, expiry, replay, and idempotency behavior.
- Added the exact PCP-Legatus detached proof over RFC 8785 JCS of `{context, signer_id, key_id, grant_id, purpose, envelope}` plus strict verifier and finalization contracts.
- Derived Legatus idempotency keys from SHA-256 of JCS `{thread, envelope_id}` to preserve unambiguous replay identity for delimiter-bearing identifiers.
- Added signed hash-chained receipts and correction semantics.
- Added stable errors for unknown properties, duplicate properties, proof and grant bindings, replay, reservation state, receipt chains, and verifier availability.
- Added a deterministic Python reference model, a machine-readable conformance manifest, tests, and CI.
- Added a portable public-release scanner and LF rules.
- Bound the artifact manifest to reproducible LF checkout bytes and documented `scripts/release-scan.sh` as the canonical shell entrypoint.
