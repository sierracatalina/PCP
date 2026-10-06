# Changelog

## task-4 — 2026-10-06

- Re-snapshotted `tests/fixtures/aaa/` schemas from Agent Aware Starter
  `task4-aaa-strict` branch commit `711e5e1f207443cb51289aab21a26b42c8dc25b1`
  (no tagged AAA release exists; re-snapshot from a tag when one is cut).
  The previous snapshot referenced commit `b19e138`, which is not in AAA's
  public history.
- The re-snapshotted schemas are strict: `additionalProperties: false` with a
  single `extensions` object, and defined `endpoints[]` items.
- Moved PCP-specific fixture fields `profile` and `http_action_api` into the
  fixture `ai-instructions.json`'s `extensions` object; both fixture documents
  validate against the strict schemas.
- `policy.allow_autonomous_execution` in fixtures is advisory only — AAA never
  grants authority (AAA spec 00, invariant 1).
- Updated `ARTIFACTS.sha256` for the touched fixture files.

## v0.1 — 2026-09-27

- Documented when `parser_record_forbidden`, `cl_type_forbidden`, and `recovery_is_not_a_grant` fire, and placed those codes in the conformance error precedence ahead of `unsupported_version` and `unknown_type`.
- Stated that a hosting workspace, chat host, or agent host is a carrier, not an issuer.
- Stated that an expired grant has no implicit renewal and no validity past `expires_at`, and that key rotation does not re-sign an issued grant.

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
