# PCP v0.1 — conformance

Conformance evidence in this repository is executable and revision-specific.

## Artifacts

| artifact | evidence |
| --- | --- |
| core and integration schemas | [schemas/](../schemas/) |
| atomic ledger model | [ledger.py](../pcp_reference/ledger.py) |
| detached proof model | [proof.py](../pcp_reference/proof.py) |
| signed receipt model | [receipt.py](../pcp_reference/receipt.py) |
| authority-position checks | [validation.py](../pcp_reference/validation.py) |
| explicit case denominator | [manifest.json](../conformance/manifest.json) |
| byte-level artifact inventory | [ARTIFACTS.sha256](../ARTIFACTS.sha256) |
| deterministic runner | [run_conformance.py](../scripts/run_conformance.py) |
| unit and integration tests | [tests/](../tests/) |

## Run

    python -m pip install -e .
    python -m unittest discover -s tests -v
    python scripts/run_conformance.py
    python scripts/release_scan.py .
    sh scripts/release-scan.sh .

The canonical shell release-scan entrypoint is `scripts/release-scan.sh`.

The conformance runner reads every case from the manifest, loads the exact named test, and emits ordered JSON. It exits nonzero for a missing, duplicated, unloaded, failed, or skipped case.

## Covered properties

- all checked-in schemas satisfy JSON Schema Draft 2020-12 meta-validation;
- clean checkouts preserve LF bytes for every manifested text artifact;
- strict unknown-property failures map to <code>unknown_property</code>;
- identity kind and URN mismatch fails closed;
- duplicate budget units fail closed;
- identical idempotent reservation, commit, and release requests return their original result;
- changed bytes under an existing idempotency key fail;
- two concurrent reservations for the final budget unit produce one winner;
- release and expiry restore only uncommitted budget;
- committed budget is terminal;
- detached Legatus proofs sign exactly `{context, signer_id, key_id, grant_id, purpose, envelope}`;
- Legatus idempotency keys match fixed JCS/SHA-256 vectors and distinguish delimiter-bearing thread and envelope ID pairs;
- opaque proof copies, signer, key, purpose, and envelope bindings fail into the signature lane;
- proof, authority, and availability failures use the two published PCP result families;
- receipt signatures and predecessor digests verify;
- duplicate receipts and broken chains fail;
- Context Layer request, grant, scope, audience, and expiry bindings fail closed;
- complete AAA 0.1 fixture documents validate against snapshot schemas;
- AAA origin, audience, scope action, grant expiry, and confirmation evidence fail closed;
- a memory-parser record or session receipt presented as authority fails <code>parser_record_forbidden</code>;
- a Context Layer pass, disclosure, scoped bundle, or context-authorization binding presented as authority fails <code>cl_type_forbidden</code>;
- a recovery or key-rotation artifact presented as authority fails <code>recovery_is_not_a_grant</code>;
- a workspace, chat host, or agent host presented as issuer fails <code>carrier_is_not_authority</code>;
- a grant is live only inside <code>[not_before, expires_at)</code>, with no skew grace and no in-place renewal; and
- key rotation publishes a new key without changing issued grant bytes, and a removed signing key fails <code>unknown_issuer</code>.

## Error precedence

Implementations apply errors in this order:

1. <code>malformed</code>, <code>duplicate_property</code>, <code>unknown_property</code>, <code>parser_record_forbidden</code>, <code>cl_type_forbidden</code>, <code>recovery_is_not_a_grant</code>, <code>unsupported_version</code>, <code>unknown_type</code>;
2. <code>identity_collapse</code>, <code>unknown_subject</code>, <code>carrier_is_not_authority</code>;
3. <code>unsigned</code>, <code>unknown_issuer</code>, <code>key_binding_mismatch</code>, <code>proof_binding_mismatch</code>, <code>bad_signature</code>;
4. <code>grant_binding_mismatch</code>, <code>not_before</code>, <code>expired</code>, <code>revoked</code>;
5. <code>purpose_mismatch</code>, <code>scope_invalid</code>, <code>delegate_forbidden</code>;
6. <code>idempotency_conflict</code>, <code>replay_detected</code>, <code>reservation_not_live</code>;
7. <code>budget_exhausted</code>, <code>receipt_chain_invalid</code>;
8. <code>verification_unavailable</code>.

A missing field, wrong JSON type, invalid enum, invalid pattern, or invalid range maps to <code>malformed</code>. Duplicate object keys map to <code>duplicate_property</code> before schema evaluation. An unknown property on a PCP object maps to <code>unknown_property</code>.

When a JSON object is offered in the authority position, the verifier reads <code>type</code> before grant-schema evaluation. The three non-grant codes below are that classification. They sit after <code>unknown_property</code> because that code belongs to PCP objects under schema evaluation, and a forbidden <code>type</code> is not run through the grant schema’s <code>additionalProperties</code> rule. They sit before <code>unsupported_version</code> and <code>unknown_type</code> because those two are residuals: a recognized forbidden <code>type</code> is not an unknown type, and it is reported even when <code>spec_version</code> is absent or is not <code>pcp/0.1</code>. They sit before group 2 and the signature group because the object is not a grant and must not be authenticated as one. The three sets are disjoint. The reference checks parser records, then Context Layer types, then recovery and rotation types.

<code>parser_record_forbidden</code> fires when <code>type</code> is <code>memory_parser_record</code> or <code>session_receipt</code>. A memory-parser record is context captured from a session. A session receipt records that session. A representative object has <code>type</code>, <code>id</code>, and <code>session_id</code>; any other members are ignored. A <code>pcp_receipt</code> is a PCP action receipt and does not use this code.

<code>cl_type_forbidden</code> fires when <code>type</code> is <code>context_pass</code>, <code>context_disclosure</code>, <code>scoped_bundle</code>, or <code>pcp_context_authorization</code>. A Context Layer pass, disclosure, or scoped bundle authorizes asking for or receiving context. <code>pcp_context_authorization</code> is the PCP binding beside a grant. None of these is authority to act.

<code>recovery_is_not_a_grant</code> fires when <code>type</code> is <code>pcp_recovery</code> or <code>pcp_key_rotation</code>. Recovery restores issuer-key control. Rotation publishes a key. Neither object mints or extends a grant.

A non-object, a missing <code>type</code>, or a non-string <code>type</code> is not one of these three codes. A string <code>type</code> outside PCP object types and outside these sets remains <code>unknown_type</code>. These three codes are not part of the Legatus signature family.

The Legatus adapter normalizes malformed proof syntax to <code>invalid_proof</code>. Its complete signature family is <code>invalid_proof</code>, <code>unsigned</code>, <code>unknown_key</code>, <code>unknown_issuer</code>, <code>bad_signature</code>, <code>proof_signer_mismatch</code>, <code>proof_key_mismatch</code>, <code>proof_purpose_mismatch</code>, <code>proof_envelope_mismatch</code>, <code>carrier_is_not_authority</code>, and <code>identity_collapse</code>. These map to <code>LEGATUS_E_SIG</code>. Grant denials stay out of band as <code>grant_not_found</code>, <code>expired</code>, <code>revoked</code>, <code>scope_mismatch</code>, or <code>budget_exhausted</code>. Only <code>unavailable</code> is retriable.

## Claim boundary

Passing this suite demonstrates behavior of the checked-in reference model for the manifest cases. It does not establish production security, durable distributed consistency, complete RFC 8785 coverage, external adoption, or independent certification.

Every published result should include the Git commit, manifest digest, runtime versions, and raw runner output. This document carries no fixed pass total.
