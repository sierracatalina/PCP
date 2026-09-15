# PCP v0.1 — receipt integrity

A `pcp_receipt` is the durable evidence returned after an authority-spending action. Every action that reaches a side effect MUST produce one receipt, including failed or cancelled outcomes after execution began.

## 1. Signed content

The receipt signature is Ed25519 over RFC 8785 JCS bytes of the complete receipt with `signature` removed. It binds:

- issuer, grant, and acting subject;
- action and idempotency key;
- canonical request and result SHA-256 digests;
- outcome and occurrence time;
- budget reservation and commit IDs, when a quantitative budget applies;
- evidence references from Legatus, Context Layer, AAA, or the runtime;
- the previous signed receipt digest; and
- the receipt being superseded, when this is a correction.

An implementation MUST use a complete RFC 8785 implementation. The checked-in Python reference intentionally accepts an ASCII, integer-only subset for deterministic fixtures.

## 2. Chain

Receipts form one ordered hash chain per grant. The first receipt has `previous_receipt_digest: null`. Every later receipt stores `sha256:<hex>` of the complete prior signed receipt in canonical form.

The receipt writer MUST serialize append by grant. A verifier rejects:

- a missing or incorrect predecessor digest as `receipt_chain_invalid`;
- a repeated receipt ID as `replay_detected`;
- an unknown property as `unknown_property`;
- a removed signing key as `unknown_issuer`; and
- a present key with an invalid signature as `bad_signature`.

Export order is chain order. Imports MUST validate schemas, signatures, unique IDs, predecessor digests, and every reservation/commit reference before accepting the chain.

## 3. Corrections

Receipts are immutable. A correction creates a new receipt whose `supersedes_receipt_id` identifies the prior receipt. The correction stays in the same hash chain. Deleting or rewriting the prior receipt invalidates later chain links.

## 4. Privacy

Receipts carry identifiers, bounded status, and digests. They MUST NOT contain raw prompts, context bundles, authorization headers, API keys, source records, model output, or other private payloads. Evidence bodies remain in their owning system under that system’s retention policy.

An evidence reference contains only `system`, `id`, and digest. A PCP receipt MAY cite a Context Layer receipt digest or Legatus envelope digest without copying either body.

## 5. Atomic success rule

For budgeted work, the budget commit and receipt are one durable transaction or one recoverable transactional-outbox operation. The caller receives success only after both are durable. For work without a quantitative budget, the signed receipt remains required before success.

Schema: [`../schemas/pcp.schema.json`](../schemas/pcp.schema.json). Reference signature and chain checks: [`../pcp_reference/receipt.py`](../pcp_reference/receipt.py).
