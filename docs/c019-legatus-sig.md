# PCP v0.1 / Legatus — detached authority proof

This profile defines the cryptographic and authority seam for a strict Legatus envelope. Legatus owns envelope shape, clock, causality, floor, transitions, and append concurrency. PCP owns principal keys, grants, revocation, linearizable budget reservation, and authority receipts.

## 1. Exact signing object

PCP signs the RFC 8785 JCS encoding of exactly this six-field object:

```json
{
  "context": "pcp-legatus-v1",
  "signer_id": "urn:pcp:principal:alice",
  "key_id": "urn:pcp:key:alice-1",
  "grant_id": "urn:pcp:grant:grant-1",
  "purpose": "legatus.delegate",
  "envelope": {
    "legatus": 0,
    "id": "env-1",
    "thread": "thread-1",
    "type": "delegate",
    "parents": [],
    "clock": {"seq": 1, "now": 100},
    "signer": "urn:pcp:principal:alice",
    "payload": {
      "assignee": "urn:pcp:principal:worker",
      "task_ref": "work-1"
    }
  }
}
```

The nested envelope equals the complete candidate with only `sig` removed. No prefix, newline, digest, idempotency key, spend record, audience, request ID, or transport field enters the signing bytes. A verifier rejects duplicate JSON keys before JCS processing.

## 2. Compact carrier

Legatus keeps `sig` as an opaque compact string:

    pcp1.BASE64URL(JCS(header)).BASE64URL(Ed25519-signature)

The unpadded header contains exactly `context`, `signer_id`, `key_id`, `grant_id`, and `purpose`. The signature covers the six-field signing object above, including the reconstructed unsigned envelope.

The verifier requires:

- the request `proof` string equals `envelope.sig` byte for byte;
- the request signer, envelope signer, and protected signer are equal PCP principal URNs;
- the resolved key belongs to that signer and equals the protected key ID;
- the request purpose and protected purpose equal `legatus.` plus the envelope type; and
- Ed25519 verification succeeds over the exact six-field JCS object.

## 3. Exact verifier request

After validating the candidate envelope and payload schema, Legatus sends exactly these five fields:

```json
{
  "profile": "pcp-legatus-v1",
  "signer_id": "urn:pcp:principal:alice",
  "purpose": "legatus.delegate",
  "envelope": {
    "legatus": 0,
    "id": "env-1",
    "thread": "thread-1",
    "type": "delegate",
    "parents": [],
    "clock": {"seq": 1, "now": 100},
    "signer": "urn:pcp:principal:alice",
    "payload": {
      "assignee": "urn:pcp:principal:worker",
      "task_ref": "work-1"
    },
    "sig": "<whole-opaque-compact-proof>"
  },
  "proof": "<whole-opaque-compact-proof>"
}
```

PCP derives these authorization inputs after proof verification:

| value | derivation |
| --- | --- |
| audience | trusted verifier deployment configuration |
| action and purpose | exact `legatus.<envelope.type>` |
| resource | exact envelope thread or registered group containing it |
| idempotency key | `legatus:` plus SHA-256 of RFC 8785 JCS of exactly `{thread, envelope_id}`, serialized as `legatus:sha256:<64 lowercase hex>` |
| spend | one `actions` unit |
| envelope digest | SHA-256 of JCS of the unsigned envelope |
| reservation request digest | SHA-256 of JCS of the exact six-field signing object |

The derived digest supports receipts and reconciliation. These derived values stay outside the signed object.

## 4. Verification and reservation

The verifier applies this order:

1. parse the strict five-field request and opaque proof;
2. compare the duplicate opaque proof, signer, and purpose bindings;
3. decode the compact header, resolve its issuer key, and verify Ed25519;
4. validate the referenced grant’s subject, trusted audience, purpose, action, resource, and time window;
5. check authoritative revocation state; and
6. reserve one action atomically under the derived `legatus:sha256:<64 lowercase hex>` key.

An allow result contains `authorization_id`, which identifies the live reservation. It does not represent irreversible spend.

## 5. Legatus finalization

Legatus can reject an allowed candidate later because its floor, gate, transition, or timeout check fails. The adapter then releases the reservation. After a durable envelope append, the adapter commits the reservation and emits the signed PCP receipt. An append CAS loss can mean the same envelope won elsewhere, so the reservation remains live until journal refresh proves presence or absence. Presence commits; established absence releases. Other ambiguous append states remain reserved until log and receipt reconciliation or recorded reservation expiry.

An identical retry returns the same reservation or terminal outcome. Reusing the derived idempotency key with different canonical request bytes is denied.

The finalization endpoint runs on the same authenticated, integrity-protected integration channel as verification. `authorization_id` is an opaque lookup handle, never a bearer credential. PCP compares the authenticated integration, authorization handle, stored envelope ID, stored thread, requested outcome, and journal evidence before changing budget state. An identical finalization replay returns the original result. A conflicting terminal outcome is denied and sent to reconciliation.

The idempotency hash input is the UTF-8 RFC 8785 serialization of exactly `{thread, envelope_id}`. For `thread-1` and `env-1`, those bytes are `{"envelope_id":"env-1","thread":"thread-1"}` and the key is `legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38`. Delimiter-bearing identifiers remain unambiguous because each value is a distinct JSON member. The profile adapter also stores thread and envelope ID separately and compares both directly during finalization. The six-field proof request digest remains a separate value.

## 6. Stable result lanes

| lane | PCP codes | Legatus surface |
| --- | --- | --- |
| proof and identity | `invalid_proof`, `unsigned`, `unknown_key`, `unknown_issuer`, `bad_signature`, `proof_signer_mismatch`, `proof_key_mismatch`, `proof_purpose_mismatch`, `proof_envelope_mismatch`, `carrier_is_not_authority`, `identity_collapse` | `LEGATUS_E_SIG`; no append |
| authority | `grant_not_found`, `expired`, `revoked`, `scope_mismatch`, `budget_exhausted` | out-of-band PCP result; no append |
| availability | `unavailable` | retriable out-of-band PCP result; no append |

Only `unavailable` is retriable. Authority denials retain their PCP code and never become a Legatus transition or committed `fail` envelope.

## 7. Move mapping

| Legatus type | PCP purpose and scope action |
| --- | --- |
| `delegate` | `legatus.delegate` |
| `handoff` | `legatus.handoff` |
| `approve` | `legatus.approve` |
| `fail` | `legatus.fail` |
| `retry` | `legatus.retry` |
| `cancel` | `legatus.cancel` |
| `resume` | `legatus.resume` |

## 8. Machine contract

- Request: [pcp-verifier-request.schema.json](../schemas/pcp-verifier-request.schema.json)
- Verifier result: [pcp-verifier-result.schema.json](../schemas/pcp-verifier-result.schema.json)
- Out-of-band authority result: [pcp-result.schema.json](../schemas/pcp-result.schema.json)
- Finalize request: [pcp-finalize-request.schema.json](../schemas/pcp-finalize-request.schema.json)
- Finalize result: [pcp-finalize-result.schema.json](../schemas/pcp-finalize-result.schema.json)
- Detached-proof reference: [proof.py](../pcp_reference/proof.py)
- Atomic budget protocol: [budget-ledger.md](budget-ledger.md)

This profile publishes a contract and deterministic test model. It contains no issuer or production verifier.
