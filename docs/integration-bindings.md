# PCP v0.1 — integration bindings

PCP supplies authority. Context Layer supplies governed disclosure. AAA supplies declared discovery metadata. Legatus supplies ordered coordination. Each layer keeps its own objects and validation rules.

## 1. Context Layer

`pcp_context_authorization` is a detached, signed companion to one Context Layer `context_request`. It does not add fields to the Context Layer request.

The binding covers:

- the exact Context Layer request ID and RFC 8785 JCS SHA-256 digest;
- PCP grant and subject IDs;
- authenticated requester principal and recipient;
- exact `purpose_code` and requested actions;
- audience and expiry.

The Context Layer policy engine validates both objects and the referenced PCP grant. It MUST confirm the request digest, requester, recipient, purpose, actions, audience, subject, issuer, and expiry; requested actions stay inside the grant scope, and the binding window stays inside both request and grant windows. A digest or field mismatch is `grant_binding_mismatch`. The engine preserves its own reductions, approval decision, single-use bundle, and receipt requirements. A PCP grant never expands a Context Layer policy decision.

The resulting PCP receipt cites the Context Layer receipt ID and digest in `evidence_refs`. Raw context stays inside Context Layer’s authority boundary.

Schema: [`../schemas/pcp-context-authorization.schema.json`](../schemas/pcp-context-authorization.schema.json).

## 2. AAA

AAA discovery metadata describes available actions. `pcp_aaa_action_binding` binds one grant to one observed discovery document and action. It covers:

- origin and discovery URL;
- SHA-256 digest of the validated discovery document;
- action ID, endpoint, and HTTP method;
- PCP audience, purpose, and scope action;
- whether AAA requires human confirmation; and
- the confirmation receipt when required.

Immediately before execution, the adapter MUST fetch both declared documents from the exact bound HTTPS origin, validate them under AAA, require active and live documents with a declared HTTP action API, recompute their digests, and compare every bound action field. The audience MUST equal the normalized origin, `scope_action` MUST equal the AAA action ID, and the binding expiry MUST fit inside the grant window. A mismatch denies execution as `grant_binding_mismatch` and requires a new binding.

PCP authorization never waives an AAA human-confirmation rule. When AAA marks an action for confirmation, the binding is valid for execution only with a signed confirmation receipt. The schema enforces this dependency.

Schema: [`../schemas/pcp-aaa-action-binding.schema.json`](../schemas/pcp-aaa-action-binding.schema.json).

## 3. Legatus

Legatus keeps its strict envelope. The opaque `sig` value carries the PCP detached proof described in [`c019-legatus-sig.md`](c019-legatus-sig.md). PCP returns an atomic budget reservation as `authorization_id` on allow. Legatus finalizes it as commit after a durable append, or as release after a deterministic floor, gate, transition, or timeout rejection. An append CAS loss remains reserved until journal refresh proves whether the same envelope became durable elsewhere.

Legatus performs its own envelope, clock, causality, floor, and transition checks. PCP performs signature, grant, purpose, scope, audience, time, revocation, replay, and budget checks.

Schemas: [verifier request](../schemas/pcp-verifier-request.schema.json), [verifier result](../schemas/pcp-verifier-result.schema.json), [authority result](../schemas/pcp-result.schema.json), [finalize request](../schemas/pcp-finalize-request.schema.json), and [finalize result](../schemas/pcp-finalize-result.schema.json).
