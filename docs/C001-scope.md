# PCP v0.1 — scope and invariants

PCP specifies portable action authority. It defines identity kinds, signed grants, revocation, budget state, receipts, recovery boundaries, and explicit bindings to adjacent protocols.

## 1. Identity and authority

| kind | identifier | authority role |
| --- | --- | --- |
| principal | <code>urn:pcp:principal:…</code> | human source of issuance, revocation, and recovery authority |
| agent | <code>urn:pcp:agent:…</code> | software subject that acts only under a live grant |
| device | <code>urn:pcp:device:…</code> | key-holding subject that acts only under a live grant |

The kind field must match the URN. Reusing an ID across kinds returns <code>identity_collapse</code>.

A signed grant supplies authority. Authentication only proves control of an identity or transport credential. Carrier handles, OAuth identities, MCP sessions, chat identities, and TLS peers require an explicit binding before they can present a PCP subject.

## 2. Grant liveness

An action is allowed only when all checks succeed:

1. strict schema and duplicate-key validation;
2. active issuer key and valid Ed25519 signature over RFC 8785 JCS bytes;
3. known subject whose kind matches its URN;
4. current time inside <code>[not_before, expires_at)</code>;
5. no effective grant or family revocation in the authoritative revision;
6. exact purpose and audience;
7. requested actions and resources contained by the grant scope;
8. parent constraints satisfied for any child grant; and
9. atomic budget reservation completed for every requested unit.

Signature verification alone establishes historical authenticity. It does not establish current liveness.

## 3. Purpose, audience, and scope

v0.1 purpose matching is exact string equality. Implementations do not infer purpose from natural language, agent names, transport channels, or nearby purpose codes.

Scope contains explicit action and resource sets. Wildcards are outside the v0.1 core profile. A registered resource group may stand for a set only when the verifier resolves the exact group revision before authorization and includes that revision in evidence.

Audience identifies the service or origin allowed to consume the grant. A request for another audience fails <code>grant_binding_mismatch</code>.

## 4. Budgets

Budgets are optional positive-integer limits. Units and atomic state transitions are defined in [budget-ledger.md](budget-ledger.md). A present budget is enforced before the action starts.

The ledger serializes revocation and reservation decisions per grant. Reserved and committed amounts count against the limit. Released amounts become available after a signed release event.

## 5. Delegation

Subdelegation requires <code>allow_subdelegation: true</code>. A child must satisfy:

- exact parent purpose and audience;
- child action and resource sets contained by the parent sets;
- a time window contained by the parent window;
- explicit issuer authority to create the child; and
- parent-budget reservation for every child limit.

A child violation returns <code>delegate_forbidden</code> or <code>scope_invalid</code>. Sibling children cannot reserve the same parent budget.

## 6. Revocation and stop

A signed <code>pcp_revocation</code> names a grant, family, or both and carries a monotonic authority revision. Every online authorization reads authoritative revocation state. An unavailable check returns retryable <code>verification_unavailable</code>.

A user stop creates or causes an effective revocation before further work is authorized. Existing durable effects and receipts remain in history. A reservation whose side effect has not started is released. A completed side effect remains charged and receives a receipt.

## 7. Consent and confirmation

The issuer signature records the principal’s grant decision. Product consent, UI confirmation, and organizational approval remain distinct evidence. A protocol binding can require that evidence and cite its receipt.

AAA human-confirmation requirements remain effective after PCP authorization. Context Layer approval and reduction decisions remain effective after PCP authorization.

## 8. Receipts

Every action that reaches a side effect produces a signed PCP receipt before success. Receipts bind request and result digests, grant, subject, action, budget events, external evidence, and the preceding receipt digest. See [receipt-integrity.md](receipt-integrity.md).

## 9. Recovery

Recovery restores the principal’s control of issuer keys. It never issues or extends a grant. Recovery rotates compromised keys and publishes an authoritative key revision. A deployment should revoke grant families created under a compromised key.

## 10. Adjacent ownership

- Context Layer owns private-context requests, disclosure policy, scoped bundles, writeback proposals, and its receipts.
- AAA owns discovery metadata and declared action surfaces.
- Legatus owns coordination envelopes, clock, floor, causality, and transitions.
- Product runtimes own planning, execution, and user experience.

PCP bindings cite adjacent objects by ID and canonical digest. They do not rename or embed those protocol types. See [integration-bindings.md](integration-bindings.md).

## 11. Published scope

This repository publishes schemas, reference behavior, and deterministic tests. It publishes no issuer, key service, durable ledger, Context Layer service, AAA site, Legatus runtime, or product executor.
