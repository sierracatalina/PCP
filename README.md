# Personal Context Protocol (PCP) v0.1

PCP is a draft authority contract for purpose-bound, scoped, expiring, revocable, and budgeted actions. This repository contains machine-readable schemas, a deterministic reference model, tests, and integration profiles. It contains no live issuer, production service, or private key.

## Contract

A PCP grant identifies:

- the principal that issued authority;
- the principal, agent, or device that may act;
- one exact purpose and audience;
- allowed actions and resources;
- optional integer budget limits;
- a bounded time window and revocation family; and
- whether constrained subdelegation is allowed.

Identity, transport authentication, discovery metadata, and context access never create authority by themselves.

~~~mermaid
flowchart LR
  P["principal"] -->|signed grant| PCP["PCP verifier + ledger"]
  PCP -->|scoped authority| X["executor"]
  X -->|signed receipt| P
  CL["Context Layer"] -. "request binding" .-> PCP
  AAA["AAA discovery"] -. "action binding" .-> PCP
  LEG["Legatus envelope"] -. "detached proof" .-> PCP
~~~

## Safety invariants

1. A live action requires a valid signed grant, exact purpose, audience, scope, subject, time window, and authoritative revocation check.
2. A carrier or authenticated account remains transport identity until an explicit PCP binding exists.
3. Every unknown or duplicate JSON property fails closed with a stable error.
4. Budget authorization uses reserve, commit, or release on one linearizable ledger history per grant.
5. One idempotency key identifies one canonical request for the grant’s lifetime.
6. A side effect produces a signed, hash-chained receipt before success is reported.
7. A verifier outage returns a retryable failure and starts no work.
8. Recovery restores issuer-key control and rotates keys. It creates no grant.

## Repository map

| path | role |
| --- | --- |
| [schemas/pcp.schema.json](schemas/pcp.schema.json) | identity, grant, revocation, ledger-event, receipt, export, and error objects |
| [schemas/pcp-budget-command.schema.json](schemas/pcp-budget-command.schema.json) | reserve, commit, and release commands |
| [schemas/pcp-verifier-request.schema.json](schemas/pcp-verifier-request.schema.json) | exact five-field Legatus verifier request |
| [schemas/pcp-verifier-result.schema.json](schemas/pcp-verifier-result.schema.json) | Legatus proof and authority disposition |
| [schemas/pcp-result.schema.json](schemas/pcp-result.schema.json) | out-of-band Legatus authority denial |
| [schemas/pcp-finalize-request.schema.json](schemas/pcp-finalize-request.schema.json) | commit or release request for a Legatus reservation |
| [schemas/pcp-finalize-result.schema.json](schemas/pcp-finalize-result.schema.json) | finalized Legatus reservation result |
| [schemas/pcp-context-authorization.schema.json](schemas/pcp-context-authorization.schema.json) | Context Layer request binding |
| [schemas/pcp-aaa-action-binding.schema.json](schemas/pcp-aaa-action-binding.schema.json) | AAA discovery/action binding |
| [docs/budget-ledger.md](docs/budget-ledger.md) | atomic budget and replay semantics |
| [docs/receipt-integrity.md](docs/receipt-integrity.md) | signed receipt and hash-chain rules |
| [docs/c019-legatus-sig.md](docs/c019-legatus-sig.md) | detached Legatus proof |
| [docs/integration-bindings.md](docs/integration-bindings.md) | Context Layer, AAA, and Legatus seams |
| [pcp_reference/](pcp_reference/) | executable reference behavior for conformance tests |
| [conformance/manifest.json](conformance/manifest.json) | explicit case denominator and test mapping |
| [ARTIFACTS.sha256](ARTIFACTS.sha256) | byte-level release artifact inventory |

## Quick validation

Python 3.11 or later is required.

    python -m pip install -e .
    python -m unittest discover -s tests -v
    python scripts/run_conformance.py
    python scripts/release_scan.py .

The canonical shell entrypoint runs the same release scan:

    sh scripts/release-scan.sh .

Current results come from the commands above. This README carries no frozen pass percentage.

## Authority state

A grant’s signature is immutable. Liveness also depends on mutable revocation and budget state. An online authorization decision therefore requires the authoritative ledger. Offline tooling may verify signatures and historical receipts; it cannot assert current authority.

Budgeted work follows:

~~~mermaid
sequenceDiagram
  participant E as Executor
  participant P as PCP ledger
  E->>P: reserve(grant, request digest, spend, idempotency key)
  P-->>E: durable reservation
  E->>E: perform side effect
  E->>P: commit(result digest, receipt id)
  P-->>E: durable commit + signed receipt
~~~

An action that never starts releases its reservation. Uncertain execution keeps the reservation until reconciliation or recorded expiry.

## Integration boundaries

- **Context Layer:** a detached signed object binds one PCP grant to the exact request digest, requester, recipient, purpose, actions, audience, and expiry. Context Layer retains disclosure reductions, single-use rules, approvals, and receipts.
- **AAA:** a signed binding covers the validated discovery-document digest and declared action. PCP authority preserves every AAA human-confirmation requirement.
- **Legatus:** its strict envelope remains unchanged. The opaque signature field carries a PCP proof over the exact principal, key, grant, purpose, and unsigned envelope object. PCP derives the trusted audience, one-action spend, and collision-free `legatus:sha256:<hex>` idempotency key from JCS of exactly `{thread, envelope_id}` during verification.

## Status and claim boundary

This is a protocol draft and reference conformance package. The tests demonstrate the checked-in model under their listed cases. Production security additionally requires durable storage, a complete RFC 8785 implementation, protected key custody, authenticated service transport, operational revocation, monitoring, and independent review.

License: MIT. See [LICENSE](LICENSE).
