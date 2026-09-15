# PCP schemas

These files are the checked-in PCP v0.1 machine contracts:

| schema | objects |
| --- | --- |
| [pcp.schema.json](pcp.schema.json) | principal, agent, device, grant, revocation, reservation, commit, release, receipt, export, error |
| [pcp-budget-command.schema.json](pcp-budget-command.schema.json) | reserve, commit, and release requests |
| [pcp-verifier-request.schema.json](pcp-verifier-request.schema.json) | exact Legatus verifier request |
| [pcp-verifier-result.schema.json](pcp-verifier-result.schema.json) | Legatus verifier disposition |
| [pcp-result.schema.json](pcp-result.schema.json) | out-of-band Legatus authority denial |
| [pcp-finalize-request.schema.json](pcp-finalize-request.schema.json) | Legatus reservation commit or release request |
| [pcp-finalize-result.schema.json](pcp-finalize-result.schema.json) | finalized Legatus reservation result |
| [pcp-context-authorization.schema.json](pcp-context-authorization.schema.json) | Context Layer authorization binding |
| [pcp-aaa-action-binding.schema.json](pcp-aaa-action-binding.schema.json) | AAA discovery/action binding |

All schemas use JSON Schema Draft 2020-12 and reject unknown properties. Parsers must reject duplicate object keys before schema validation.

Semantic checks that JSON Schema cannot express include:

- identity kind equals the URN kind;
- time-window ordering;
- unique budget units;
- subset and parent-budget rules for subdelegation;
- canonical digest and signature verification;
- revocation freshness;
- ledger serialization and idempotency history; and
- receipt-chain and cross-object reference integrity.

The reference package implements the cases named in the conformance manifest. The remaining semantic checks above are normative implementation obligations. Production implementations also need durable storage, complete RFC 8785 canonicalization, key custody, authenticated transport, and operational revocation.
