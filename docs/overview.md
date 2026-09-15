# PCP v0.1 — overview

PCP joins immutable signed authority with mutable revocation, budget, and receipt state.

## Components

~~~mermaid
flowchart TB
  G["signed grant"] --> V["authority verifier"]
  R["revocation log"] --> V
  L["linearizable budget ledger"] --> V
  V -->|allow + reservation| E["executor"]
  E -->|commit or release| L
  E -->|signed evidence| RC["receipt chain"]
~~~

The grant states maximum authority. The verifier narrows that authority to one request. The ledger prevents concurrent overspend and replay. The receipt records the durable result.

## Action lifecycle

~~~mermaid
stateDiagram-v2
  [*] --> Validated
  Validated --> Reserved: signature, scope, revocation, budget pass
  Reserved --> Committed: side effect durable + receipt
  Reserved --> Released: side effect did not start
  Reserved --> Released: recorded expiry
  Committed --> [*]
  Released --> [*]
~~~

Every terminal transition is a signed ledger event. Repeating the same canonical operation is idempotent. Reusing its key for different bytes fails.

## Integration

~~~mermaid
flowchart LR
  AAA["AAA action map"] -->|document digest + action| AB["PCP AAA binding"]
  CL["Context request"] -->|request digest + purpose| CB["PCP Context binding"]
  LEG["Legatus envelope"] -->|detached proof| LV["PCP Legatus verifier"]
  AB --> V["PCP authority decision"]
  CB --> V
  LV --> V
  V --> RC["PCP receipt"]
~~~

Each neighboring protocol validates its own object. PCP binds to an exact digest and selected fields, preserving ownership and preventing a later object from inheriting an earlier authorization.

## Read next

- [scope and invariants](C001-scope.md)
- [atomic budget ledger](budget-ledger.md)
- [receipt integrity](receipt-integrity.md)
- [integration bindings](integration-bindings.md)
- [Legatus detached proof](c019-legatus-sig.md)
- [conformance](conformance.md)
