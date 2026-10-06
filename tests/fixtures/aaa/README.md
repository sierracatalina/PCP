# AAA integration fixtures

> **No tagged AAA release exists** (checked 2026-10-06 via
> `gh api repos/sierracatalina/agent-aware-starter/tags` — empty).
> The schemas below are snapshotted from the `task4-aaa-strict` branch commit
> `711e5e1f207443cb51289aab21a26b42c8dc25b1` (pushed to origin), which carries
> the task-4 tightening (`additionalProperties: false` + `extensions`,
> defined `endpoints[]` items, `reference/validate.mjs`). Re-snapshot from a
> proper AAA tag as soon as one is cut. The previous snapshot referenced
> commit `b19e138145e76d060ee4be908389279c689f26b0`, which is not in AAA's
> public history.

`agents.schema.json` and `ai-instructions.schema.json` are test-only snapshots
from Agent Aware Starter commit `711e5e1f207443cb51289aab21a26b42c8dc25b1`.

| file | source SHA-256 |
| --- | --- |
| `agents.schema.json` | `d2ce277cdc766c34a3e100e847f4e86481a839f120e2b3728a7c2af864181b94` |
| `ai-instructions.schema.json` | `0a949bcf04833ac6ca2b48ae6fbddd1a3a39848c8a197f0d7913a681ce2e6e07` |

The two JSON documents are PCP-owned integration fixtures shaped and validated by those schemas. Updating the AAA snapshot requires recording the new source commit and hashes.

Note: the fixture `ai-instructions.json` keeps PCP-specific fields `profile` and
`http_action_api` inside its `extensions` object, which is the extension point
the strict AAA schema provides. `policy.allow_autonomous_execution` in these
fixtures is advisory only — AAA never grants authority (AAA spec 00, invariant 1).
