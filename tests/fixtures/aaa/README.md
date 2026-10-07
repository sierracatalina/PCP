# AAA integration fixtures

> **No tagged AAA release exists** (rechecked 2026-10-07 via GitHub's
> releases API, Git matching tag refs API, and `git ls-remote --tags`;
> all returned empty). Re-snapshot from an official release tag when one
> is published. The current snapshot pins the merged `main` commit below.

`agents.schema.json` and `ai-instructions.schema.json` are byte-for-byte,
test-only snapshots from Agent Aware Starter merge commit
[`d5b6b5b806a6e68a5fe07af320dbc7ded9b31c29`](https://github.com/sierracatalina/agent-aware-starter/commit/d5b6b5b806a6e68a5fe07af320dbc7ded9b31c29),
which merged [AAA PR #4](https://github.com/sierracatalina/agent-aware-starter/pull/4)
on 2026-10-07. These schema bytes are identical to reviewed PR head
`8cf515b5f16685d1d1da6b56088990d79bade3fd` and include the strict
`out_of_settings_actions` definition. They supersede the earlier branch
snapshot at `711e5e1f207443cb51289aab21a26b42c8dc25b1`.

| file | immutable source | source SHA-256 |
| --- | --- | --- |
| `agents.schema.json` | [upstream](https://github.com/sierracatalina/agent-aware-starter/blob/d5b6b5b806a6e68a5fe07af320dbc7ded9b31c29/schemas/agents.schema.json) | `d2ce277cdc766c34a3e100e847f4e86481a839f120e2b3728a7c2af864181b94` |
| `ai-instructions.schema.json` | [upstream](https://github.com/sierracatalina/agent-aware-starter/blob/d5b6b5b806a6e68a5fe07af320dbc7ded9b31c29/schemas/ai-instructions.schema.json) | `67de8a6e5c6903699d0e0c5b174c4a7c6778820c8ddda20b029aa4563dec41c5` |

The two JSON documents are PCP-owned integration fixtures shaped and validated
by those schemas. Updating the AAA snapshot requires recording the source
commit, release-tag status, source hashes, and updated `ARTIFACTS.sha256` entries.

Both documents declare `http_action_api: "declared"` at the top level, as
supported by AAA's schemas and required by PCP's `validate_aaa_binding()`.
The fixture `ai-instructions.json` keeps vendor-specific `profile` under
`extensions`. Unknown fields in strict objects remain rejected; vendor
metadata belongs in the declared `extensions` objects.

AAA describes discovery and the handshake. A principal-signed PCP grant is
the sole source of action authority. `policy.allow_autonomous_execution`
remains advisory (AAA spec 00, invariant 1); both boolean values preserve
PCP's grant scope and confirmation requirements. Tests cover schema validity,
complete-document digests, and binding validation, including rejection when
the HTTP API declaration appears only under `extensions`.
