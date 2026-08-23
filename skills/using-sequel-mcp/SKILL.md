---
name: using-sequel-mcp
description: Run safe MySQL/MariaDB or SQLite queries through the sequel-mcp server with policy-gated writes, pre-mutation backups, MySQL/MariaDB Keychain credentials, and passwordless SQLite file connections. Use when the user wants to inspect, query, or modify a MySQL/MariaDB or SQLite database from an AI coding agent such as Claude Code or Codex, recover from a bad mutation, audit recent SQL activity, or import existing Sequel Ace connections. Covers read-only queries, gated writes/DDL/admin statements, restore-from-backup, per-database policy overrides, SQLite files, and SSH/Docker tunnel connections.
---

# Using sequel-mcp

`sequel-mcp` is an MCP server that lets an AI coding agent run real MySQL/MariaDB or SQLite SQL behind a policy gate. Every statement is classified (`read` / `write` / `ddl` / `admin` / `txCtrl`) and the corresponding action — `allow`, `confirm`, `deny` — is applied per-connection (and per-database/schema, if overrides exist). Mutations are backed up before execution so they can be replayed if the result is wrong.

## When to use this skill

- The user asks to query, modify, or inspect a MySQL, MariaDB, or SQLite database.
- The user wants to recover from a recent `UPDATE` / `DELETE` / `DROP` they (or you) ran.
- The user wants to audit what SQL was run, when, and from which connection.
- The user wants to import their existing Sequel Ace favorites.

Do not use for: Postgres, MSSQL, NoSQL, or generic "run shell SQL" requests outside supported MySQL/MariaDB/SQLite connections.

## Tools at a glance

Client UIs render MCP tool names differently. Claude Code commonly shows `sequel-mcp:query`; Codex may expose the same tool as `mcp__sequel-mcp__query` or another namespaced form. Map those names back to the core tool names below.

**Read path (always safe):**
- `sequel-mcp:list_connections` — what's configured (no secrets)
- `sequel-mcp:get_default_connection` / `sequel-mcp:set_default_connection`
- `sequel-mcp:list_databases` / `sequel-mcp:describe_table`
- `sequel-mcp:query` — single read-only statement. MySQL/MariaDB reads are wrapped in `START TRANSACTION READ ONLY`; SQLite reads open the file read-only.

**Write path (policy-gated):**
- `sequel-mcp:execute` — `INSERT/UPDATE/DELETE/DDL/admin`. The server elicits a 3-choice confirm when the category is `confirm`: *once / session / decline*.
- `sequel-mcp:restore_backup` — replay a pre-mutation backup; `dryRun=true` by default.

**Policy + setup:**
- `sequel-mcp:add_sqlite_connection` — SQLite file connection; no password or Keychain entry.
- `sequel-mcp:remove_connection` — forget a connection + its Keychain entry.
- `sequel-mcp:import_from_sequel_ace` — the guided MySQL/MariaDB setup path (imports favorites + Keychain). The interactive `add_connection` tool is not yet re-implemented in 0.10.0; MySQL connections otherwise come from the user's own config.
- `sequel-mcp:set_policy` — change baseline action set + caps.
- `sequel-mcp:set_table_policy` / `sequel-mcp:clear_table_policy` / `sequel-mcp:list_table_policies` — exact (`db.table`) or wildcard (`db.*`) rules; exact beats wildcard, strictest wins across tables.
- `sequel-mcp:explain_policy` — classify a statement and show the per-table resolution without executing.
- `sequel-mcp:select_database` — change a connection's default DB.

**Audit + housekeeping:**
- `sequel-mcp:audit_search` / `sequel-mcp:history_search` (unifies audit + Sequel Ace history)
- `sequel-mcp:list_backups` / `sequel-mcp:audit_cleanup` / `sequel-mcp:set_retention`
- `sequel-mcp:doctor` — sanitized diagnostic JSON (no secrets) suitable for bug reports.

**Optional Sequel Ace integration:**
- `sequel-mcp:import_from_sequel_ace` — read `Favorites.plist`, copy connections (and optionally passwords) into config + Keychain.
- `sequel-mcp:sequel_ace_history` — read the queryHistory.db Sequel Ace keeps.

## Choosing `query` vs `execute`

| Statement | Tool |
|-----------|------|
| `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, read-only SQLite `PRAGMA` | `sequel-mcp:query` |
| `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `TRUNCATE` | `sequel-mcp:execute` |
| `CREATE`, `DROP`, `ALTER`, `RENAME` (DDL) | `sequel-mcp:execute` |
| `GRANT`, `REVOKE`, `FLUSH`, `KILL`, `SET GLOBAL` (admin) | `sequel-mcp:execute` |
| `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT` (txCtrl) | `sequel-mcp:execute` |

The server rejects multi-statement input. Send one statement per call.

## Workflow: investigate a table

```
Goal: understand `orders` table on connection "prod-readonly"

Progress:
- [ ] list_databases → confirm DB exists
- [ ] describe_table table=orders → schema
- [ ] query: SHOW INDEX FROM orders → indexes
- [ ] query: SELECT COUNT(*) FROM orders → size
- [ ] query: SELECT * FROM orders LIMIT 5 → sample
- [ ] Summarize findings to user
```

## Workflow: recover from a bad mutation

The user just ran a destructive write through `sequel-mcp:execute` and the result is wrong.

```
Progress:
- [ ] sequel-mcp:list_backups connection=<name> → find recent backup_id
- [ ] sequel-mcp:audit_search connection=<name> outcome=success limit=5 → confirm backup linked to the bad statement
- [ ] sequel-mcp:restore_backup backupId=<id> dryRun=true → inspect plan
- [ ] sequel-mcp:restore_backup backupId=<id> dryRun=false → confirm with user, replay
- [ ] sequel-mcp:audit_search outcome=success limit=1 → verify restore appears in the log
```

Restores go through the same policy gate as live writes (so they elicit a confirm) and are themselves audited and backed up.

## Confirm grants: once / session

When the server elicits `confirm` for a `write` / `ddl` / `admin` statement, the user gets three choices:

- **Allow once** — authorizes only this statement.
- **Allow for session** — skips the prompt for the same `(connection, database, category)` until the MCP server restarts. RAM-only.
- **Decline** — abort; statement is audited as `declined`.

There is no inline "always" (dropped in 0.9.0). To make an allowance durable, use `set_table_policy`.

If the client cannot elicit at all, the server falls back to the local approval companions (`sequel-mcp approve` CLI or the native GUI window) for 60 seconds before failing closed.

A session grant on `staging` does **not** cover `prod`. Surface the scope clearly when relaying the prompt to the user.

## When the confirm prompt cannot be shown

Elicitation is an **optional** MCP capability, and even a client that supports it can fail to
deliver a specific prompt — no interactive surface in this session, a timeout, a dialog dismissed
unanswered. The MCP spec models this precisely: `ElicitResult.action` is `"accept" | "decline" |
"cancel"`, where `"cancel"` means *no explicit choice was made* — distinct from `"decline"`, a real
no. As of **sequel-mcp 0.9.1**, `confirm` honors that distinction end to end: only a genuine
`"decline"` is ever reported as declined. Anything else — capability not negotiated, the elicitation
call throwing, or a `"cancel"` result — surfaces as `outcome: error` with a specific `error_msg`
explaining why no answer exists, never as a fabricated refusal. This held true across the case that
motivated the fix: Claude Code launched with `--permission-mode bypassPermissions
--allow-dangerously-skip-permissions` (an unattended/automated mode with no live surface to show a
prompt in) legitimately resolves elicitation with `"cancel"` — before 0.9.1 that was misreported as
`"declined"`; now it correctly comes back as unavailable. The fix is protocol-level, not client-
specific, so it applies the same way in Claude Code CLI and Claude.app.

**Check `sequel-mcp:doctor` → `version` before trusting a `declined` result.** On ≥ 0.9.1, take a
`declined` outcome at face value. Below 0.9.1, a `cancel` a client never truly answered could still
show up as `"User declined confirmation. Statement not executed."`, indistinguishable in the tool
result from a real decline — do not tell the user "you declined X" on that basis alone. Ask them
directly instead: "did you actually see and decline a confirmation prompt just now?" If they say no,
don't retry the identical call (whatever blocked delivery will likely block it the same way again) —
get their explicit re-approval in chat, in their own words, and treat that as the authorization for
the retry. `elicitation.supported: true` in `doctor` only means the client negotiated the capability;
it does not by itself prove any given prompt will actually reach a human — a session-level block (like
`bypassPermissions`) can sit underneath a `true` and fail every single confirm the same way, not as a
one-off glitch.

Either way — capability genuinely absent, or a specific prompt genuinely undeliverable — the
resolution is the same: say so, and let the user choose explicitly (in chat, in their own words)
between running elsewhere (an interactive session/terminal) or temporarily authorizing a scoped policy
widen for the specific statements already agreed on. Never silently widen the policy yourself — that
is the user's call, on their data. If they choose the temporary-widen path, set it back afterward.

## Common mistakes to avoid

1. **Never put passwords in tool arguments.** MySQL/MariaDB credentials live in the macOS Keychain (`import_from_sequel_ace` copies them with the user's approval); SQLite uses `add_sqlite_connection` and has no password. Tool arguments are logged; secrets channels are not.
2. **Do not stack statements.** `SELECT 1; SELECT 2;` is rejected. Issue two calls instead.
3. **Do not bypass policy by asking the user to lower it.** If the user wants `write` allowed permanently, that is a `set_table_policy` change they make knowingly — scope it to the narrowest table or database, prefer `confirm` over `allow`, and put it back afterwards. The one case where proposing `allow` is legitimate is a client that cannot prompt at all (see above), and even then only with an explicit yes.
4. **Do not lose the `backup_id`.** Whenever `sequel-mcp:execute` returns a non-null `backupId`, mention it to the user in your reply — it's their rollback handle.
5. **Do not call `audit_cleanup` without `dryRun=true` first.** It deletes rows and VACUUMs.
6. **Do not take a `declined` result at face value on sequel-mcp < 0.9.1.** `elicitation.supported: true` does not guarantee the prompt actually reached the user — check `doctor` → `version` too, and if it's below 0.9.1, confirm with the user in chat before telling them "you declined." See [When the confirm prompt cannot be shown](#when-the-confirm-prompt-cannot-be-shown).

## Reference material

- Policy + per-DB overrides + presets: see [references/policy.md](references/policy.md)
- Recovery + restore semantics + insert-hint backups: see [references/recovery.md](references/recovery.md)
- Connection types (SQLite, direct MySQL/MariaDB, SSH, SSH+Docker, TLS-through-tunnel): see [references/connections.md](references/connections.md)

## File paths used by the server

- Config: `~/.config/sequel-mcp/config.json`
- Audit DB: `~/.local/share/sequel-mcp/audit.sqlite` (WAL mode, mmap, foreign keys on)
- Keychain service prefix: `sequel-mcp : <connection-name>`

Audit + backup data is local to the user's machine; no telemetry, no network calls beyond MySQL/MariaDB + SSH targets the user configures. SQLite connections access only the configured local database file path.
