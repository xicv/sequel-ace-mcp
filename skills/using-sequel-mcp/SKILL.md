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
- `sequel-mcp:execute` — `INSERT/UPDATE/DELETE/DDL/admin`. The server elicits a 4-choice confirm when the category is `confirm`: *once / session / always / decline*.
- `sequel-mcp:restore_backup` — replay a pre-mutation backup; `dryRun=true` by default.

**Policy + setup:**
- `sequel-mcp:add_connection` / `sequel-mcp:remove_connection` — MySQL/MariaDB password is captured via elicitation, never via tool args.
- `sequel-mcp:add_sqlite_connection` — SQLite file connection; no password or Keychain entry.
- `sequel-mcp:set_policy` — change baseline action set + caps.
- `sequel-mcp:set_database_policy` / `sequel-mcp:clear_database_policy` / `sequel-mcp:list_database_policies` — per-DB overrides; strictest wins for multi-DB statements.
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

## Confirm grants: once / session / always

When the server elicits `confirm` for a `write` / `ddl` / `admin` statement, the user gets four choices:

- **Allow once** — authorizes only this statement.
- **Allow for session** — skips the prompt for the same `(connection, database, category)` until the MCP server restarts. RAM-only.
- **Allow always** — persists the policy as `allow` in the saved config (durable).
- **Decline** — abort; statement is audited as `declined`.

A session grant on `staging` does **not** cover `prod`. Surface the scope clearly when relaying the prompt to the user.

## Common mistakes to avoid

1. **Do not include passwords in `add_connection` arguments.** The server collects MySQL/MariaDB passwords through a separate elicitation channel and writes to the macOS Keychain. Tool arguments are logged; the elicitation reply is not. SQLite uses `add_sqlite_connection` and has no password.
2. **Do not stack statements.** `SELECT 1; SELECT 2;` is rejected. Issue two calls instead.
3. **Do not bypass policy by asking the user to lower it.** If the user wants to allow `write` permanently, walk them through the *"Allow always"* choice in the confirm prompt — that's the same outcome but with explicit consent.
4. **Do not lose the `backup_id`.** Whenever `sequel-mcp:execute` returns a non-null `backupId`, mention it to the user in your reply — it's their rollback handle.
5. **Do not call `audit_cleanup` without `dryRun=true` first.** It deletes rows and VACUUMs.

## Reference material

- Policy + per-DB overrides + presets: see [references/policy.md](references/policy.md)
- Recovery + restore semantics + insert-hint backups: see [references/recovery.md](references/recovery.md)
- Connection types (SQLite, direct MySQL/MariaDB, SSH, SSH+Docker, TLS-through-tunnel): see [references/connections.md](references/connections.md)

## File paths used by the server

- Config: `~/.config/sequel-mcp/config.json`
- Audit DB: `~/.local/share/sequel-mcp/audit.sqlite` (WAL mode, mmap, foreign keys on)
- Keychain service prefix: `sequel-mcp : <connection-name>`

Audit + backup data is local to the user's machine; no telemetry, no network calls beyond MySQL/MariaDB + SSH targets the user configures. SQLite connections access only the configured local database file path.
