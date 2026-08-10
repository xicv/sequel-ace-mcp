# sequel-mcp

[![CI](https://github.com/xicv/sequel-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/xicv/sequel-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A Model Context Protocol server for **MySQL/MariaDB and SQLite** with policy-gated action sets, pre-mutation backups, an immutable audit log, macOS Keychain credential storage for MySQL/MariaDB, and optional Touch ID. Designed so Claude Code, Codex CLI, or any MCP client can run real SQL safely enough to use every day.

> **Sequel Ace is OPTIONAL.** This is a fully standalone MCP. Sequel Ace integration is a *bootstrap convenience* (one-time import of saved MySQL/MariaDB favorites) and a *history augment* (read its query history alongside our audit log). If you don't have Sequel Ace installed, all core tools still work — only `import_from_sequel_ace` and `sequel_ace_history` will fail with a clear "not found" error. Use `add_connection` or `add_sqlite_connection` instead.

> **Not published to npm.** This is a source-only project — clone and build it, then point your MCP client at the local `dist/index.js`. There is no `npx -y sequel-mcp` / `npm install -g sequel-mcp` path.

## Capabilities

Current release: **v0.9.3**. Full version history: [CHANGELOG.md](./CHANGELOG.md).

- **Two-layer permissions** — connection-level baseline + per-database overrides; strictest-wins for multi-DB statements (fail-closed).
- **SQLite connections** — first-class `driver: sqlite` connections via `add_sqlite_connection`, no password required, with `PRAGMA database_list` / `PRAGMA table_info` metadata support.
- **Pre-mutation backups** for UPDATE / DELETE / REPLACE / INSERT / TRUNCATE / DROP / ALTER, including multi-table UPDATE/DELETE.
- **Restore from any backup** via `restore_backup`. Plans + executes; default `dryRun=true`. Subject to the same policy gate as live writes.
- **Append-only audit log** at `~/.local/share/sequel-mcp/audit.sqlite` — redacted SQL, decision, outcome, duration, backup_id linkage; optional SHA-256 prev-hash chain (now written inside a single `BEGIN IMMEDIATE` transaction for atomic chain integrity).
- **Per-category retention** — `read=7d / write=30d / ddl=90d / admin=180d / txCtrl=7d`; auto-cleanup on boot.
- **Unified history search** — merges our audit log with Sequel Ace's `queryHistory.db` (when present) into one timeline.
- **macOS-native security** — Keychain-stored MySQL/MariaDB passwords (non-syncable, `WhenUnlockedThisDeviceOnly`); Touch ID via `LocalAuthentication`; SSH tunnels via `ssh2`.
- **Database inside a remote Docker container** *(0.5.0)* — five access patterns documented; first-class support for the closed-container case via SSH + `docker exec` stdio bridge with allowlist-validated commands.
- **SSH host key verification** *(0.5.0, opt-in)* — `hostKeyPolicy: 'strict'` matches against `~/.ssh/known_hosts`; SHA-256 fingerprint logged on every connect so users can opt in. `@revoked` markers honored even in lenient mode.
- **TLS server name preservation through tunnel** *(0.5.0, opt-in)* — `sslServerName` forwards original hostname into TLS handshake so cert SAN verification works against the real DB host instead of the tunnel's `127.0.0.1`.
- **Session-scoped confirm grants** *(0.6.0)* — `confirm` prompts surface a three-choice radio (Allow once / Allow for session / Decline). "Allow for session" skips further prompts for the same `(connection, database, category)` until the MCP server restarts. Grants are RAM-only and per-(conn, db, category) — a session grant on `staging` does not cover `prod`. Durable allowances go through `set_database_policy`; the inline "Allow always" choice was dropped in 0.9.0.
- **Companion Claude Code / Codex Skill** *(0.7.0)* — ships `skills/using-sequel-mcp/SKILL.md` plus references for policy, recovery, and connections. Teaches agents when to use `query` vs `execute`, how to relay the confirm grant scope, and the restore-from-backup workflow. Includes Codex-facing `agents/openai.yaml` metadata.
- **Structured tool results** *(0.7.0)* — every JSON-returning tool now emits `structuredContent` alongside the legacy text block per the latest MCP spec. Modern clients (Claude Code, Inspector) render structured responses; older clients are unaffected.
- **Server modularized** *(0.7.0)* — `src/server.ts` split from a 1180-line monolith into `src/server/{shared,run-sql,prompts,resources}.ts` + `src/server/tools/{sql,connections,policy,audit,backup,doctor}.ts`. Public `buildServer` API unchanged. Touch ID resolves lazily on first use (fixes a boot-window race + mutation). `restore_backup` honors the user's *Decline* choice (was previously ignored).

## Install

### Requirements

- macOS 12+ (Apple Silicon or Intel) — Keychain + Touch ID rely on macOS APIs.
- Node.js 20+ (24 supported).
- *Optional:* Xcode Command Line Tools — for the Touch ID helper. Install with `xcode-select --install`.

### Build from source

```bash
git clone https://github.com/xicv/sequel-mcp.git
cd sequel-mcp
npm install
npm run build
npm run build:touchid              # optional — Swift LocalAuthentication helper
```

The MCP entry point is at `<repo>/dist/index.js`. To update an existing install, `git pull && npm install && npm run build`, then restart the MCP server/client session so it picks up the new `dist/`.

### Wire into Claude Code

```bash
claude mcp add --scope user sequel-mcp -- node /absolute/path/to/sequel-mcp/dist/index.js
```

Verify:

```bash
claude mcp list   # sequel-mcp should appear with ✓ Connected
```

In a Claude Code session, `/mcp` lists every tool the server exposes.

### Wire into Codex CLI

```bash
codex mcp add sequel-mcp -- node /absolute/path/to/sequel-mcp/dist/index.js
```

Equivalent `~/.codex/config.toml` entry:

```toml
[mcp_servers.sequel-mcp]
command = "node"
args = ["/absolute/path/to/sequel-mcp/dist/index.js"]
startup_timeout_sec = 20
tool_timeout_sec = 600
```

Verify:

```bash
codex mcp list
```

This repo also includes `.codex/config.toml` for trusted project-scoped Codex sessions — it points at the local build via a repo-relative path, so it only works when Codex loads it from within a built checkout of this repo. Install the Skill separately with one of the options below.

### Install the companion Skill (optional, v0.7.0+)

The Skill at `skills/using-sequel-mcp/` teaches Claude Code and Codex *when* to use each tool — read-vs-execute decisions, confirm-grant scopes, the recovery workflow. Install it once for the client you use:

```bash
mkdir -p ~/.claude/skills
ln -sf "$(pwd)/skills/using-sequel-mcp" ~/.claude/skills/using-sequel-mcp
```

For Codex, either place the skill in your Codex skills directory:

```bash
mkdir -p ~/.codex/skills
ln -sf "$(pwd)/skills/using-sequel-mcp" ~/.codex/skills/using-sequel-mcp
```

Or point Codex at the skill from `~/.codex/config.toml`:

```toml
[[skills.config]]
path = "/absolute/path/to/sequel-mcp/skills/using-sequel-mcp"
enabled = true
```

Claude Code and Codex pick up the `SKILL.md` frontmatter on next session start. The Skill loads body content only when relevant, so token cost stays low until triggered.

### Wire into Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sequel-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/sequel-mcp/dist/index.js"]
    }
  }
}
```

Restart Claude Desktop.

### Wire into Cursor / other MCP clients

Any client that speaks the MCP stdio transport works. Point its `command` at `node` with the absolute `dist/index.js` path.

### First-run quickstart

MySQL/MariaDB:

```text
"Add a sequel-mcp connection 'local' on 127.0.0.1:3306, user root, database app, read-only preset."
"Set the default connection to local."
"Count rows in users."
```

SQLite:

```text
"Add a SQLite sequel-mcp connection 'local-sqlite' at ~/Projects/app/dev.sqlite, read-only preset."
"Set the default connection to local-sqlite."
"Count rows in users."
```

Already use Sequel Ace? `"Import my Sequel Ace connections."` instead — macOS prompts once per favorite to allow Keychain access (click *Always Allow*).

MySQL/MariaDB passwords are elicited mid-call into the macOS Keychain. SQLite connections store only the database file path. **No credentials in any config file.**

## Action sets — the permission model

Each connection has a policy with five categories. Each is `allow` | `confirm` | `deny`.

| Category | What it covers                                           |
|----------|----------------------------------------------------------|
| `read`   | `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, read-only SQLite `PRAGMA` |
| `write`  | `INSERT`, `UPDATE`, `DELETE`, `REPLACE`                  |
| `ddl`    | `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `RENAME`          |
| `admin`  | `GRANT`, `REVOKE`, `SET GLOBAL`, `KILL`, `FLUSH`, `LOAD` |
| `txCtrl` | `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`               |

`confirm` triggers an MCP **elicitation** — the client surfaces a radio with three choices: **Allow once** (this statement), **Allow for session** (skip prompts for the same `(connection, database, category)` until the MCP server restarts), or **Decline**. The prompt is **server-issued per call** — no client allowlist can bypass it.

> **Elicitation is an optional MCP capability.** In a client that does not implement it, no prompt can be shown, so a `confirm` policy can never be satisfied and every gated statement fails closed. Since 0.9.0 that is reported as an explicit "prompt could not be delivered" error — with the reason, and audited as `outcome=error` rather than `declined` — instead of being mistaken for a refusal. Check `doctor` → `elicitation.supported`; where it is `false`, use an explicit `allow` or `deny`.

### Presets

| Preset      | read   | write   | ddl     | admin  | rowCap | timeout | Touch ID |
|-------------|--------|---------|---------|--------|--------|---------|----------|
| `read-only` | allow  | deny    | deny    | deny   | 1000   | 10s     | off      |
| `dev`       | allow  | confirm | confirm | deny   | 5000   | 30s     | off      |
| `admin`     | allow  | confirm | confirm | confirm| 5000   | 60s     | **on**   |

Adjust per-connection via `set_policy` or per-database via `set_database_policy` — no JSON editing.

## Tools (26)

| Tool                       | Annotation               | What it does |
|----------------------------|--------------------------|--------------|
| `query`                    | readOnly                 | Single read SELECT/SHOW/DESCRIBE/EXPLAIN, plus read-only SQLite PRAGMA statements. MySQL/MariaDB reads are wrapped in `START TRANSACTION READ ONLY`; SQLite reads open the file read-only. |
| `execute`                  | destructive              | Single non-read statement; subject to policy. Backup captured automatically. |
| `describe_table`           | readOnly                 | `DESCRIBE table` on MySQL/MariaDB; `PRAGMA table_info` on SQLite. |
| `list_databases`           | readOnly                 | `SHOW DATABASES` on MySQL/MariaDB; `PRAGMA database_list` on SQLite. |
| `list_connections`         | readOnly                 | Saved connections (no secrets). Marks `isDefault`. |
| `add_connection`           | -                        | Add/update MySQL/MariaDB connection. Password via elicitation → Keychain. |
| `add_sqlite_connection`    | -                        | Add/update SQLite file connection. No password or Keychain entry. |
| `remove_connection`        | destructive              | Forget a connection + delete Keychain entry. |
| `set_policy`               | -                        | Change a connection's baseline action set or limits. |
| `set_database_policy`      | -                        | Per-database policy override. Takes precedence over baseline. |
| `clear_database_policy`    | -                        | Revert one DB to baseline cascade. |
| `list_database_policies`   | readOnly                 | Baseline + every override for a connection. |
| `set_default_connection`   | -                        | Subsequent calls use this when `connection` arg omitted. Empty string clears. |
| `get_default_connection`   | readOnly                 | Return the current default name. |
| `select_database`          | -                        | Set a connection's default database (no password needed). |
| `audit_search`             | readOnly                 | Query the local audit log SQLite. |
| `audit_cleanup`            | destructive              | Prune entries past retention. `dryRun=true` to preview. |
| `set_retention`            | -                        | Configure per-category windows + size caps. |
| `list_backups`             | readOnly                 | Show recent pre-mutation backups. |
| `restore_backup`           | destructive              | Replay a backup back into the originating MySQL/MariaDB or SQLite connection. Default `dryRun=true`. Goes through the policy gate. |
| `history_search`           | readOnly                 | Unified timeline: MCP audit + Sequel Ace queryHistory.db (when present). |
| `import_from_sequel_ace`   | -                        | One-time import from Sequel Ace's `Favorites.plist` + Keychain. **Requires Sequel Ace installed.** |
| `sequel_ace_history`       | readOnly                 | Read Sequel Ace's GUI query history (read-only). **Requires Sequel Ace installed.** |
| `doctor`                   | readOnly                 | Sanitized JSON diagnostic. **No passwords.** |
| `setup-connection` (prompt)| -                        | Guided new-connection workflow. |
| `analyze-table` (prompt)   | -                        | Read-only schema/index/sample inspection. |

Plus one resource: `sequel-mcp://connections` (JSON listing).

---

## Security playbook — real-world use

This section is the *how-to-not-shoot-yourself* guide. The tool's defaults are conservative; this section tells you exactly what to do at each level of trust.

### Daily read-only operation (recommended baseline)

The default preset is `read-only`. Writes/DDL/admin are **denied outright** — not "confirm", but "blocked". Run as much SELECT/SHOW/DESCRIBE/EXPLAIN as you want.

```text
"On acme-prod, list databases."
"Describe the users table on acme-prod/app."
"On acme-prod, count rows in orders where status = 'pending'."
```

If Claude tries to write, it gets `Denied by policy: write statements not allowed on "acme-prod"`. No prompt, no slip — the only escape is you explicitly relaxing the policy.

**This is the level I recommend for all production connections, all the time.**

### Adding selective write capability (per-database, scoped)

You rarely need writes everywhere. Scope them down:

```text
"Set baseline on acme-prod to read-only."
"Override the policy for staging on acme-prod: write=confirm, ddl=deny."
"List database policies on acme-prod."
   → baseline read-only; staging has write=confirm; everything else read-only.
```

Now Claude can `INSERT`/`UPDATE`/`DELETE` on `staging` only — every write triggers a CONFIRM prompt — and is silently blocked on every other DB. A cross-DB `JOIN` that touches a denied DB fails closed.

### Confirming a write

When `write=confirm`:

1. Claude runs the tool. The server classifies it (AST + admin keyword fallback). Multi-statement input rejected.
2. Server fires `elicitation/create` to your client. You see:
   ```
   About to run a WRITE statement on connection "acme-prod".
   --- SQL ---
   UPDATE staging.users SET email = 'x' WHERE id = 1
   --- end ---

   Pick an authorization scope.
     ( ) Allow once (this statement only)
     ( ) Allow for session (all WRITE statements until restart)
     ( ) Decline
   ```
3. Pick a scope. **Decline** (or closing the dialog) cancels.
4. **Backup captured** in the same transaction (`SELECT … FOR UPDATE` on MySQL/MariaDB; `BEGIN IMMEDIATE` + pre-image `SELECT` on SQLite).
5. Statement runs.
6. Audit log entry written, linked to `backup_id`.

#### Choosing the right scope

| Scope | Effect | Survives restart? | Use when |
|-------|--------|-------------------|----------|
| **Allow once** | This statement only. Next write re-prompts. | n/a (single shot) | One-off write — you want to review every subsequent statement too. |
| **Allow for session** | Skips the prompt for the same `(connection, database, category)` on every later statement in this MCP session. | **No** — dies when the MCP server process exits. | You're running a batch (migration, bulk update) and don't want N prompts. Each restart re-arms the gate. |
| **`set_database_policy`** | Not a prompt choice — a separate tool call that writes `policy[category]` for one database. | **Yes** — written to the config JSON. | The category should genuinely no longer be gated there. Prefer scoping to a single database, and put it back afterwards. |
| **Decline** | Statement does not run; audit entry recorded as `declined`. | n/a | Reject this attempt. |

Session grants are scoped per `(connection, database, category)`. A session grant for `acme-prod/staging:write` does **not** cover `acme-prod/prod:write` — the strictest-wins multi-DB resolver still applies, so a cross-DB statement that touches both is gated on the prod side until you grant that too. Session grants do **not** bypass Touch ID — `requireTouchID: true` still prompts independently.

You'd see this exact flow even if Claude is being prompt-injected — the prompt isn't bypassable from the model side. And telling Claude in chat "I allow this" cannot register a grant on its own; the grant has to enter through the elicit dialog (or a future explicit grant tool).

### Reviewing the audit log (weekly habit)

```text
"Search audit log for the last 7 days, outcome=denied."
   → audit_search({sinceIso: '...', outcome: 'denied'})
   Shows what Claude tried that you blocked. Useful for: "is the model
   trying to do things I didn't expect?"

"Search audit log for the last 7 days, category=write."
   → All confirmed writes. Skim to make sure each was intentional.
```

If a denied entry surprises you, that's signal — either the model misunderstood your request, or your policy needs tightening.

### Restoring from a mistake

When something goes sideways:

```text
"List backups on acme-prod from the last day."
   → list_backups, sorted newest first.

"Show me the restore plan for backup #142, dry run."
   → restore_backup({backupId: 142, dryRun: true})
   Returns the exact SQL it would run + warnings.

"Restore backup #142."
   → restore_backup({backupId: 142, dryRun: false})
   Re-confirmation. Plays back via dialect-specific upsert statements
   (for UPDATE/DELETE) or DELETE BETWEEN/IN (for INSERT-hint).
```

**Always run the dry-run first.** Look at the warnings: schema may have changed since backup; FK constraints may break the restore order.

### Touch ID for high-value DBs

For your most sensitive connection (prod, customer PII), require user-presence per session:

```text
"Set policy on acme-prod: requireTouchID=true."
```

First operation in a 15-minute idle window pops the macOS Touch ID dialog. Subsequent calls within the window skip the prompt. Trade-off: 200-500 ms latency per session unlock; vs. shoulder-surfed laptop entropy.

For *very* high-value DBs, also reduce `stmtTimeoutMs` to 5000ms and `rowCap` to 100 — caps any accidental large query.

### Multi-DB safety

Cross-DB statements are tricky:

```sql
INSERT INTO db1.audit SELECT * FROM db2.users;
```

This statement touches `db1` (write) and `db2` (read). If `db2` has `read=deny` for any reason, the whole statement is denied — **fail closed**. The audit log records `contributing_database: db2` so you know which constraint fired.

The merge rule (Apache Ranger semantics): for each category in the statement, take the strictest action across all touched DBs. `deny > confirm > allow`.

### Incident response — Claude did something unexpected

```text
1. "Show audit log entries for the last 30 minutes."
   → audit_search({sinceIso: '...'})
   Find the offending request_id.

2. "Show backup #N."
   → list_backups + the row's backup_id.

3. "Restore backup #N, dry run."
   → restore_backup({backupId: N, dryRun: true})
   Verify the plan matches what you want to undo.

4. "Restore backup #N."
   → executes; type CONFIRM.

5. (After resolution) "Tighten policy on <connection> to read-only."
   → set_policy. Prevent recurrence.
```

Every step is one tool call. The audit log is append-only — even if the SQLite file is moved, the rows stay (no UPDATE/DELETE on it from the MCP itself).

### Production database inside a Docker container on a remote bastion (0.5.0)

The realistic shape of a hardened production setup:

```
your laptop ──SSH (strict host key)──> bastion.example.com
                                             │
                                             ├─ docker exec -i mysql_prod nc 127.0.0.1 3306
                                             ▼
                                       container with MySQL 8.4 (TLS on)
```

Step by step:

```text
1. "On bastion.example.com, run docker ps to confirm container 'mysql_prod' is up."
   → Use your normal SSH client to verify infrastructure first. NOT through MCP.
   → Capture the SHA-256 fingerprint shown when you connect — paste into known_hosts:
       ssh-keyscan -t ed25519 bastion.example.com >> ~/.ssh/known_hosts

2. "Add a connection named prod-mysql, host 127.0.0.1, port 3306, user readonly,
    ssl true, ssl server name mysql.prod.internal,
    ssh host bastion.example.com, ssh user deploy, ssh key path ~/.ssh/id_ed25519,
    ssh host key policy strict,
    ssh docker container mysql_prod, ssh docker bridge tool nc,
    policy preset read-only."
   → Single tool call. Password elicited mid-call into Keychain.
   → strict mode rejects the connection if the host key changes (MitM signal).
   → sslServerName makes mysql2 verify the cert SAN against mysql.prod.internal.
   → read-only preset means writes are denied, not "confirm".

3. "On prod-mysql, list databases."
   → First query opens the SSH session, runs docker inspect, verifies nc is in
     the container, opens the exec channel, mysql2 handshakes over TLS through
     the bridge, query runs, all logged.

4. "Search audit log for prod-mysql in the last hour."
   → Should show one entry: outcome=success, category=read.
```

If any of these go wrong, the failure mode is *visible*:
- Host key mismatch → `SSH host key MISMATCH for bastion.example.com:22 (strict mode — rejecting)`. Connection fails fast.
- Container missing → `container mysql_prod is not running`. Connection fails fast.
- Bridge tool absent → `bridge tool 'nc' not found in container 'mysql_prod'`. Pick `socat` or `ncat` instead.
- TLS cert mismatch → mysql2 raises `ERR_TLS_CERT_ALTNAME_INVALID` with the actual SAN names — fix `sslServerName` to match.

### Hardening an existing tunnel: lenient → strict host key (0.5.0)

For users with pre-0.5.0 connections, the upgrade path is:

```text
1. "Run a query on <existing-conn> — anything trivial like SELECT 1."
   → Watch sequel-mcp stderr (Claude Code shows it under MCP logs). You'll see:
       [sequel-mcp] SSH host bastion.example.com:22 fingerprint=SHA256:abc123…

2. (Out of band, in your shell:)
   ssh-keyscan -t ed25519 bastion.example.com | grep -v '^#' >> ~/.ssh/known_hosts
   → Verify the captured key has the same SHA-256 fingerprint as step 1.
     Compare via: ssh-keygen -lf ~/.ssh/known_hosts -F bastion.example.com

3. "Re-add the connection <existing-conn> with ssh host key policy strict."
   → add_connection is idempotent on `name`; existing fields are preserved
     except those you explicitly change. Password not re-prompted unless
     missing in Keychain.

4. "Run a query on <existing-conn>." → still works.
   → Now MitM on the SSH leg = visible failure, not silent compromise.
```

Optional: scope known_hosts to a project file:

```text
"Re-add the connection prod-mysql with ssh known hosts path
 ~/projects/sequel-mcp/.known_hosts and ssh host key policy strict."
```

### TLS to MySQL when the cert was issued for the real DB hostname

If your DBA gave the MySQL server a cert with SAN `mysql.prod.internal`, but you connect via SSH tunnel (so mysql2 sees `127.0.0.1`), the SAN check fails or silently passes depending on mysql2 internals. Pin it:

```text
"Add a connection … ssl true, ssl server name mysql.prod.internal."
```

mysql2 receives `{ servername: 'mysql.prod.internal' }`, the TLS handshake's SNI header carries that name, and the cert SAN verification compares against it. Mismatched cert = loud failure, not silent bypass.

If your cert SAN was actually issued for `127.0.0.1` (unusual, sometimes done for tunnel-only setups), leave `sslServerName` unset — the legacy behavior remains.

### When NOT to use this MCP

- **You need Multi-statement scripts.** Out of scope. The MCP rejects them at parse time *and* at the driver level. Use a migration tool.
- **High-write-throughput automation.** Backup capture adds transactional reads/locks; not a good fit for >1000 mutations/min.
- **Production deploys.** Use a real migration framework (Liquibase, Flyway, Atlas). This MCP is for ad-hoc + investigative use.
- **Other tools modifying the same rows.** The MCP holds transactional locks during backup; concurrent writers may serialize.

### Recommended starting policy for a real workplace setup

| Connection | Baseline | Per-DB overrides |
|---|---|---|
| `prod-readonly` | read-only | none |
| `prod-admin` | read-only, `requireTouchID=true` | only on a single migration DB: `write=confirm`, `ddl=confirm` |
| `staging` | dev | `confirm` for writes, `confirm` for DDL |
| `local-dev` | dev | none — full freedom on local Docker |

Set this up once via `set_policy` + `set_database_policy`. Saved in `~/.config/sequel-mcp/config.json`. Persists across CC sessions.

### Daily-use sanity check

Before considering this MCP routine for production, run this drill once on a non-critical DB:

```text
1. doctor                                    → confirm config sane
2. set baseline read-only                    → safer default
3. override one staging DB to write=confirm  → scoped relaxation
4. INSERT a test row → CONFIRM works         → proves policy gate
5. list_backups → see the insert-hint backup → proves backup capture
6. restore_backup id=N --dry-run             → verify plan
7. restore_backup id=N                       → CONFIRM, watch row deleted
8. audit_search → see all four entries      → proves audit linkage
```

If steps 4-8 work end-to-end, you've stress-tested the safety net live. After that, daily use is sane.

---

## Two-layer permissions

Every connection has a **baseline policy** that cascades to all databases; per-database overrides take precedence. When a single SQL statement touches multiple databases, **the strictest action wins**.

```text
"Set baseline on acme-prod to read-only."
"Override staging policy: write=confirm."
"List database policies on acme-prod."
   → baseline: read-only
     overrides: staging → write=confirm
```

Strictness order: `deny > confirm > allow`.

| db1 policy | db2 policy | resolved |
|---|---|---|
| allow | confirm | confirm |
| allow | deny | deny |
| confirm | confirm | confirm |

Resolved decision recorded in audit log along with the contributing database.

## Audit log + pre-mutation backup

Every tool call writes one row to `~/.local/share/sequel-mcp/audit.sqlite`:

| Field | Notes |
|---|---|
| `ts`, `request_id`, `connection`, `databases`, `category`, `ast_type` | Identity |
| `sql_raw`, `sql_redacted` | Full + AST-redacted (literals → placeholders) |
| `decision`, `confirmed`, `outcome` | Policy + outcome |
| `affected_rows`, `duration_ms`, `error_msg` | Observability |
| `backup_id` | FK to backup row when applicable |
| `prev_hash`, `row_hash` | Optional SHA-256 chain |

Backups for these statement types:

| Statement | Backup |
|---|---|
| UPDATE | MySQL/MariaDB: `SELECT * FROM <table> WHERE <where> FOR UPDATE`; SQLite: pre-image `SELECT` inside `BEGIN IMMEDIATE` |
| DELETE | Same |
| Multi-table UPDATE/DELETE | One backup per mutated table |
| REPLACE | MySQL/MariaDB: `SELECT * FROM <table> WHERE id IN (<keys>) FOR UPDATE`; SQLite: same pre-image without `FOR UPDATE` |
| INSERT | Post-mutation hint: `{kind:'range', start, end}` (auto-inc) or `{kind:'explicit', values}` |
| TRUNCATE | MySQL/MariaDB: `SELECT *` (capped) + `SHOW CREATE TABLE` |
| DROP TABLE | Same combined |
| ALTER / RENAME | Schema-only where supported |

Caps: `maxBackupRows=10000`, `maxBackupBytes=50MB` per backup. Default behavior on overflow: **abort** the mutation (configurable).

Restore:

```text
"List backups for acme-prod."
"Show restore plan for backup 42, dry run."
"Restore backup 42."   → CONFIRM, executes
```

## Retention / cleanup

Defaults:

| Setting | Default |
|---|---|
| `retentionDaysByCategory.read` | 7 |
| `retentionDaysByCategory.write` | 30 |
| `retentionDaysByCategory.ddl` | 90 |
| `retentionDaysByCategory.admin` | 180 |
| `retentionDaysByCategory.txCtrl` | 7 |
| `backupDays` | 30 |
| `auditMaxMB` | 500 (hard cap) |
| `backupMaxMB` | 1000 (hard cap) |
| `autoCleanupHours` | 24 (lazy on boot) |
| `redactSqlInLog` | false |
| `tamperEvidentChain` | false |

```text
"Set retention: keep reads 3 days, writes 14 days."
   → set_retention({retentionDaysByCategory: {read: 3, write: 14}})

"Audit cleanup, dry run."
   → audit_cleanup({dryRun: true})
```

Auto-cleanup runs on server boot if last cleanup > `autoCleanupHours` ago.

Legacy `auditDays` from v0.2 is auto-migrated to uniform per-category on first read.

## Sequel Ace integrations (all optional)

If Sequel Ace is **not installed**, three things are unavailable; everything else works unchanged:

| Tool | If Sequel Ace missing |
|---|---|
| `import_from_sequel_ace` | "Favorites.plist not found" — use `add_connection` or `add_sqlite_connection` instead |
| `sequel_ace_history` | "queryHistory.db not found" — use `audit_search` instead |
| `history_search({source:'both'})` | Degrades silently to `source:'mcp'` (audit log only) |

If Sequel Ace IS installed, you get:

- **One-time bootstrap.** `import_from_sequel_ace` reads the Favorites.plist + macOS Keychain entries, copies them into our namespace. macOS prompts "Always Allow" once per favorite.
- **Cross-tool history search.** `history_search` merges Sequel Ace's `queryHistory.db` (deduplicated by query text) with our audit log into one timeline.

```text
"Show me my Sequel Ace history from the last 7 days containing 'users'."
   → sequel_ace_history({sinceIso, search: 'users'})
```

**Sequel Ace is never written to.** All our reads are read-only. `queryHistory.db` is opened with `readonly: true; fileMustExist: true`.

## Default connection / database

Set once, omit on every subsequent call:

```text
"Set the default connection to local."
"Set local's default database to app."
"Count rows in users."   → query({sql: 'SELECT COUNT(*) FROM users'}) — uses local/app
"On prod, count rows in audit."   → explicit override; default untouched
```

For SQLite, the `database` value is the schema name used for policy scope and metadata lookup, usually `main`.

## Defence in depth

1. **AST classification** via `node-sql-parser` — closed-world: unknown statement types are denied.
2. **Multi-statement input rejected** at parse time AND at driver (`multipleStatements: false`).
3. **Read-only driver enforcement** — MySQL/MariaDB reads use `START TRANSACTION READ ONLY`; SQLite reads open the database file with a read-only handle.
4. **Two-layer policy gate** — per-DB override + baseline cascade; strictest wins; fail-closed.
5. **Elicitation confirmation** — typed `CONFIRM` token, server-issued, uncircumventable.
6. **Pre-mutation backup** — same-transaction pre-image rows for UPDATE/DELETE; schema capture for DDL where supported; row + byte caps.
7. **Audit log** — append-only SQLite; optional SHA-256 chain.
8. **Row cap + statement timeout** — `MAX_EXECUTION_TIME` hint for MySQL/MariaDB reads; SQLite uses the configured busy timeout.
9. **Touch ID** — optional per-session unlock via macOS LocalAuthentication.
10. **SSH host key verification** *(0.5.0)* — opt-in `hostKeyPolicy='strict'` matches against `~/.ssh/known_hosts`; rejects unknown hosts and key mismatches. `@revoked` markers honored in all modes. Defends against MitM on the SSH leg of every tunnel.
11. **TLS server name preservation** *(0.5.0)* — opt-in `sslServerName` forwards original hostname into mysql2's TLS handshake. SNI + cert SAN verification target the real DB host, not the tunnel's `127.0.0.1`.
12. **Docker exec command allowlist** *(0.5.0)* — bridge command components (container name, host, port, tool) validated by zod regex AND inside `buildBridgeCommand`. No shell metacharacter can reach the SSH command line even if the schema layer is bypassed.

## Credentials — local-only by design

- MySQL/MariaDB passwords are stored via `@napi-rs/keyring` → macOS Keychain Services API.
- Default attributes: **non-syncable**, `WhenUnlockedThisDeviceOnly`. Not iCloud Keychain.
- Service name: `sequel-mcp : <connection-name>`. Account: DB user. Visible in `Keychain Access.app` so you can revoke any time.
- We **never** read Sequel Ace's keychain at runtime. The one-time `import_from_sequel_ace` shells out to `/usr/bin/security` — macOS prompts "Always Allow / Allow / Deny" — and we copy the result into our own service namespace.
- SQLite connections store only a local file path in `config.json`; no password is requested or stored.

## SSH tunnels

If a connection has SSH details (auto-imported from Sequel Ace, or set via `add_connection`), `executeStatement` opens an `ssh2` local-to-remote tunnel before connecting `mysql2`. SSH passwords/passphrases live in Keychain under `<conn-name>::ssh`.

Tilde paths (`~/.ssh/id_rsa`) auto-expanded.

### Host key verification (opt-in, 0.5.0)

Every SSH connect now logs the SHA-256 fingerprint of the remote host's key:

```
[sequel-mcp] SSH host bastion.example.com:22 fingerprint=SHA256:abc123…
```

Default policy is `lenient` (accept any key — preserves the pre-0.5.0 behavior so no one breaks on upgrade). Once you've captured the fingerprint and added it to `~/.ssh/known_hosts`, switch to strict:

```text
"Add a connection … ssh host key policy strict."
```

Strict mode:
- Rejects unknown hosts (no entry in known_hosts).
- Rejects key mismatches (MitM signal — fingerprint changed).
- Honors `*` wildcards, `[host]:port` brackets, hashed (`|1|salt|hash`) and `@cert-authority` entries.

`@revoked` markers are enforced **even in lenient mode** — if you've explicitly revoked a key, sequel-mcp refuses regardless of policy.

Custom known_hosts path supported via `sshKnownHostsPath` (e.g., a project-scoped file separate from your personal one).

### TLS to MySQL through a tunnel (opt-in, 0.5.0)

When `ssl: true` and a tunnel is open, mysql2 connects to `127.0.0.1` so a cert with SAN matching the original DB hostname will silently bypass or fail verification. Fix per connection by opting into:

```text
"Add a connection … ssl true, ssl server name db.prod.example.com."
```

This forwards the original hostname into mysql2's TLS handshake (SNI + cert SAN check). Opt-in to avoid breaking legacy users whose certs intentionally matched `127.0.0.1`.

## Database inside a Docker container

If the MySQL/MariaDB instance lives inside a Docker container on a remote server, pick the access pattern that matches your infra. Five options, listed simplest first.

### 1. Publish the container port to host loopback (recommended for standalone Docker)

In `docker-compose.yml` or `docker run`:

```yaml
services:
  mysql:
    image: mysql:8.4
    ports:
      - "127.0.0.1:3306:3306"   # host loopback only — not internet-exposed
```

Then add a normal SSH-tunnel connection — `host=127.0.0.1` is resolved on the server side after SSH.

```text
"Add a connection named prod-db, host 127.0.0.1, port 3306, user root, ssh host server.example.com, ssh user deploy, ssh key path ~/.ssh/id_ed25519."
```

No new flags. Existing tunnel handles it.

### 2. Tailscale subnet router / direct tailnet name

If your Docker host runs a Tailscale subnet router, the container's bridge IP becomes routable from your laptop over the tailnet. Set `host` to the container's tailnet name or bridge IP. No SSH needed.

### 3. AWS SSM Session Manager port forwarding (RDS / private VPC)

Open the SSM tunnel out-of-band:

```bash
aws ssm start-session \
  --target <ec2-jump-instance-id> \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters '{"host":["mydb.rds.amazonaws.com"],"portNumber":["3306"],"localPortNumber":["56789"]}'
```

Then add a sequel-mcp connection to `127.0.0.1:56789` with no SSH config.

### 4. Teleport database access

Run `tsh proxy db --tunnel <db-name>` and connect to the local port it prints. SSO + ephemeral certs handled by Teleport.

### 5. SSH + `docker exec` stdio bridge (closed containers)

Use this when the container has **no published port** and **no reachable bridge IP** from the SSH host. The MCP opens an SSH session to the server, then runs `docker exec -i <container> nc <host> <port>` to pipe MySQL bytes through the container's stdin/stdout.

**Container requirement:** must have one of `nc`, `socat`, or `ncat` installed. BusyBox `nc` ships in Alpine and `mariadb`/`mysql` official images by default.

**Add a connection:**

```text
"Add a connection named prod-mysql, host 127.0.0.1, port 3306, user root,
 ssh host server.example.com, ssh user deploy, ssh key path ~/.ssh/id_ed25519,
 ssh docker container mysql_prod, ssh docker bridge tool nc."
```

The MCP will:

1. Open SSH session (existing logic).
2. Run `docker inspect <container>` to verify it's running and capture image + start time.
3. Run `docker exec <container> sh -c 'command -v <tool>'` to verify the bridge tool exists.
4. For each MySQL connection, open a new `docker exec -i <container> <tool> <host> <port>` exec channel and pipe a local TCP socket through it. `mysql2` speaks raw MySQL binary protocol over that pipe — prepared statements, multi-result sets, etc., all work.

**Security model:**

- Container name, remote host, remote port, and bridge tool are validated by zod regex (alphanumeric + `._-` only). No shell metacharacters can reach the SSH command line.
- SSH user must already have Docker access on the server (`docker` group membership ≈ root-equivalent). Your existing SSH ACLs are the trust boundary.
- All bridge commands are logged to stderr (visible to the MCP host) for transparency.
- The `docker exec` process dies with stdin EOF — closing the local socket terminates the remote process; killing the MCP propagates SIGHUP through SSH to clean up.

**Performance note:** stdio bridging adds one extra hop vs raw `forwardOut`. For interactive queries it's negligible; for bulk imports prefer publishing the port (option 1).

**Limitations:**

- TLS hostname verification through any tunnel needs the new `sslServerName` opt-in (see *TLS to MySQL through a tunnel* above). Without it, mysql2 sees `127.0.0.1` and SAN-matches against that.
- Each query opens a fresh SSH + docker exec session (no pooling yet).
- Use this only against trusted images. A malicious container could refuse to connect or return crafted MySQL handshakes.

## Doctor / debugging

```bash
npm run doctor                     # text report
node dist/doctor.js --json         # machine-readable
sequel-mcp-doctor                  # if installed globally
```

Or as an MCP tool:

```text
"Run sequel-mcp doctor and show the report."
```

The report includes runtime versions, every configured connection (host/user/database for MySQL/MariaDB, file path/schema for SQLite, SSH key path when present), policy, `hasStoredPassword` boolean, retention config, Sequel Ace history availability. **No passwords or Keychain secrets.** Hostnames + DB usernames + SQLite paths + key paths ARE included — review before pasting publicly.

## Development

```bash
npm install
npm run typecheck
npm run lint
npm test                                  # 213 tests as of v0.9.3
npm run build
npm run build:touchid                     # macOS only — Swift LocalAuthentication helper
npm run security:scan                     # local secret regex scan
./scripts/install-pre-commit-hook.sh      # optional — secret scan on every commit
```

## Security policy

See [SECURITY.md](./SECURITY.md) for the threat model and [CONTRIBUTING.md](./CONTRIBUTING.md) for contributor rules around credentials and PII.

Quick summary: **no credential, no PII, no environment-specific identifier may ever enter this repository.** Test fixtures use the IETF-reserved `example.com` domain. A regex scanner (`scripts/check-secrets.sh`) runs locally and as an optional pre-commit hook. CI re-runs `gitleaks` on every push.

## Threat model (what's NOT protected)

See [SECURITY.md](./SECURITY.md) for the full list. Highlights:

- A logged-in attacker on your Mac with shell access can read process memory and grab the cached password during the 15-min idle window. Use `requireTouchID: true` to shorten the trust window.
- The MCP runs in your user context with no extra sandboxing. Keep your `mcpServers` list to vetted servers.
- We do not pin TLS certs. If `ssl: true` and your DB is on the open internet, configure your DB to require valid certs server-side.
- Restoring a backup taken before a schema migration may fail or coerce silently. Always run `restore_backup --dry-run` first.
- Foreign-key-heavy DELETE rollback is not topology-aware — restored INSERTs may violate FKs if dependent rows were also deleted.

## License

MIT — see [LICENSE](./LICENSE).
