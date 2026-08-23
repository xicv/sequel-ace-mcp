# sequel-mcp

[![CI](https://github.com/xicv/sequel-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/xicv/sequel-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A native-Rust Model Context Protocol server for **MySQL/MariaDB and SQLite** with policy-gated action sets, table-level rules, pre-mutation backups, an append-only audit log, macOS Keychain credential storage, optional Touch ID, and authenticated approval companions (CLI + native GUI). Designed so Claude Code, Codex CLI, or any MCP client can run real SQL safely enough to use every day.

> **0.10.0 is a full native-Rust rewrite** of the former TypeScript implementation (0.9.x). The Node/npm install path is gone; see [Migration from 0.9.x](#migration-from-09x-node). **Not yet published to crates.io** — install from source for now; the `cargo install sequel-mcp` path arrives with the first real publish.

> **Sequel Ace is OPTIONAL.** This is a fully standalone MCP. Sequel Ace integration is a *bootstrap convenience* (one-time import of saved MySQL/MariaDB favorites) and a *history augment*. Without Sequel Ace, everything else works — only `import_from_sequel_ace` and `sequel_ace_history` report "not found".

## Capabilities

Current release: **v0.10.0**. Full history: [CHANGELOG.md](./CHANGELOG.md).

- **Single static binary** — pure Rust (`sequel-mcp`), no Node runtime, no `dist/`, no npm.
- **Two-layer permissions** — connection baseline + table rules (exact `db.table` or wildcard `db.*`; exact beats wildcard; strictest-wins across everything a statement touches; fail-closed).
- **Elevation still confirms** — a table rule can relax what the baseline denied, but elevated categories always require per-statement confirmation.
- **28 tools** + 2 prompts + 1 no-secrets resource (`sequel-mcp://connections`).
- **Approvals, three ways** — MCP elicitation first; when the client cannot elicit, an authenticated same-user local IPC channel answers instead (`sequel-mcp approve` CLI or the native GUI window). Modern clients use server-side opaque `requestState` handles (MRTR) bound to the exact operation digest. Every path fails closed — nothing is ever auto-approved.
- **Pre-mutation backups** for UPDATE / DELETE / REPLACE / INSERT / TRUNCATE / DROP / ALTER, multi-table aware; `restore_backup` replays through the same policy gate (`dryRun=true` default).
- **Append-only audit log** (SQLite, optional SHA-256 chain) with per-category retention and boot-time auto-cleanup.
- **Three transports** — direct TCP (TLS, private CA via `sslCaPath`), SSH tunnels (russh; strict/lenient host-key policy, keepalives, tunnel-lease generation pool keys), and SSH + `docker exec` stdio bridge (`nc`/`ncat`/`socat`) for closed containers — works even under `AllowTcpForwarding no`.
- **macOS-native security** — Keychain (`WhenUnlockedThisDeviceOnly`, non-syncable), optional Touch ID per connection, fail-closed if unavailable.
- **Sequel Ace import + unified history** — one-time favorites/Keychain import; `history_search` merges Sequel Ace's query history with the audit log.

## Install

### Requirements

- macOS 12+ (Apple Silicon or Intel) for Keychain + Touch ID. Linux builds compile (CI check), but Keychain/Touch ID degrade to explicit errors — fail-closed, no plaintext fallback.
- Rust toolchain matching [`rust-toolchain.toml`](./rust-toolchain.toml) (1.97.1) — `rustup` picks it up automatically.

### From source (current path)

```bash
git clone https://github.com/xicv/sequel-mcp.git
cd sequel-mcp
cargo install --path . --locked
```

That builds and installs the `sequel-mcp` binary into `~/.cargo/bin` (make sure it's on your `PATH`). To update an existing install: `git pull && cargo install --path . --locked`, then restart your MCP client session.

### After the crates.io publish (future)

```bash
cargo install sequel-mcp --locked
```

This path does not work yet — 0.10.0 has not been published. It is verified publishable (`cargo publish --dry-run` is green); the real publish happens per the release checklist in [CONTRIBUTING.md](./CONTRIBUTING.md).

## Wire into an MCP client

`sequel-mcp serve` speaks MCP over stdio — the only transport; there is no `--stdio` flag to pass.

### Claude Code

```bash
claude mcp add --scope user sequel-mcp -- sequel-mcp serve
```

### Codex CLI

```bash
codex mcp add sequel-mcp -- sequel-mcp serve
```

Equivalent `~/.codex/config.toml` entry (also what this repo's project-scoped [`.codex/config.toml`](./.codex/config.toml) now contains):

```toml
[mcp_servers.sequel-mcp]
command = "sequel-mcp"
args = ["serve"]
startup_timeout_sec = 20
tool_timeout_sec = 120
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sequel-mcp": { "command": "sequel-mcp", "args": ["serve"] }
  }
}
```

### Any other MCP client

Point `command` at the `sequel-mcp` binary with args `["serve"]`.

## CLI reference

```text
sequel-mcp serve                    # MCP stdio server (the primary transport)
sequel-mcp doctor [--json]          # sanitized local-install diagnostics
sequel-mcp approve [--socket P] [--choice once|session|decline]
                                    # answer a pending confirmation over the
                                    # authenticated approval IPC socket
sequel-mcp gui [--socket P]         # native approvals companion window
```

`doctor` reports config path/version/revision, connection count, default connection — **no passwords**.

## How approvals resolve

When a statement's category is `confirm`:

1. **MCP elicitation** (preferred) — the client shows the statement and a three-choice prompt: *Allow once*, *Allow for session*, *Decline*. Session grants are per `(connection, database, category)` and die with the server process.
2. **Authenticated approval IPC** (fallback) — if the client cannot elicit, the server asks over a Unix socket restricted to the **same effective uid** (`runtime/approval.sock`). Answer it with `sequel-mcp approve` or leave the **GUI window** (`sequel-mcp gui`) open — it watches the socket, shows the statement, and turns your click into an id-bound reply. Replies are single-use and bound to the exact pending request; a 60-second deadline fails the ask closed (audited as unavailable, never declined, never approved).
3. **Modern `requestState` (MRTR)** — clients that support round-trip confirmations receive a server-side opaque handle bound to the operation digest; the approved statement replays only if the digest, connection, and policy revision all match.

If no channel can answer, the statement does not run — the audit log records an unavailable prompt with the reason.

## Action sets — the permission model

Each connection has a baseline policy; each category is `allow` | `confirm` | `deny`.

| Category | What it covers |
|----------|----------------|
| `read`   | `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, read-only SQLite `PRAGMA` |
| `write`  | `INSERT`, `UPDATE`, `DELETE`, `REPLACE` |
| `ddl`    | `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `RENAME` |
| `admin`  | `GRANT`, `REVOKE`, `SET GLOBAL`, `KILL`, `FLUSH`, `LOAD` |
| `txCtrl` | `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT` |

### Presets

| Preset | read | write | ddl | admin | rowCap | timeout | Touch ID |
|--------|------|-------|-----|-------|--------|---------|----------|
| `read-only` | allow | deny | deny | deny | 1000 | 10s | off |
| `development` | allow | confirm | confirm | deny | 5000 | 30s | off |
| `administration` | allow | confirm | confirm | confirm | 5000 | 60s | **on** |

### Table rules (layer two)

`set_table_policy` writes an exact (`database.table`) or wildcard (`database.*`) rule per connection. Resolution for every table a statement touches: exact rule → wildcard rule → baseline, **strictest action wins** across tables. A rule may elevate a denied category, but elevated statements always confirm. `explain_policy` previews the classification and per-table resolution of any statement without executing it.

```text
"Set baseline on acme-prod to read-only."
"Set table policy on acme-prod: staging.* write=confirm."
"Set table policy on acme-prod: staging.migrations ddl=confirm."
"Explain policy for: UPDATE staging.users SET email='x' WHERE id=1"
```

## Tools (28)

| Tool | What it does |
|------|--------------|
| `query` | Single read statement; MySQL reads under `START TRANSACTION READ ONLY`, SQLite via read-only handle. |
| `execute` | Single non-read statement; gated; backup captured automatically. |
| `explain_policy` | Classify a statement and show per-table resolution without executing. |
| `describe_table` | `DESCRIBE` (MySQL/MariaDB) / `PRAGMA table_info` (SQLite). |
| `list_databases` | `SHOW DATABASES` / `PRAGMA database_list`. |
| `list_connections` | Saved connections, no secrets; marks default + `hasStoredPassword`. |
| `add_connection` | Add/update a MySQL/MariaDB connection; password elicited separately → Keychain. |
| `add_sqlite_connection` | Add/update a SQLite file connection (no password). |
| `remove_connection` | Forget a connection + delete its Keychain entry. |
| `set_policy` | Change a connection's baseline. |
| `set_database_policy` / `clear_database_policy` / `list_database_policies` | Legacy per-database override view; stored as `db.*` table rules. |
| `set_table_policy` / `clear_table_policy` / `list_table_policies` | Layer-two exact/wildcard rules. |
| `set_default_connection` / `get_default_connection` | Default used when `connection` is omitted. |
| `select_database` | Per-connection default database. |
| `audit_search` | Query the local audit log. |
| `audit_cleanup` / `set_retention` | Prune past retention; configure windows/caps. |
| `list_backups` / `restore_backup` | Inspect and replay pre-mutation backups. |
| `history_search` | Unified timeline: audit log + Sequel Ace history. |
| `import_from_sequel_ace` | One-time favorites + Keychain import. Requires Sequel Ace. |
| `sequel_ace_history` | Read Sequel Ace's query history. Requires Sequel Ace. |
| `doctor` | Sanitized diagnostics. No passwords. |

Prompts: `setup-connection` (guided connection setup), `analyze-table` (read-only investigation). Resource: `sequel-mcp://connections` (JSON, no secrets).

## Adding connections

### SQLite

```text
"Add a SQLite connection 'local' at ~/Projects/app/dev.sqlite, read-only preset."
```

### MySQL/MariaDB

The guided path is `add_connection` — arguments carry everything except the password; the server elicits the password separately (it never appears in tool arguments or logs) and stores it in the macOS Keychain:

```text
"Add a connection named local, host 127.0.0.1, port 3306, user root, database app, read-only preset."
```

Optional `ssh_*` arguments build the tunnel in the same call (`ssh_host`, `ssh_port`, `ssh_user`, `ssh_key_path`, `ssh_docker_container` + `ssh_docker_bridge_tool`, `ssh_host_key_policy`, `ssh_known_hosts_path`); `ssl`, `ssl_server_name`, and `ssl_ca_path` control TLS. Declining or dismissing the password prompt cancels — nothing is saved.

Alternatives: `import_from_sequel_ace` (one-time favorites + Keychain import on macOS) or manual setup — add the connection to `~/.config/sequel-mcp/config.json` (v2) and store the password yourself:

1. Config entry (camelCase fields):

   ```json
   {
     "version": 2,
     "revision": 1,
     "connections": [{
       "driver": "mysql",
       "name": "local",
       "host": "127.0.0.1",
       "port": 3306,
       "user": "root",
       "database": "app",
       "ssl": false,
       "policy": { "read": "allow", "write": "confirm", "ddl": "confirm",
                    "admin": "deny", "txCtrl": "allow", "rowCap": 1000,
                    "stmtTimeoutMs": 10000, "requireTouchID": false,
                    "maxBackupRows": 10000, "maxBackupBytes": 52428800,
                    "onBackupOverflow": "abort" },
       "tablePolicies": {}
     }],
     "retention": {}
   }
   ```

2. Store the password in the macOS Keychain under the service name the server looks up — `sequel-mcp : <connection-name>`, account = DB user:

   ```bash
   security add-generic-password -s "sequel-mcp : local" -a root -w
   ```

3. SSH passwords/passphrases go under service `<connection-name>::ssh`, account = SSH user.

No credentials ever live in the config file.

## SSH tunnels and Docker bridge

A connection may carry `ssh: { host, port, user, authMethod: "key"|"password", privateKeyPath, hostKeyPolicy: "strict"|"lenient", knownHostsPath, docker: { container, bridgeTool } }`.

- **Direct tunnel** — local forward onto multiplexed SSH channels. `hostKeyPolicy: "strict"` rejects unknown and changed host keys (fail-closed MitM signal); `lenient` still enforces `@revoked` markers. TLS hostname preservation via `sslServerName`; private CAs via `sslCaPath`.
- **Docker bridge** — for containers with no published port: `docker: { container: "mysql_prod", bridgeTool: "nc" }` pipes MySQL over `docker exec -i … nc 127.0.0.1 3306` through SSH exec channels. Works under `AllowTcpForwarding no`. Ops prerequisites: the SSH user can run `docker`, and `nc`/`ncat`/`socat` exists inside the container.

## Security playbook (short form)

1. **Default to `read-only`** for production connections — writes are denied outright, not "confirm".
2. **Scope relaxations** to one table or database (`set_table_policy` / wildcard), prefer `confirm` over `allow`, revert afterwards.
3. **Review the audit log weekly** — `audit_search` filtered by `outcome=denied` shows what was blocked; skim confirmed writes.
4. **Restore drills** — always `restore_backup` with `dryRun=true` first; check schema-drift warnings.
5. **Touch ID** on the most sensitive connection (`requireTouchID` via `set_policy`); shrink `rowCap`/`stmtTimeoutMs` further if you want tighter caps.
6. **Docker-in-bastion setups** — strict host-key policy + `sslServerName` + read-only preset = every leg fails visibly rather than silently.

### Defence in depth

AST classification (closed-world, unknown denied) · multi-statement rejection · read-only driver enforcement · two-layer strictest-wins gate · server-issued confirmations (elicitation / same-uid IPC / MRTR) · same-transaction backups · append-only audit · row caps + wall-clock statement timeouts · Touch ID · SSH host-key verification · TLS server-name preservation · bridge argv validation (no shell metacharacters).

## Audit, backups, retention

- Audit DB: `~/.local/share/sequel-mcp/audit.sqlite` — one row per tool call: identity, redacted SQL, decision, outcome, duration, `backup_id`, optional hash chain.
- Backup caps: `maxBackupRows` 10000 / `maxBackupBytes` 50 MB, overflow **aborts** the mutation (configurable).
- Retention defaults: read 7d, write 30d, ddl 90d, admin 180d, txCtrl 7d; audit hard cap 500 MB; auto-cleanup on boot every 24 h.

## Migration from 0.9.x (Node)

- **Install**: replace the `node dist/index.js` wiring with the `sequel-mcp` binary (`cargo install --path . --locked`; see above). Update any `command = "node"` MCP config to `command = "sequel-mcp"`.
- **Config**: v1 configs migrate in place on first load — `databasePolicies` become `db.*` table rules; SSH host-key policy inherited unset is marked `hostKeyPolicyMigrated` and treated as lenient-with-warning.
- **Keychain**: unchanged service names (`sequel-mcp : <name>`, `<name>::ssh`) — existing stored passwords keep working.
- **Behavior**: confirmations now resolve elicitation-first with the approve CLI / GUI fallback and MRTR for modern clients; unavailable prompts are audited as errors, never as declines.

## Doctor / debugging

```bash
sequel-mcp doctor          # text report
sequel-mcp doctor --json   # machine-readable
```

Reports config path/version/revision, connection count, default connection. No secrets.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash scripts/ci-local.sh              # the full local gate incl. cargo package
bash scripts/test-db.sh both          # docker MySQL/MariaDB matrices
bash scripts/test-ssh.sh mariadb      # SSH transport matrix
bash scripts/check-secrets.sh         # local secret scan
```

CI (`.github/workflows/ci.yml`) runs fmt + clippy + check on macOS and Ubuntu, tests on macOS, plus secret scans. All actions are pinned to commit SHAs.

## Security policy

See [SECURITY.md](./SECURITY.md) for the threat model and [CONTRIBUTING.md](./CONTRIBUTING.md) for contributor rules around credentials and PII. Quick summary: **no credential, no PII, no environment-specific identifier may ever enter this repository.**

## License

MIT — see [LICENSE](./LICENSE).
