# Legacy capability parity matrix

Status vocabulary: **ported** (same behaviour, verified by fixture/test parity),
**improved** (intentional change, stronger security/UX — each justified below),
**wrapper** (deprecated legacy API kept as a compatibility shim over the new
model), **removed** (explicit justification required).

Generated fixtures live in `tests/fixtures/legacy/` (classifier.json — 160
cases, redactor.json, extractor.json, resolver.json, hints.json,
known-hosts.json, grants.json) and were produced by executing the legacy
TypeScript build at base SHA `8b35dea`.

## MCP tools

| Legacy tool | Status | Notes |
|---|---|---|
| `query` | ported | read-only; `expectReadOnly` rejection message preserved |
| `execute` | ported | full gate path |
| `describe_table` | ported | DESCRIBE / PRAGMA table_info synthesis identical |
| `list_databases` | ported | SHOW DATABASES / PRAGMA database_list |
| `list_connections` | ported | sanitized listing incl. hasStoredPassword |
| `add_connection` | ported | elicitation password capture → Keychain |
| `add_sqlite_connection` | ported | |
| `remove_connection` | ported | deletes keychain entries (mysql + ssh) |
| `set_default_connection` | ported | empty string clears |
| `get_default_connection` | ported | |
| `select_database` | ported | identifier-regex validation |
| `import_from_sequel_ace` | ported | plist + optional keychain copy |
| `set_policy` | ported | merge-onto-baseline semantics |
| `set_database_policy` | **wrapper** | operates on wildcard table rule `<database>.*` |
| `clear_database_policy` | **wrapper** | clears the `<database>.*` table rule |
| `list_database_policies` | **wrapper** | lists wildcard table rules as per-database overrides |
| `audit_search` | ported | filters + redacted SQL |
| `audit_cleanup` | ported | dryRun + per-category windows |
| `set_retention` | ported | merge semantics preserved |
| `history_search` | ported | unified mcp + sequel-ace timeline |
| `sequel_ace_history` | ported | stat + read queryHistory.db |
| `list_backups` | ported | |
| `restore_backup` | **improved** | dry-run default kept; execution re-planned through the central operation planner (policy + approval + tunnel + TLS + audit) instead of the legacy ad-hoc MySQL connection |
| `doctor` | ported | sanitized diagnostics; adds GUI/IPC availability |
| `setup-connection` (prompt) | ported | |
| `analyze-table` (prompt) | ported | |
| `sequel-mcp://connections` (resource) | ported | |

New first-class tools (additive, no legacy breakage): `set_table_policy`,
`clear_table_policy`, `list_table_policies`, `explain_policy`.

## Classifier behaviour

| Behaviour | Status | Notes |
|---|---|---|
| category buckets read/write/ddl/admin/txCtrl | ported | |
| multi-statement rejection (quote/paren aware) | ported | parser + driver boundary enforcement added |
| comment stripping, comment-only rejection | ported | |
| TX/admin/PRAGMA regex fast paths | ported | same trigger sets |
| read-only PRAGMA allowlist | ported | same 22 names |
| `PRAGMA x = v` / unknown → admin | ported | |
| `EXPLAIN` → read | **improved** | `EXPLAIN ANALYZE` executes its underlying statement → classified as the wrapped statement's category (legacy: parser error) |
| `SELECT … FOR UPDATE` / `LOCK IN SHARE MODE` → read | **improved** | locking reads are not ordinary reads: classified with a `locking_read` flag; policy treats them as requiring write-class authorization on the read tables (legacy: plain read) |
| `SELECT … INTO OUTFILE` → read | **improved** | denied: file-writing read (legacy: plain read) |
| `LOAD DATA [LOCAL] INFILE` → admin | **improved** | denied outright by default policy (legacy: admin-gated) |
| `CALL` → parse/unknown error | ported | unresolved side effects stay denied |
| `SET @x` → admin | ported | session-variable mutation stays gated |
| `INSERT … SELECT` | **improved** | authorizes write on target + read on source tables separately (legacy: only category check) |
| `CREATE TABLE … AS SELECT` | **improved** | DDL on target + read authorization on source |
| unknown AST node → deny | ported | |
| parser error → deny | ported | |

## Policy model

| Behaviour | Status | Notes |
|---|---|---|
| connection baseline (5 categories + limits) | ported | defaults preserved exactly |
| presets read-only/dev/admin | ported | preset name `dev` maps to new preset name `development` with legacy alias kept |
| strictest-wins across databases | ported | now applies per table object, not per database |
| per-database overrides | **wrapper** | migrated to wildcard table rules `<db>.*`; strictest-wins between exact and wildcard keeps exact precedence |
| — | **improved** | exact table rules (`db.table`) with elevation→confirm semantics; reads prompt-free unless `read=confirm` |
| session grants `(conn, db, category)` | **improved** | grants bound to exact approved table set + statement digest + expiry + revocation; broad legacy scope only via explicit opt-in |
| once grants single-use | ported | now digest-bound and atomic under concurrency |
| unavailable ≠ declined | ported | plus distinct cancelled/expired outcomes in audit |

## Execution

| Behaviour | Status | Notes |
|---|---|---|
| MySQL single connection per statement | **improved** | bounded per-connection pool with health checks and metadata invalidation |
| START TRANSACTION READ ONLY/READ WRITE, continue on failure | **improved** | failed READ ONLY start = hard failure for reads |
| MAX_EXECUTION_TIME hint injection | ported | |
| numeric fidelity (bigNumberStrings, decimalNumbers=false, dateStrings) | ported | lossless strings for BIGINT/DECIMAL/dates |
| multipleStatements=false | ported | plus parser-level rejection |
| TLS + sslServerName override | ported | |
| SQLite readonly handle for reads | ported | plus symlink/path containment checks |
| BEGIN IMMEDIATE for writes | ported | |
| busy_timeout = stmtTimeoutMs | ported | plus real cancellation via interrupt handle |
| rows sliced after full fetch | **improved** | streaming with early stop at row/byte caps (both drivers) |
| SSH tunnel per statement | **improved** | warm reusable tunnel session per connection |
| known-hosts lenient default | **improved** | new configs default strict; lenient only for migrated configs with warning |
| `@revoked` unconditional deny | ported | |
| hashed/wildcard/bracketed known_hosts | ported | (HMAC-SHA1 retained — OpenSSH format) |
| docker bridge via `sh -c 'command -v'` probe | **improved** | structured exec, no shell string |
| bridge tools nc/ncat/socat + regex validation | ported | |

## Backup / restore

| Behaviour | Status | Notes |
|---|---|---|
| pre-image SELECT (FOR UPDATE on MySQL) | ported | |
| schema/rows/combined/insert-hint kinds | ported | |
| multi-table update/delete per-target backups | ported | |
| REPLACE PK pre-select | ported | |
| insert hints (explicit PK / autoincrement range) | ported | |
| overflow abort/truncate | ported | |
| **backup capture failure → continue** | **improved** | mutation denied unless explicitly configured, planned and audited as unprotected (legacy: log-and-continue) |
| restore dry-run default | ported | |
| dialect-specific upsert syntax | ported | |
| restore ad-hoc MySQL connection | **improved** | routed through central planner + connection's tunnel/TLS (legacy: raw host connection) |

## Security posture

| Behaviour | Status | Notes |
|---|---|---|
| Touch ID unavailable → pass | **improved** | deny (legacy fail-open at `touchid.ts:98`) |
| runtime swiftc compilation | **improved** | removed; compiled-in LocalAuthentication binding |
| Keychain service naming | ported | `sequel-mcp : <name>` / `<name>::ssh` |
| config 0700/0600 atomic writes | ported | + lock, revision, fsync, timestamped backups (v1→v2 migration) |
| audit WAL + hash chain | ported | + chain epochs at retention boundaries |
| SQL redaction | ported | same token classes; redacted-by-default raw column |
| stdout protocol cleanliness | ported | logs to stderr only |
| elicitation form-mode capability check | ported | `capabilities.elicitation.form` sub-capability respected |

## CLI

| Legacy binary | Status | Notes |
|---|---|---|
| `sequel-mcp` (stdio server) | ported | `sequel-mcp serve --stdio`; bare invocation aliases serve |
| `sequel-mcp-doctor` | ported | `sequel-mcp doctor [--json]` |
| `sequel-mcp-migrate` | ported | `sequel-mcp migrate [--force] [--purge] [--json]` — sequel-ace-mcp legacy namespace migration retained; also performs v1→v2 config migration |

New subcommands: `gui`, `connections …`, `policy …`, `query`, `execute`,
`audit …`, `history search`, `backups …`, `completions`.
