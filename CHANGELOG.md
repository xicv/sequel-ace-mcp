# Changelog

All notable changes to **sequel-mcp** are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2] — 2026-08-10

### Fixed

- **`elicit/confirm.ts` no longer reports an unanswered `accept` as a decline.** 0.9.1 fixed the `"cancel"` case but missed a second path to the same failure: the MCP SDK's `elicitInput()` only runs schema validation against the response `content` when `content` is truthy, so a client that resolves an elicitation with `{ action: 'accept', content: undefined }` (or an empty object) sails through unvalidated instead of throwing. `confirm.ts`'s fallback then defaulted any content without a recognizable `choice` to `'decline'` — fabricating the exact refusal-nobody-made bug 0.9.1 was written to eliminate, just from the `accept` branch instead of `cancel`. An `accept` with no usable `choice` now resolves to `{ choice: 'unavailable', reason }`, with the reason including the actual `content` received so a broken client integration is diagnosable rather than silently misreported as "declined". A real decline (`content.choice === 'decline'`, chosen from the radio) is unaffected.
- **`doctor`'s `elicitation.supported` and `confirm.ts`'s capability gate now check `capabilities.elicitation.form`, not just `capabilities.elicitation`.** Every confirm prompt this server sends uses the SDK's default `'form'` mode, which the SDK itself gates on `capabilities.elicitation.form` — but both call sites here only checked truthiness of the parent `elicitation` object. A client that declares `elicitation: {}` (support for some other mode, or an incomplete capability stub) passed both checks and was reported `supported: true` by `doctor`, then failed inside the SDK on the first real attempt. `confirm.ts` now fails closed to `unavailable` before ever calling `elicitInput()` in that case, and `doctor` reports the same `capabilities.elicitation.form` value it's actually gated on, so the two can no longer disagree.

### Tests

- New: `tests/confirm.test.ts` (12 cases) — direct coverage of `makeConfirmFn`, previously untested (`gate.test.ts` mocks `elicitConfirm` out entirely). Covers the capability gate (missing entirely, present without `.form`, throwing), `cancel` → `unavailable`, a real `decline`, all three valid `content.choice` values including an explicit `'decline'`, and the regression case (`accept` with missing/empty/invalid content → `unavailable`, not `'decline'`).
- **Total: 213** (was 193 at 0.9.1). All previous tests still pass — zero behavioral regression for existing call paths.

## [0.9.1] — 2026-08-09

### Fixed

- **`elicit/confirm.ts` no longer reports a dismissed prompt as a decline.** Per the MCP spec, `ElicitResult.action` is `"accept" | "decline" | "cancel"`, where `"cancel"` means the client dismissed the request *without* an explicit choice (no interactive surface to show it in, a timeout, a dialog closed unanswered) — distinct from `"decline"`, an explicit no. The code folded both into `decline`, so any client/session that could never deliver a real prompt (e.g. Claude Code launched with `--permission-mode bypassPermissions`) had every `confirm`-gated statement come back `"User declined confirmation"` — a refusal nobody made, on any server version, `elicitation.supported` notwithstanding. `"cancel"` now correctly resolves to `{ choice: 'unavailable', reason }`, which was already plumbed through `PolicyConfirmationUnavailableError` and reported honestly (this is the same downstream path 0.9.0's `outcome: error` reporting added) — the gap was purely in `confirm.ts` collapsing the distinction before it ever reached that code. Fixed at the protocol level, so it should behave correctly in any spec-compliant MCP client (Claude Code CLI and Claude.app both, not one over the other).

## [0.9.0] — 2026-06-09

### Changed

- **Per-database confirmation prompt** — the authorization prompt now shows the target database, not just the connection (e.g. `WRITE on AVCRM PROD · rpa_staging`), so multi-database connections make clear which database a statement will hit.
- **Session grants scoped per database in the prompt copy** — "Allow for session" now states it covers the specific database until restart, matching the existing per-`(connection, database, category)` grant key.

### Removed

- **"Allow always" inline choice** — the four-option prompt is now three (`Allow once` / `Allow for session` / `Decline`). Persisting a policy as `allow` is done explicitly via `set_database_policy`. This also removes a footgun where "Allow always" persisted `allow` to the connection baseline — silently widening write access to every database on the connection, including production — instead of the database actually being acted on.

## [0.8.0] — 2026-06-05

### Added

- **SQLite support** — added `driver: "sqlite"` connections, `add_sqlite_connection`, SQLite query/execute routing through `better-sqlite3`, SQLite metadata support for `list_databases`/`describe_table`, dialect-aware backup capture, and SQLite restore upsert planning.
- **Codex CLI setup** — README now includes `codex mcp add sequel-mcp -- npx -y sequel-mcp`, equivalent `~/.codex/config.toml`, and Codex skill installation via `~/.codex/skills` or user-level `[[skills.config]]`. The repo also ships `.codex/config.toml` for trusted project-scoped MCP setup.
- **Codex skill metadata** — `skills/using-sequel-mcp/agents/openai.yaml` adds OpenAI/Codex-facing display metadata while preserving the same `SKILL.md` used by Claude Code.

### Fixed

- **npm package now includes the companion Skill** — `package.json` `files` now includes `skills/`, so the shipped tarball matches the README/CHANGELOG claim that `skills/using-sequel-mcp` is bundled.

## [0.7.0] — 2026-05-20

### Added

- **Companion Claude Code Skill** — ships `skills/using-sequel-mcp/SKILL.md` + `references/{policy,recovery,connections}.md`, following the May-2026 Anthropic skill authoring guideline (gerund-form name, third-person ≤1024-char description, body ≤500 lines, refs one-level-deep). Teaches Claude when to pick `query` vs `execute`, how to surface the four-choice confirm grant scope, the recover-from-bad-mutation workflow, and where credentials/audit live.
- **Repo `CLAUDE.md`** — fast orientation for Claude Code sessions: module layout, run/verify commands, repo conventions (immutability, single-statement rule, fail-closed policy), runtime paths.
- **Tool results now emit `structuredContent`** — every `jsonResult`-returning tool (24 tools) returns both a legacy text block AND a `structuredContent` object per the latest MCP spec. Modern clients (Claude Code, Inspector) can render structured responses; older clients keep the text block unchanged. No tool argument or behavior change.

### Changed

- **`src/server.ts` split into `src/server/` modules** — the 1180-line monolith is now a 61-line orchestrator. Tool registrations live under `src/server/tools/{sql,connections,policy,audit,backup,doctor}.ts`. Shared helpers in `src/server/shared.ts`. Prompts and resources in their own files. Public API (`buildServer`) unchanged; no impact on consumers.
- **Lazy Touch ID resolution** — replaced the `Object.assign(auth, …)` mutation + boot-window race with `createLazyAuth(provider)`. The TouchID prompt is resolved exactly once on the first `ensureAuthenticated` call. Provider is now injectable for tests.
- **Audit-log writes wrapped in a single `BEGIN IMMEDIATE` transaction** — the previous `SELECT row_hash ORDER BY id DESC LIMIT 1` then `INSERT` sequence was not atomic; concurrent writers (or any future multi-writer scenario) could break the SHA-256 hash chain. The tail-read and insert now share one immediate transaction, so each `prev_hash` deterministically equals the previous row's `row_hash`.
- **`list_connections` keychain lookup parallelized** — replaced the serial `for…await` over `secretStore.hasPassword(...)` with `Promise.all(map(...))`. N connections now resolve in 1× keychain RTT instead of N×.

### Fixed

- **`restore_backup` no longer ignores user decline** — the confirm path previously checked `if (!ok)` where `ok` was a `GrantChoice` string (`'once' | 'session' | 'always' | 'decline'`), all truthy. Declining a restore did nothing and the replay proceeded. Now correctly aborts when the choice is `'decline'`.
- **Graceful shutdown** — `src/index.ts` registers `SIGINT`/`SIGTERM`/`beforeExit` hooks that WAL-checkpoint + close `better-sqlite3` so a kill mid-write does not leave WAL pages unmerged.
- **Dead code** — removed an unused `inSingle` local + `void inSingle` in `policy/classifier.ts` left from a prior refactor.
- **`executor.ts` ssl type** — drop the `as unknown as ConnectionOptions['ssl']` cast in favor of a typed assertion with an inline justification comment.

### Tests

- New: `tests/shared.test.ts` (10) — covers `jsonResult` structuredContent emission, scalar/array/null wrapping, `toolError` / `textResult` / `noConnectionMessage` semantics, and `createLazyAuth` provider-injection invariants (single resolution under 3-way concurrency, prompt failure propagates).
- Updated: `tests/audit-logger.test.ts` — now verifies the SHA-256 chain itself (row N's `prev_hash` must equal row N-1's `row_hash`) plus a 20-row rapid-write test that proves the immediate-transaction wrapping holds the chain.
- **Total: 193** (was 181 at 0.6.0). All previous tests still pass — zero behavioral regression for existing call paths.

### Notes

- No breaking API changes. `npx -y sequel-mcp` users pick up 0.7.0 on the next session start.
- No SDK upgrade. `@modelcontextprotocol/sdk@1.29.0` (released 2026-03-30) remains the latest published version on npm.

## [0.6.0] — 2026-05-19

### Added

- **Session-scoped confirm grants** — the elicit prompt fired by `confirm` actions is no longer a free-text `CONFIRM` field. The client now surfaces a four-choice radio: **Allow once** (this statement only), **Allow for session** (skip prompts for the same `(connection, database, category)` until the MCP server process exits), **Allow always** (persists `policy[category] = 'allow'` via the same writer `set_policy` uses), and **Decline**. Session grants live in an in-memory `GrantStore` (`src/policy/grants.ts`), are scoped per `(connection, database, category)`, and never touch disk — restarts re-arm the gate. Touch ID, the multi-DB strictest-wins resolver, and `deny` short-circuits are all unchanged: a session grant never bypasses Touch ID, and a grant on `staging` does not cover `prod`.

### Changed

- `evaluatePolicy` (`src/policy/gate.ts`) gained `grants`, `grantDatabase`, and `onAlwaysGrant` parameters; signature is backward-compatible for direct callers that only supply the original four args, since the new fields are optional.
- `makeConfirmFn` (`src/elicit/confirm.ts`) now returns `'once' | 'session' | 'always' | 'decline'` instead of `boolean`. Non-accept responses and unknown values map to `'decline'` so missing/old clients fall back to the safest path.
- Audit log shape unchanged for this release. Statements that pass via a session grant still log as `decision: 'confirm', confirmed: true` — recording grant origin in the audit row is deferred to a future minor release behind an additive column.

### Tests

- New: `tests/grants.test.ts` (7) — store consume/grantOnce/grantSession semantics, scope isolation across (conn, db, category), `clear` with and without filter, snapshot output.
- Updated: `tests/gate.test.ts` — existing four cases migrated to the new `GrantChoice` return type, plus four new cases covering (a) session-grant skip, (b) `'session'` choice registering a grant for subsequent statements, (c) `'always'` invoking `onAlwaysGrant` exactly once with the right category, (d) cross-database scope isolation.
- **Total: 181** (was 169 at 0.5.0, unchanged at 0.5.1). All previous tests still pass — zero behavioral regression for any code path where the user picks `Allow once`, which is the literal old `CONFIRM`-on-each-call behavior.

### Notes

- Local MCP clients that read `npx -y sequel-mcp` will pick up the new prompt automatically on the next session start (npx cache resolves to latest unless pinned). Existing connections, saved policies, and Keychain entries are untouched — purely additive.

## [0.5.1] — 2026-05-07

### Changed

- README republished with the 0.5.0 feature surface fully documented: three new Capabilities bullets, SSH tunnels section gains opt-in subsections for host key verification + TLS server name, Defence-in-depth list extended with three new numbered layers (SSH known_hosts strict, TLS servername preservation, docker-exec command allowlist), Security playbook adds three real-use scenarios (production Docker bastion end-to-end, lenient→strict host-key migration, TLS to MySQL when cert was issued for the real DB hostname).
- Test count line bumped from 87 (v0.4.0) to 169 (v0.5.0).

### Note

No code change. Docs-only republish so `npm view sequel-mcp readme` matches the GitHub copy.

## [0.5.0] — 2026-05-07

### Added

- **Database access through Docker container on a remote server** — when a MySQL/MariaDB instance lives inside a Docker container with no published port, `add_connection` now accepts `sshDockerContainer` + `sshDockerBridgeTool` (`nc` | `socat` | `ncat`). Each query opens an SSH session to the host, runs `docker inspect` to confirm the container is running, verifies the bridge tool is present, then pipes a local TCP socket through `docker exec -i <container> <tool> <host> <port>`. `mysql2` continues to speak raw MySQL binary protocol over the pipe — prepared statements, multi-result sets, and policy gates all unchanged. New `src/sql/dockerTunnel.ts` is fully separate from the existing port-forward `tunnel.ts`; legacy SSH connections are unaffected.
- **SSH host key verification (opt-in)** — new optional `sshHostKeyPolicy: 'lenient' | 'strict'` and `sshKnownHostsPath` fields on the `ssh` config block. Default = `lenient` (current accept-any behavior preserved). When set to `strict`, the SHA-256 fingerprint must match an entry in `~/.ssh/known_hosts` (or the user-supplied path); plain, hashed (`|1|salt|hash`), `*` wildcard, `[host]:port`, `@cert-authority`, and `@revoked` markers are all parsed. Fingerprint is logged to stderr on every connect regardless of policy so users can capture it before opting in. `@revoked` markers are honoured even in lenient mode — if the user explicitly revoked a key, we never accept it.
- **TLS server name preservation through SSH tunnel (opt-in)** — new optional `sslServerName` field on the connection. When `ssl: true` and the connection is tunneled, mysql2 normally talks to `127.0.0.1` and a cert with SAN matching the original hostname will fail verification (or worse, be silently bypassed depending on the mysql2 default). Setting `sslServerName: "db.prod.example.com"` forwards that name into the TLS handshake's SNI/verification. Opt-in to avoid breaking legacy users with cert/host setups that rely on the old behavior.

### Security

- New module `src/sql/sshHostKey.ts` (pure functions, 21 unit tests): `parseKnownHosts`, `matchHost`, `fingerprintSha256`, `keyMatchesEntry` (timing-safe), `verifyHostKey`, `loadKnownHosts`, `buildHostVerifier`. Handles plain, hashed, wildcard, and bracketed-port entries.
- Docker tunnel command construction is allowlist-validated — container/host names match strict regex (`^[A-Za-z0-9][A-Za-z0-9_.-]*$`, `^[A-Za-z0-9.\-]+$`), bridge tool is an enum, port is integer 1–65535. Validation runs both at zod parse time AND inside `buildBridgeCommand`, so no shell metacharacters can reach the SSH command line even if the schema layer is bypassed.

### Notes

- Existing `tunnel.ts` SSH path now also logs the SHA-256 fingerprint as an informational stderr line, so users can copy it into their `known_hosts` and switch to `strict` mode at their leisure. No behavioral change for connections without `hostKeyPolicy` set.
- Docker bridge tier requires `nc`, `socat`, or `ncat` inside the container. BusyBox `nc` ships in Alpine and the official `mysql`/`mariadb` images by default; check your custom images otherwise.

### Tests

- New: `tests/dockerTunnel.test.ts` (36) — command builder allowlist, schema validation, end-to-end Connection round-trip, backward-compat for legacy SSH configs.
- New: `tests/sshHostKey.test.ts` (21) — known_hosts parsing, host pattern matching (exact, wildcard, bracket-port, hashed), fingerprint, key match, full verifier outcomes (matched / mismatch / unknown / revoked).
- New: `tests/sshHostKeyVerifier.test.ts` (13) — `buildHostVerifier` behavior under `lenient` and `strict`, `@revoked` enforcement in both modes, `SshTunnelSchema` backward-compat assertions.
- New: `tests/executor.test.ts` (12) — `buildBaseOptions` TLS shape under all four `ssl` × `sslServerName` permutations, plus invariant guarantees (`multipleStatements: false`, `decimalNumbers: false`, `connectTimeout: 15000`, etc.) that existing users rely on.
- **Total: 169** (was 87). All previous tests still pass — zero behavioral regression for legacy connections.

## [0.4.1] — 2026-05-06

### Changed

- README + CHANGELOG: replaced environment-specific placeholders (`AVCRM PROD` → `acme-prod`, `rpa_staging` → `staging`).
- Repo history rewritten via `git filter-repo` to scrub the old names from every commit. Tags re-pointed; force-pushed to `main`.
- Older npm versions (`<0.4.1`) deprecated; please upgrade.

### Note

No code change. This is a docs-and-history-only release.

## [0.4.0] — 2026-05-06

### Added

- **Multi-table UPDATE/DELETE backup.** `UPDATE a JOIN b ON … SET a.x = 1, b.y = 2 WHERE …` now produces one `backup` row per mutated table (detected from the `SET` clause). `DELETE a, b FROM a JOIN b …` produces one backup per deleted target. Each backup gets its own `backup_id`; `restore_backup` replays each independently.
- **REPLACE PK rollback.** `REPLACE INTO t (id, …) VALUES (…)` triggers a pre-mutation `SELECT * FROM t WHERE id IN (…) FOR UPDATE` against pre-existing rows. Restorable via `INSERT … ON DUPLICATE KEY UPDATE`. Identifies PK column by name (`id` / `uuid` / `pk`).
- **INSERT auto-rollback hint** (`backup_kind = 'insert-hint'`). Captured *after* execution; no pre-mutation cost. For auto-increment tables, stores `{kind: 'range', column: 'id', start, end}` from `mysql.insertId` + `affectedRows`. For explicit-PK INSERTs, stores `{kind: 'explicit', columns, values}`. Restore generates `DELETE FROM t WHERE id BETWEEN start AND end` or `DELETE FROM t WHERE (cols) IN ((…), …)`.
- **`history_search` tool.** Unified timeline merging the local audit log with Sequel Ace's `queryHistory.db` (when present). Sorted by `ts` DESC; each row carries `source: 'mcp' | 'sequel-ace'`. Filter via `source=mcp` / `source=sequel-ace` / `source=both` (default).

### Changed

- `isBackupRequired()` now returns `true` for `replace` and `insert` (was `false` in 0.2/0.3).
- README restructured around real-world workflows + a Security Playbook section.

### Tests

- Extractor: 27 (was 19) — multi-table UPDATE/DELETE, REPLACE, INSERT hint cases.
- History merge: 3 new tests.
- **Total: 87** (was 76).

## [0.3.0] — 2026-05-06

### Added

- **Per-category audit retention.** New `RetentionConfig.retentionDaysByCategory: { read, write, ddl, admin, txCtrl }`. Defaults: `read=7`, `write=30`, `ddl=90`, `admin=180`, `txCtrl=7`. Cleanup runs `DELETE … WHERE category = ?` per category with its own cutoff.
- **`sequel_ace_history` tool.** Reads Sequel Ace's `queryHistory.db` in `better-sqlite3` read-only mode. Filters: `sinceIso`, `search` (`LIKE %text%`), `limit` (default 200, max 5000). Read-only — no lock or modification of Sequel Ace's file.
- `doctor` tool now reports `sequelAceHistory: { available, path, entryCount, sizeBytes }` and the resolved `retention` block.

### Changed

- `set_retention` now accepts `retentionDaysByCategory` partial map (deep-merged over current).
- Legacy `auditDays: number` from 0.2 configs auto-migrated uniformly to all five categories on first read (via `z.preprocess`). Non-breaking.

### Tests

- Retention: 7 (was 5) — per-category cleanup + legacy migration.
- Sequel Ace history reader: 7 new tests.
- **Total: 76** (was 67).

## [0.2.0] — 2026-05-06

### Added

- **Two-layer permission system.** `Connection.databasePolicies?: Record<string, Partial<Policy>>` — per-database overrides cascade off the connection baseline. Multi-DB statements take the **strictest** action (`deny > confirm > allow`) — fail closed (Apache Ranger semantics).
  - New tools: `set_database_policy`, `clear_database_policy`, `list_database_policies`.
  - Classifier extracts `targetDatabases` from AST `tableList`.
- **Audit log** (`better-sqlite3` at `~/.local/share/sequel-mcp/audit.sqlite`). Every tool call writes one row: request UUID, target databases, category, AST type, raw + redacted SQL, decision, confirmed bool, outcome (`success`/`error`/`denied`/`declined`), `affected_rows`, `duration_ms`, `error_msg`, `backup_id`. Optional SHA-256 prev-hash chain (off by default).
  - AST-walk literal redaction stores `sql_redacted` with literals replaced by placeholders (`<str>`, `0`, `false`).
  - Raw SQL kept by default for local debugging; opt-in `redactSqlInLog` flag drops it.
  - New tools: `audit_search`, `audit_cleanup`.
- **Pre-mutation backup.** Every UPDATE/DELETE runs `SELECT … FOR UPDATE` for row backup; TRUNCATE/DROP/ALTER/RENAME run `SHOW CREATE TABLE`; combined kinds for TRUNCATE/DROP capture both.
  - Caps: `maxBackupRows=10000`, `maxBackupBytes=50MB`. Default abort on overflow (configurable per connection via `Policy.onBackupOverflow`).
  - New tools: `list_backups`, `restore_backup` (default `dryRun=true`; goes through the same policy gate; `INSERT … ON DUPLICATE KEY UPDATE`).
  - **Multi-table UPDATE/DELETE** explicitly rejected for 0.2 (will cause statement to be denied with a clear reason). Landed in 0.4.
- **Retention / cleanup.** `RetentionConfig`: `auditDays=90`, `backupDays=30`, `auditMaxMB=500`, `backupMaxMB=1000`, `autoCleanupHours=24`. `maybeAutoCleanup` runs lazily on server boot if last cleanup > N hours.
  - New tools: `set_retention`. `audit_cleanup` doubles as manual purge.
  - VACUUM after each cleanup; soft cap triggers extra 20% trim.
- New deps: `better-sqlite3@^12`, `drizzle-orm`/`drizzle-kit`, `uuid`.

### Changed

- Stderr breadcrumb log gains backup-capture progress: `[sequel-mcp] acme-prod/write capturing backup … backup #42: 47 rows, 8200B`.

### Tests

- Resolver: 6 new tests.
- Audit logger: 3 new tests.
- Extractor: 19 new tests.
- Retention: 5 new tests.
- **Total: 67** (was 34).

### Known limitations (later addressed in 0.4)

- Multi-table UPDATE/DELETE not yet supported.
- REPLACE not auto-backed up (PK-level rollback not yet implemented).
- INSERT auto-rollback hint not yet implemented.

## [0.1.1] — 2026-05-06

### Changed (BREAKING)

- **Renamed package: `sequel-ace-mcp` → `sequel-mcp`.** The project is a fully standalone MySQL/MariaDB MCP — Sequel Ace integration is a one-time importer, not core. The old name was misleading. The old npm package is deprecated and points to the new name; the GitHub repo at `xicv/sequel-ace-mcp` redirects to `xicv/sequel-mcp`.
  - App name → `sequel-mcp`
  - Keychain service prefix → `sequel-mcp : <name>`
  - Resource URI → `sequel-mcp://connections`
  - Stderr breadcrumb prefix → `[sequel-mcp]`
  - Bin entries → `sequel-mcp`, `sequel-mcp-doctor`, `sequel-mcp-migrate`
- **`sequel-mcp-migrate` tool.** Copies `~/.config/sequel-ace-mcp/config.json` → `~/.config/sequel-mcp/config.json` and re-keys macOS Keychain entries from service `sequel-ace-mcp : <name>` to `sequel-mcp : <name>`. Non-destructive by default; `--purge` to remove legacy; `--force` to overwrite; `--json` for machine output.

### Added

- **Default connection state.** New tools: `set_default_connection`, `get_default_connection`. Tools that took a `connection` arg now treat it as optional; if omitted, the resolver falls back to the configured default.
- **`select_database` tool.** Set a connection's default database without re-entering the password.
- README + Migration section.

## [0.1.0] — 2026-05-06

### Initial release

MCP server that lets Claude run MySQL/MariaDB queries via Sequel Ace's saved connections, with policy-gated read/write/DDL action sets and macOS Keychain credential storage.

#### Highlights

- **AST-based SQL classification** via `node-sql-parser` + admin-keyword regex fallback. Closed-world: unknown statement types are denied.
- **Per-connection policy** (`allow | confirm | deny`) per category: `read`, `write`, `ddl`, `admin`, `txCtrl`.
- **Elicitation-driven CONFIRM token** for gated statements — server-issued, uncircumventable.
- **Multi-statement input rejected** at parse time + driver-level (`multipleStatements: false`).
- **Server-side `START TRANSACTION READ ONLY`** for read-category statements.
- **Sequel Ace bootstrap importer** for `Favorites.plist` + legacy keychain entries.
- **macOS Keychain** via `@napi-rs/keyring`. Non-syncable, `WhenUnlockedThisDeviceOnly`.
- **Optional Touch ID** gate via Swift `LocalAuthentication` helper.
- **SSH tunnel support** via `ssh2` with tilde-expanded key paths.
- **`doctor` tool + CLI** for sanitized diagnostics.
- **13 tools / 2 prompts / 1 resource / 34 unit tests.**

#### Hardened repository

- `.gitignore` covers `node_modules`, `dist`, `fixtures`, all `.env` / key / secret patterns
- `.npmignore` strips source / tests / scripts from the published package
- LICENSE (MIT)
- SECURITY.md with full threat model
- CONTRIBUTING.md with credentials-and-PII rules
- `scripts/check-secrets.sh` local regex scanner + optional pre-commit hook

[0.4.1]: https://github.com/xicv/sequel-mcp/releases/tag/v0.4.1
[0.4.0]: https://github.com/xicv/sequel-mcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/xicv/sequel-mcp/releases/tag/v0.3.0
[0.2.0]: https://github.com/xicv/sequel-mcp/releases/tag/v0.2.0
[0.1.1]: https://github.com/xicv/sequel-mcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/xicv/sequel-mcp/releases/tag/v0.1.0
