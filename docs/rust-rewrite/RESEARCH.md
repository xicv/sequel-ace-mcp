# Research and decisions (verified against primary sources, 2026-08-21)

Full source lists are in the research working notes; every version below was
verified against crates.io / docs.rs / official specs on 2026-08-21.

## ADR-1: MCP SDK — `rmcp` 3.1.4

The official Rust SDK. Current published version **3.1.4** (2026-08-20)
implements the **2026-07-28** MCP specification (a breaking, stateless
rewrite: per-request `_meta` versioning, mandatory `server/discover`,
`InputRequiredResult`/`input_required` elicitation flow) **and remains
compatible with 2025-11-25 and earlier via dual-era serving** — including the
legacy `initialize` handshake that **Codex still sends by default at
`2025-06-18`** (verified in `codex-rs/rmcp-client/src/protocol_mode.rs`).

Features used: `server`, `macros`, `schemars`, `transport-io` (stdio),
`elicitation`. No HTTP transport — stdio only, per threat model (no listener,
no new attack surface). Consequences:

- elicitation `form` sub-capability must be checked before prompting
  (`capabilities.elicitation.form`); modern-era clients declare capabilities
  per-request instead;
- cancel = `notifications/cancelled` (no response sent for cancelled work);
- progress = `notifications/progress` with the client's `_meta.progressToken`;
- structuredContent: emit for every JSON result plus the equivalent text
  block (spec's backward-compat SHOULD);
- stdout must carry only protocol frames; logs go to stderr.

## ADR-2: SQL parsing — `sqlparser` 0.62.0 (pinned exactly)

Apache-2.0, active. Both `MySqlDialect` (also used for MariaDB) and
`SQLiteDialect`. 0.62 restructured `Statement` variants into newtype structs
(`Statement::Insert(Insert)` etc.), moved visitor traits into
`sqlparser::ast` (`Visitor`, `visit_relations`, …), `Query.locks` exposes
`FOR UPDATE` / `LOCK IN SHARE MODE` (`LockType::{Share, Update}`), and
multi-statement rejection is `parse_sql(...)?.len() == 1`. Every 0.x minor
is AST-breaking → pin `=0.62.0` and upgrade deliberately.

## ADR-3: MySQL/MariaDB driver — `mysql_async` 0.37.0

Chosen over `sqlx` 0.9 (MSRV 1.94; no TLS hostname override; no raw-bytes
value escape hatch). Decisive APIs:

- TLS: `OptsBuilder::ssl_opts(SslOpts)` with
  `with_danger_tls_hostname_override(Some(name))` for the legacy
  `sslServerName` feature (name is verified against the override, not the
  tunnel endpoint — same semantics as the TypeScript `servername` hack);
- pool: `Pool` + `PoolOpts::with_constraints(PoolConstraints::new(min, max))`
  (bounded per configured connection; pool is a cheap clone handle);
- fidelity: text-protocol values arrive as `Value::Bytes` (lossless DECIMAL /
  oversized BIGINT as raw strings) — we map to JSON strings for those;
- LOCAL INFILE: disabled by default (`NoHandler`) — kept off;
- streaming: `query_stream`/`exec_stream` with early drop at caps;
- statement timeout: `SET SESSION max_execution_time` (MySQL) /
  `max_statement_time` (MariaDB, seconds) + future-level timeout.

## ADR-4: SQLite — `rusqlite` 0.40.2 with own async wrapper

`tokio-rusqlite` 0.7 pins rusqlite ^0.37 → incompatible; a ~30-line
`spawn_blocking` + channel wrapper gives serialized per-connection access on
rusqlite 0.40.2. Used APIs: `open_with_flags` (+`SQLITE_OPEN_READ_ONLY` for
reads, no `CREATE`), `busy_timeout`, `get_interrupt_handle()` for
cancellation/timeout from the async side, `stmt.column_names()` before
execution, `Rows` early drop, `backup` feature for restore snapshots.
Extensions loading stays uncompiled.

## ADR-5: SSH — `russh` 0.62.7 (pin; 0.63 is beta)

Async-native; `client::Handler::check_server_key(&PublicKey)` is the host-key
gate (default rejects everything — good fail-closed base). We keep the legacy
known_hosts parser/matcher (plain, wildcard, `[host]:port`, hashed `|1|`
entries — HMAC-SHA1 is the OpenSSH format for hashed entries and is retained
deliberately; it is hostname matching, not secret protection) and wire it into
`check_server_key`. Tunnels: `channel_open_direct_tcpip` bridged to a local
UDS-less in-process listener; docker bridge via `Channel::exec` with
argv-structured commands (no `sh -c`).

## ADR-6: GUI — `egui`/`eframe` 0.36.x

Only mainstream pure-Rust toolkit shipping macOS accessibility today:
AccessKit is a mandatory dependency since 0.34 and enabled by default on
macOS (NSAccessibility → VoiceOver), with active a11y investment through
0.36 (screen-reader announcements, inspection protocol, egui_kittest for CI
role/name assertions). MIT/Apache-2.0 (no Slint-style licence entanglement),
no webview/JS, trivially `cargo install`-able, ~2.5–3 MB release binaries,
reactive repaint ⇒ negligible idle CPU; `Context::request_repaint` from
tokio tasks; `egui_extras::TableBuilder` for policy matrix/audit tables.
Known accepted gaps: no native menu bar (in-app menus), tab-order keyboard
navigation. egui 0.36 MSRV (1.95) forces `rust-version` ≥ 1.95 — the GUI
target raises the package MSRV accordingly (installed toolchain 1.97.1 used
for development).

Rejected: iced (no shipped AccessKit integration as of 2026-05), Slint
(licence incompatible with MIT distribution), gpui (deprioritized for
external use; GPL component layer; no a11y), masonry/xilem (experimental),
cacao (semi-dormant), raw objc2-AppKit (unbounded build cost).

## ADR-7: Keychain — `security-framework` 3.7.0 directly

`keyring` v4 cannot set accessibility/synchronizable attributes. We need
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (local-device-only,
non-synchronizing default), so the secret store is implemented directly on
`security_framework::item` (SecItem add/copy/update/delete) with the
legacy-compatible service/account naming (`sequel-mcp : <connection>` /
account `<user>`; SSH entries `<connection>::ssh`). No plaintext fallback on
any platform: unsupported store ⇒ explicit error.

## ADR-8: Touch ID — `objc2-local-authentication` 0.3.2

Raw bindings `LAContext::canEvaluatePolicy_error` /
`evaluatePolicy_localizedReason_reply` (block2 feature), wrapped in a safe
helper bridging to tokio via oneshot; `LAError` codes mapped to
unavailable/failed/cancelled/system-cancel. Policy
`kLAPolicyDeviceOwnerAuthenticationWithBiometrics`. Required-but-unavailable
⇒ deny (fail closed — replaces the legacy fail-open). Short visible cached
user-presence window (default 15 min, revocable).

## ADR-9: Config, locking, misc

- `fs4` 1.1.0 (`flock` semantics) for inter-process config/migration locks;
- `plist` 1.10.0 for Sequel Ace Favorites.plist (IndexMap-backed dictionary);
- `serde`/`serde_json`, `clap` 4 (derive), `tokio` 1 (full), `tracing` +
  `tracing-subscriber` (redacted by default; no SQL literals at normal
  levels), `uuid` v4.

## Codex configuration (verified keys)

```toml
[mcp_servers.sequel_mcp]
command = "sequel-mcp"
args = ["serve", "--stdio"]
startup_timeout_sec = 20
tool_timeout_sec = 120
```

`startup_timeout_sec` (default 10) and `tool_timeout_sec` (default 60) are
the current documented keys. Host-side `default_tools_approval_mode` consults
`readOnlyHint` — a UX layer only; our policy engine stays authoritative.

## Toolchain

Development and CI pin Rust **1.97.1** via `rust-toolchain.toml` (installed
on the build Mac; satisfies egui 0.36's MSRV 1.95). `rust-version` in
Cargo.toml is set to 1.95.

## Dependency risk register

1. sqlparser: exact pin `=0.62.0` (AST-breaking minors).
2. russh: pin 0.62.7; watch 0.63 stabilization.
3. mysql_async `with_danger_tls_hostname_override` name (0.37) — used only
   for the user-configured `sslServerName` override; certificate validation
   itself stays enabled.
4. rmcp server-side `elicit` gating on the `elicitation` feature — verified
   at compile time in Phase 4.
