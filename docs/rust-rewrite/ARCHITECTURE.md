# Architecture

One Cargo package `sequel-mcp` (version 0.10.0) with a reusable library and
two binaries. A workspace is not used: the compile boundary gain is small for
this size and a single package keeps `cargo install sequel-mcp --locked`
trivial.

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml          # pins the tested toolchain
src/
  lib.rs                     # public library root; re-exports services
  bin/
    sequel_mcp.rs            # CLI + MCP stdio server entry
    sequel_mcp_gui.rs        # native GUI entry
  app/                       # shared application services (single source of truth)
    runtime.rs               # tokio runtime, config watch, pool/tunnel registry
    paths.rs                 # XDG-aware path resolution (parity with legacy)
    doctor.rs                # sanitized diagnostics builder
  cli/                       # clap definitions + command dispatch → app services
    mod.rs
    connections.rs policy.rs sql.rs audit.rs backup.rs serve.rs gui.rs
  mcp/                       # MCP layer only: framing, registration, mapping
    mod.rs                   # rmcp server construction, capability negotiation
    tools/                   # 24 legacy tools + 4 table-policy tools
    prompts.rs resources.rs
    confirm.rs               # elicitation adapter → ApprovalSink
  policy/
    mod.rs
    model.rs                 # Policy, TableRule, presets, validation
    classifier.rs            # sqlparser-based classification + table refs
    resolver.rs              # two-layer strictest-wins resolution
    gate.rs                  # operation gate (plan → approval → revalidate)
  sql/
    mod.rs
    ast.rs                   # object extraction, alias/CTE resolution, redaction
    hints.rs                 # MAX_EXECUTION_TIME injection
    executor.rs              # dialect dispatch, streaming, caps, cancellation
    mysql.rs                 # mysql_async pool, TLS/SNI, numeric fidelity
    sqlite.rs                # rusqlite handles, interrupt-based timeout
    tunnel.rs                # russh direct-tcpip forward, session reuse
    docker.rs                # docker bridge channel (no shell)
    known_hosts.rs           # parse/match/verify (incl. hashed |1| entries)
  connections/
    mod.rs                   # connection registry service (upsert/remove/default)
  approval/
    mod.rs                   # ApprovalEngine: one-time digests, session grants
    digest.rs                # canonical operation digest (SHA-256)
    outcomes.rs              # approved/declined/cancelled/unavailable/expired/…
  audit/
    mod.rs db.rs logger.rs redactor.rs retention.rs chain.rs
  backup/
    mod.rs extractor.rs capture.rs restore.rs
  vault/
    mod.rs keychain.rs touchid.rs   # security-framework keychain; LAContext binding
  importer/
    mod.rs sequel_ace.rs            # Favorites.plist + queryHistory.db
  ipc/
    mod.rs protocol.rs server.rs client.rs   # approval IPC (UDS, 0700)
  config/
    mod.rs v1.rs v2.rs migrate.rs   # schema, atomic locked migration
  migration/
    mod.rs                           # legacy sequel-ace-mcp namespace migration
tests/
  fixtures/legacy/          # generated differential corpus (see PARITY.md)
  contract/ integration/ migration/ mcp/ security/ gui/
scripts/
  ci-local.sh
```

## Data flow (single execution authority)

Every SQL-bearing surface (MCP tool, CLI command, GUI action, restore) calls
the same pipeline in `app`/`policy`/`sql`:

```text
resolve connection → classify SQL → extract object set (read/mutated tables)
  → resolve two-layer policy (strictest wins, deny unresolved)
  → build immutable OperationPlan {digest, policy revision, backup plan}
  → require Touch ID if configured (fail closed)
  → request approval (MCP elicitation OR GUI IPC; both unavailable ⇒ unavailable)
  → revalidate policy + metadata + plan digest
  → consume approval atomically (one-time) or match session grant
  → execute (streaming, caps, timeout, cancellation)
  → commit → audit outcome (incl. approval linkage) → response mapping
```

The MCP layer never talks to drivers directly; the GUI never bypasses the
gate; the CLI never re-implements policy.

## Approval paths

`ApprovalSink` is a trait. Implementations:

1. `ElicitationSink` — rmcp elicitation (`form` mode, capability-checked,
   cancel/malformed ⇒ `unavailable`, never `declined`);
2. `IpcSink` — authenticated Unix-domain-socket round trip to the GUI
   (peer-UID check, capability token, request nonce, expiry, replay-proof
   one-time consumption);
3. `CompositeSink` — GUI-first when a live GUI session is registered,
   elicitation otherwise; both missing ⇒ `unavailable` (fail closed).

## Process model

- `sequel-mcp serve --stdio`: MCP server on stdin/stdout; logs → stderr.
- `sequel-mcp-gui`: opens the native window; discovers MCP sessions via the
  runtime registry directory; renders approvals, policy, audit, backups,
  doctor from library services (no second policy implementation).
- Runtime registry: `~/.local/share/sequel-mcp/runtime/` (0700) holds
  per-session sockets + metadata; crashes are recovered by PID-liveness
  checks and socket probing; no TCP, no HTTP, no cloud.

## Configuration

- v2 config at `~/.config/sequel-mcp/config.json` (revision field,
  compare-and-swap writes under an inter-process lock; atomic tmp+rename with
  fsync of file and parent).
- v1 → v2 migration maps `databasePolicies[db]` to wildcard table rules
  `db.*`; timestamped backup of v1 kept; SSH `hostKeyPolicy` unset → migrated
  as `lenient` with a warning flag (new connections default `strict`).
- Audit DB keeps its SQLite schema versioned (`meta.schema_version`) with
  transactional migrations and chain epochs written when retention deletes rows.

## Secrets

- Keychain (`security-framework`) under the legacy-compatible service names;
  this-device-only accessibility class; no plaintext fallback — unsupported
  platform ⇒ explicit `Unsupported` error, never a file store.
- Touch ID via `objc2-local-authentication` `LAContext` on a dedicated
  thread; required-but-unavailable ⇒ deny. Short cached user-presence window,
  visible and revocable.
