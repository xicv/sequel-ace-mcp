# sequel-mcp — Claude orientation

This file gives Claude Code (and any Claude Agent) a fast orientation when working in this repo. It does **not** replace `README.md` (user-facing) or `CONTRIBUTING.md` (contributor-facing).

## What this is

A native-Rust MCP (Model Context Protocol) server — the `sequel-mcp` binary — that lets Claude run MySQL/MariaDB/SQLite SQL behind a **policy gate** with **pre-mutation backups**, an **append-only audit log**, **macOS-native credential storage**, and **authenticated approval companions** (CLI + egui GUI). 0.10.0 is a full rewrite of the former TypeScript implementation; the Node/npm path is gone.

It is **not** a Claude Code Skill. A companion Skill is bundled under `skills/using-sequel-mcp/`.

## Layout

```
src/
├── bin/sequel_mcp.rs       # CLI: serve | doctor | approve | gui
├── lib.rs                  # library root (one implementation of everything)
├── app/                    # paths, config gate wiring, test-mode isolation
├── approval/               # grant engine, digest-bound approvals, IPC hub
├── audit/                  # SQLite audit DB, redactor, retention, history
├── backup/                 # capture, extractor (multi-table), restore
├── config/                 # v1→v2 migration, ConfigStore
├── gui/                    # egui approvals window (companion + reducer + long-poll client)
├── importer/               # Sequel Ace plist + queryHistory
├── mcp/                    # rmcp server: 27 tools, prompts, resource, MRTR, limits
├── policy/                 # classifier (sqlparser), resolver, model
├── sql/                    # mysql (mysql_async), sqlite (rusqlite), ssh (russh), docker bridge, pool
└── vault/                  # keychain (SecItem), touchid, paths
scripts/
├── ci-local.sh             # full local gate (check/test/clippy/fmt/doc/package/publish-dry-run/gitleaks)
├── test-db.sh              # docker MySQL/MariaDB matrices (isolated)
├── test-ssh.sh             # SSH transport matrix against a digest-pinned bastion
├── test-mcp-lifecycle.sh   # process-level MCP lifecycle tests
├── bench-mcp.sh            # benchmarks (PROFILE=release for packaging-grade numbers)
├── check-secrets.sh        # secret scan (incl. user-home paths)
└── lib/isolated-test-env.sh # shared fail-closed test isolation (SEQUEL_MCP_TEST_MODE)
skills/using-sequel-mcp/    # MCP-user-facing Skill (SKILL.md + references/)
tests/                      # lifecycle (real binary), mysql matrices, SSH, bench
docs/rust-rewrite/VERIFICATION.md  # session-by-session verification history
```

## Run / verify

```bash
cargo build                          # debug binary at target/debug/sequel-mcp
cargo test --workspace --locked      # 161 lib + 16 lifecycle + matrix groups
cargo clippy --workspace --all-targets --locked -- -D warnings
bash scripts/ci-local.sh             # everything incl. cargo package
```

E2E with a live MCP client: `sequel-mcp serve` (stdio; stdout belongs to the protocol, logs go to stderr).

## Conventions in this repo

- **Single MCP transport**: stdio. No HTTP server in scope.
- **Single SQL statement per call.** Structural, not advisory.
- **Fail-closed policy**: unknown statement types and parser errors both reject; unavailable approvals reject; timeouts are wall-clock deadlines.
- **One implementation**: policy, approval, and execution semantics exist once in the crate; the CLI, server, and GUI all reuse them.
- **No stdout writes outside the protocol** — `eprintln!`/`tracing` to stderr only.
- **Tests never touch real user state**: everything spawned runs under the fail-closed isolated test env; secrets come from `SEQUEL_MCP_TEST_SECRETS`, never the real Keychain.
- **No process spawns in test code** — integration phases are orchestrated by the bash scripts.

## Where things live at runtime

| Item | Path |
|------|------|
| User config | `~/.config/sequel-mcp/config.json` (`0o600`) |
| Audit + backup DB | `~/.local/share/sequel-mcp/audit.sqlite` (WAL) |
| Approval IPC socket | XDG runtime dir `sequel-mcp/runtime/approval.sock` (`0600`) + `runtime/sessions/<pid>.json` |
| Keychain service prefix | `sequel-mcp : <connection-name>` (SSH: `<connection-name>::ssh`) |

## Common tasks

- **Add a tool**: `#[tool(name = …)]` in `src/mcp/tools.rs` with honest `annotations`. Gated writes go through the shared approval path.
- **Change policy semantics**: `src/policy/` (classifier/resolver/model) + tests; update `explain_policy` expectations.
- **Touch the audit schema**: additive `CREATE TABLE IF NOT EXISTS` + migration; never destructive ALTERs against existing user data.
- **Benchmarks**: `bash scripts/bench-mcp.sh` (debug) / `PROFILE=release bash scripts/bench-mcp.sh` (packaging-grade).

## Things to avoid

- Do **not** add a second MCP transport without RFC.
- Do **not** weaken policy defaults (`write=confirm`, `ddl=deny`, `admin=deny` for new presets).
- Do **not** persist passwords outside Keychain.
- Do **not** add network telemetry. The project is local-first by design.
- Do **not** `--no-verify` past the secret scanner, and do not bypass CI gates.
- Do **not** test against real production databases — local docker only.

## Useful references inside the repo

- Policy semantics: `skills/using-sequel-mcp/references/policy.md`
- Recovery + insert-hint behavior: `skills/using-sequel-mcp/references/recovery.md`
- Connection types incl. SSH+Docker: `skills/using-sequel-mcp/references/connections.md`
- Verification history: `docs/rust-rewrite/VERIFICATION.md`
- Changelog: `CHANGELOG.md` — version-by-version behavior changes.
- Security model: `SECURITY.md`.
