# sequel-mcp — Claude orientation

This file gives Claude Code (and any Claude Agent) a fast orientation when working in this repo. It does **not** replace `README.md` (user-facing) or `CONTRIBUTING.md` (contributor-facing).

## What this is

An MCP (Model Context Protocol) server, published to npm as `sequel-mcp`, that lets Claude run MySQL/MariaDB SQL behind a **policy gate** with **pre-mutation backups**, an **immutable audit log**, and **macOS-native credential storage**.

It is **not** a Claude Code Skill. A companion Skill is bundled under `skills/using-sequel-mcp/` and follows the May-2026 Anthropic skill authoring guideline (progressive disclosure, third-person description, refs one level deep).

## Layout

```
src/
├── index.ts                # CLI entry (stdio transport)
├── server.ts               # registerTool / registerPrompt / registerResource
├── doctor.ts               # sanitized diagnostic CLI
├── migrate.ts              # config migration CLI
├── types.ts                # Zod schemas + domain types
├── policy/                 # classifier, gate, resolver, grants
├── sql/                    # executor, ssh tunnel, docker tunnel, host-key
├── audit/                  # SQLite logger, retention, history-search
├── vault/                  # keychain, config, paths, touchid
├── elicit/                 # confirm prompt (4-choice grant)
├── importer/               # Sequel Ace plist + queryHistory
└── backup/                 # capture, extractor (multi-table aware), restore
scripts/
├── check-secrets.sh        # pre-commit secret scanner
├── install-pre-commit-hook.sh
└── touchid-helper.swift    # compiled to dist/touchid-helper at install time
skills/using-sequel-mcp/    # MCP-user-facing Skill (SKILL.md + references/)
tests/                      # vitest, in-memory secret store, fixture DBs
```

## Run / verify

```bash
npm run build       # tsc only
npm test            # vitest (181 tests at last count)
npm run typecheck   # tsc --noEmit
npm run doctor      # sanitized diagnostic JSON
```

E2E with a live MCP client: `node dist/index.js` (consumes stdio). Not published to npm — source-only, see README.

## Conventions in this repo

- **Single MCP transport**: stdio. No HTTP server in scope.
- **Single SQL statement per call.** The classifier rejects multi-statement input. Do not work around this by chaining `;`.
- **Fail-closed policy**: unknown statement types and parser errors both reject.
- **Immutable patterns**: never mutate `Connection` / `Config` / `Policy` objects; create new ones (see `vault/config.ts`).
- **Zod is the source of truth**: every persisted shape goes through `*Schema.parse()` on read AND write.
- **No console.log**: use `process.stderr.write` (stdout is reserved for MCP framing). ESLint `no-console` rule warns on it.
- **Strict TS**: `noUncheckedIndexedAccess`, `noFallthroughCasesInSwitch`, `strict: true`.
- **Tests use `InMemorySecretStore`** from `src/vault/keyring.ts`; never the real Keychain.

## Where things live at runtime

| Item | Path |
|------|------|
| User config | `~/.config/sequel-mcp/config.json` (`mode 0600`) |
| Audit + backup DB | `~/.local/share/sequel-mcp/audit.sqlite` (WAL mode) |
| Touch ID helper | `dist/touchid-helper` (compiled from `scripts/touchid-helper.swift`) |
| Keychain service prefix | `sequel-mcp : <connection-name>` |

## Common tasks

- **Add a tool**: register in `src/server.ts` with explicit `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`). Add an `inputSchema` Zod shape. Audit-log writes/destructive ops via `writeAuditEntry`.
- **Add a SQL category**: edit `policy/classifier.ts`, `types.ts` (`SQL_CATEGORIES`), `policy/gate.ts`. Update tests.
- **Change retention defaults**: edit `types.ts` `RetentionInnerSchema`.
- **Touch the audit schema**: add `CREATE TABLE IF NOT EXISTS` + migration in `migrate.ts`. Never destructive ALTERs against existing user data without a migration.

## Things to avoid

- Do **not** add a second MCP transport without RFC.
- Do **not** weaken policy defaults (`write=confirm`, `ddl=deny`, `admin=deny` for new presets).
- Do **not** persist passwords outside Keychain.
- Do **not** add network telemetry. The project is local-first by design.
- Do **not** `--no-verify` past the pre-commit secret scanner.

## Useful references inside the repo

- Policy semantics: `skills/using-sequel-mcp/references/policy.md`
- Recovery + insert-hint behavior: `skills/using-sequel-mcp/references/recovery.md`
- Connection types incl. SSH+Docker: `skills/using-sequel-mcp/references/connections.md`
- Changelog: `CHANGELOG.md` — version-by-version behavior changes.
- Security model: `SECURITY.md`.
