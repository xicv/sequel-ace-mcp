# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.10.x  | :white_check_mark: |

## Reporting a Vulnerability

If you find a security issue, **do not open a public GitHub issue**. Instead, open a private security advisory on the repository or email the maintainers directly. We aim to acknowledge within 72 hours.

## Threat Model

This MCP server runs locally on the user's Mac as a child process of an MCP client (Claude Code, Claude Desktop, Codex CLI, Cursor, etc.). It is a single native-Rust binary. It connects to MySQL/MariaDB/SQLite targets the user has configured, directly or over SSH.

### What we protect

| Asset                              | Storage                                                                | Protection                                                                                                                |
|------------------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| Database passwords                 | macOS Keychain (direct SecItem API via `security-framework`)           | `WhenUnlockedThisDeviceOnly`, non-syncable. Never written to disk in plaintext. Never sent to any cloud service.          |
| SSH tunnel passwords/passphrases   | macOS Keychain (`<conn-name>::ssh` service)                            | Same as above.                                                                                                            |
| Connection metadata (host/user/db) | `~/.config/sequel-mcp/config.json`, `0o600` permissions            | Local file only. No passwords stored here.                                                                                |
| Approval intent                    | Server-side opaque MRTR handles + in-RAM session grants               | Never persisted; bound to operation digest + policy revision; single-use.                                                 |

### Boundaries enforced by this server

- **No outbound network calls** other than the configured database target (direct TCP or SSH tunnel). No telemetry. No update checks. No external lookups.
- **Read-only category SQL** runs inside `START TRANSACTION READ ONLY` (MySQL/MariaDB) or a read-only file handle (SQLite) — server-side enforcement in addition to parser-side classification.
- **Multi-statement input rejected** at parse time. A single statement per call is structural, not advisory.
- **Closed-world classification** (`sqlparser` AST): any unrecognized statement type is `unknown` → denied. Admin keywords the parser can't classify fall back to a keyword pass classified as `admin` (default `deny`).
- **Confirmations are server-issued and unforgeable from the model side.** Three channels, in order: MCP elicitation; authenticated approval IPC (Unix socket under the XDG runtime dir, restricted to the server's **own effective uid** — credential-checked before any protocol byte; replies single-use and id-bound; 60 s deadline fails closed); and server-side opaque `requestState` (MRTR) handles for round-trip clients, bound to the exact operation digest so an approved statement cannot be replayed against different SQL, connection, or policy revision.
- **Wall-clock statement timeouts** — the SQLite interrupt watchdog and MySQL budget enforce real deadlines regardless of scheduler contention.
- **SSH host-key verification** — `strict` policy rejects unknown and changed host keys; `lenient` still enforces `@revoked`. Docker bridge argv is validated space-free and metacharacter-free before it ever reaches the SSH command line.
- **Touch ID** is optional per connection; uses macOS `LocalAuthentication` only. Unavailable hardware fails closed.

### What is NOT protected

- A logged-in attacker on the same Mac with shell access can read the MCP process memory and may extract a cached password during the configured idle window. Use `requireTouchID: true` to shorten that window.
- The approval IPC trusts **same-uid** processes by design — anything already running as your user can answer prompts. That is the same trust boundary as the Keychain itself.
- This server is not sandboxed. Run it under your normal user account; do not run it as root.
- We do not pin TLS certificates. If you set `ssl: true` against a public-internet database, configure the database's TLS policy server-side (`sslCaPath` adds a private CA).
- We do not encrypt the local config file beyond default `0o600` filesystem permissions. Anyone with `cat` access to your home directory can read it (host/user/db only — no passwords).
- We do not protect against malicious MCP clients. The client decides which tools to call; this server enforces what each tool is *allowed* to do once called.

### Defence-in-depth layers

1. AST classification (`sqlparser`, closed-world + admin-keyword fallback).
2. Multi-statement rejection.
3. Read-only transaction enforcement for read-category statements.
4. Two-layer policy (baseline + exact/wildcard table rules, strictest-wins, fail-closed).
5. Server-issued confirmations (elicitation / same-uid IPC / MRTR digest-bound handles).
6. Pre-mutation backups inside the same transaction, with row/byte caps.
7. Append-only audit log with optional hash chain.
8. Row caps + wall-clock statement timeouts.
9. Optional Touch ID gate per session.
10. SSH host-key verification + TLS server-name preservation + bridge argv validation.
11. Recommended: a dedicated read-only DB user with `GRANT SELECT` only.

## Credentials and the Repository

This repository must never contain credentials, even in test fixtures. To enforce:

- `.gitignore` excludes common credential file patterns and any `.env*` file other than `.env.example`.
- Test fixtures use the IETF-reserved domain `example.com` and obviously-fake names like `prod-tunnel`.
- `scripts/check-secrets.sh` performs a regex scan (including user-home-path literals); run before each commit.
- CI runs gitleaks over the full history on every PR.

See `CONTRIBUTING.md` for the full contributor checklist.

If you suspect a credential has been committed historically, consider the credential compromised, rotate it immediately, and run `git filter-repo` to scrub history before any push.
