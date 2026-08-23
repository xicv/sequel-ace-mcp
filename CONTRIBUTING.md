# Contributing to sequel-mcp

Thanks for considering a contribution. This project handles real database credentials, so the contribution rules are stricter than usual around what may enter the repository.

## The Cardinal Rule

**No credential, no PII, no environment-specific identifier may ever enter this repository — not in source code, not in tests, not in commit messages, not in screenshots in PRs.**

If you suspect you've committed something sensitive, see "I think I leaked something" below.

## What you may NOT commit

| Category | Examples |
|---|---|
| Passwords / tokens | Any password literal, API keys, JWTs, OAuth tokens, AWS access keys, GitHub PATs, Slack tokens. |
| Private keys | `id_rsa`, `id_ed25519`, any `*.pem` / `*.key` / `*.p12`. |
| Real hostnames | Real DB hosts, internal bastions, VPN endpoints, jumpboxes, `*.internal`, `*.corp`, `*.local`. |
| Real database/schema names that identify a customer or org | `acme_prod`, `customer_pii`. |
| User home paths | `/Users/<name>/...`, `/home/<name>/...` — in code, docs, or commit messages. |
| Personal email addresses or full names | Anywhere outside the standard contributor signoff. |
| Screenshots that include any of the above | PR descriptions and discussions included. |

## What you may use in tests

- **Hostnames**: only `example.com`, `example.org`, `example.net`, `localhost`, `127.0.0.1` (IETF-reserved per RFC 2606).
- **DB names**: generic placeholders like `app`, `analytics`, `test_db`.
- **User names**: generic placeholders like `root`, `readonly`, `dbuser`.
- **Synthetic plist/config blobs**: any `Favorites.plist`-shaped fixture must be hand-written with placeholders, never copy-pasted from a real Sequel Ace install.
- **No process spawns in unit tests**: integration tests that need the real binary are orchestrated by the bash phase scripts (`scripts/test-mcp-lifecycle.sh`, `scripts/test-db.sh`, `scripts/test-ssh.sh`) under the fail-closed isolated test environment (`scripts/lib/isolated-test-env.sh`) — never inherit the developer's real config, audit DB, or Keychain.

## Pre-commit checklist

Run before every commit:

```bash
bash scripts/check-secrets.sh        # local regex scan (user-home paths included)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Optional but recommended: install [`gitleaks`](https://github.com/gitleaks/gitleaks) and run it against the repo (`gitleaks detect --source=. --redact`). CI runs it over full history on every PR.

## Coding rules

- Rust 2024 edition; the toolchain is pinned in `rust-toolchain.toml`.
- New features need tests for the safety-critical layers (classifier, resolver, gate, approval IPC, transports).
- The AST classifier remains **closed-world** — never extend it with an `else → allow` fallback. Unknown statement types must remain unknown.
- Never add a shortcut that bypasses the policy gate. All SQL goes through the same gate path; there is exactly one implementation of policy, approval, and execution semantics in the crate.
- Never log raw credentials or unredacted SQL literals. Audit writes go through the redactor.
- New tools must declare `annotations` honestly (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
- `unsafe` is confined to the pinned credential-probe/FFI sites (`LOCAL_PEERCRED`/`SO_PEERCRED`, libc calls) — each carries its justification inline. New `unsafe` needs a comment stating the invariant.
- Timeouts must be wall-clock deadlines, not iteration counts.

## I think I leaked something

1. Stop. Do not push.
2. If you've already committed locally but not pushed:
   ```bash
   git reset --soft HEAD~1
   # remove the secret from the file
   bash scripts/check-secrets.sh
   git commit -c ORIG_HEAD
   ```
3. If you've already pushed: assume the credential is compromised. **Rotate it immediately.** Then scrub history with `git filter-repo` and force-push, after coordinating with maintainers.

A leaked credential cannot be "deleted" from a public repo — it has been crawled within minutes by automated scanners. Rotation is the only real fix.

## Release checklist (0.10.x)

1. Merge the reviewed PR; record the merged `main` SHA.
2. Rerun the clean local gates from the merged SHA (`scripts/ci-local.sh`).
3. `cargo package --locked` → inspect contents; `cargo publish --dry-run --locked`.
4. Confirm crates.io ownership for the `sequel-mcp` name.
5. `cargo publish --locked`; verify `cargo install sequel-mcp --locked` from the registry.
6. Tag `v0.10.0` at the exact published commit; create the GitHub release.

Never tag before the publish succeeds, and never publish from a PR branch.

## License

By submitting a PR you agree your contribution is licensed under MIT (see `LICENSE`).
