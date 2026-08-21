#!/usr/bin/env bash
# Deterministic local check gate. No GitHub Actions, no self-hosted runners.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo check"
cargo check --workspace --all-targets --all-features --locked

echo "==> cargo test"
cargo test --workspace --all-features --locked

echo "==> cargo clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

echo "==> cargo package (list + build)"
cargo package --locked --list >/dev/null
cargo package --locked

echo "==> cargo publish dry-run"
cargo publish --dry-run --locked

echo "==> gitleaks (if installed)"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source=. --no-git=false --redact -v
else
  echo "    (gitleaks not installed — skipped)"
fi

echo "==> git whitespace check"
git diff --check

echo "ALL LOCAL CHECKS PASSED"
