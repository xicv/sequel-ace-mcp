#!/usr/bin/env bash
# MCP stdio lifecycle + isolation regression suite against the real
# built binary, under the shared fail-closed isolation root. The tests
# themselves spawn children with clean environments (env -i semantics)
# and SEQUEL_MCP_TEST_MODE=1 fail-closed enforcement.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/isolated-test-env.sh
source scripts/lib/isolated-test-env.sh

cargo build 2>/dev/null
iso_init
iso_export_for_cargo
cargo test --test mcp_lifecycle -- --test-threads=1
echo "==> MCP lifecycle + isolation suite PASSED"
