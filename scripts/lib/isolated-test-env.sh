#!/usr/bin/env bash
# Shared fail-closed isolation for every process under test.
#
# One entry point used by bench-mcp.sh, test-db.sh and
# test-mcp-lifecycle.sh: a fresh temporary root (0700) with home/config/
# data/cache/runtime subtrees, and clean-environment launchers. Because
# children are started via `env -i` (or an explicit env map), NOTHING is
# inherited from the developer shell — not SEQUEL_MCP_* paths, not
# DATABASE_URL/MYSQL_*/SSH_AUTH_SOCK/NODE_OPTIONS/npm_config_*, not the
# real config or Keychain. The binary additionally enforces
# SEQUEL_MCP_TEST_MODE=1 fail-closed behavior on its side (paths under
# SEQUEL_MCP_TEST_ROOT, loopback-only MySQL endpoints, no Keychain).
#
# Usage:   source scripts/lib/isolated-test-env.sh && iso_init
# Launch:  iso_spawn_env target/debug/sequel-mcp serve
#          (or build an explicit env map from `iso_env_map`)

ISO_ROOT=""

iso_init() {
  ISO_ROOT="$(mktemp -d /tmp/sqm-iso.XXXXXX)"
  export ISO_ROOT
  mkdir -p \
    "$ISO_ROOT/home" \
    "$ISO_ROOT/config" \
    "$ISO_ROOT/data" \
    "$ISO_ROOT/cache" \
    "$ISO_ROOT/runtime"
  chmod 700 \
    "$ISO_ROOT/home" \
    "$ISO_ROOT/config" \
    "$ISO_ROOT/data" \
    "$ISO_ROOT/cache" \
    "$ISO_ROOT/runtime"
  trap 'rm -rf "$ISO_ROOT"' EXIT INT TERM
  echo "ISO_ROOT=$ISO_ROOT"
}

# env -i launcher prefix for a direct exec of a process under test.
iso_spawn_env() {
  printf 'env -i PATH="%s" HOME="%s/home" XDG_CONFIG_HOME="%s/config" XDG_DATA_HOME="%s/data" XDG_CACHE_HOME="%s/cache" XDG_RUNTIME_DIR="%s/runtime" SEQUEL_MCP_TEST_MODE=1 SEQUEL_MCP_TEST_ROOT="%s" RUST_BACKTRACE=1' \
    "$PATH" "$ISO_ROOT" "$ISO_ROOT" "$ISO_ROOT" "$ISO_ROOT" "$ISO_ROOT" "$ISO_ROOT"
}

# KEY=VALUE lines for tools that build an explicit environment map
# (node drivers). Same variables as iso_spawn_env, nothing else.
iso_env_map() {
  cat <<MAP
PATH=$PATH
HOME=$ISO_ROOT/home
XDG_CONFIG_HOME=$ISO_ROOT/config
XDG_DATA_HOME=$ISO_ROOT/data
XDG_CACHE_HOME=$ISO_ROOT/cache
XDG_RUNTIME_DIR=$ISO_ROOT/runtime
SEQUEL_MCP_TEST_MODE=1
SEQUEL_MCP_TEST_ROOT=$ISO_ROOT
RUST_BACKTRACE=1
MAP
}

# In-process test runs (cargo): export the isolated variables into the
# cargo environment. cargo itself keeps the normal environment; every
# path the library derives lands under ISO_ROOT, and TEST_MODE makes the
# binary-side gates fail closed.
iso_export_for_cargo() {
  export XDG_CONFIG_HOME="$ISO_ROOT/config"
  export XDG_DATA_HOME="$ISO_ROOT/data"
  export SEQUEL_MCP_TEST_MODE=1
  export SEQUEL_MCP_TEST_ROOT="$ISO_ROOT"
  echo "cargo env: XDG_CONFIG_HOME=$XDG_CONFIG_HOME XDG_DATA_HOME=$XDG_DATA_HOME TEST_ROOT=$SEQUEL_MCP_TEST_ROOT"
}
