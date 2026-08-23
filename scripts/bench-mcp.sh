#!/usr/bin/env bash
# D8: reproducible benchmarks. Deterministic process-level MCP harness
# (n samples, median/p95/max); live-server warm/cold queries when
# SEQUEL_MCP_TEST_MYSQL points at a LOCAL docker server only.
#
# SAFETY: every spawned process runs under the shared fail-closed
# isolation entry (scripts/lib/isolated-test-env.sh): a fresh temporary
# root, clean env-map spawns (nothing inherited), SEQUEL_MCP_TEST_MODE=1.
# The real user config (production connections), the real audit DB, and
# the real Keychain are unreachable from benchmarks.
#
# RESULTS STATUS: default runs are development/debug-profile directional
# numbers. Run with PROFILE=release for the packaging-grade release/LTO
# numbers (same machine, same methodology); Session 12 of
# docs/rust-rewrite/VERIFICATION.md records both.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/isolated-test-env.sh
source scripts/lib/isolated-test-env.sh

PROFILE="${PROFILE:-debug}"
if [ "$PROFILE" = "release" ]; then
  cargo build --release 2>/dev/null
  BIN=target/release/sequel-mcp
else
  cargo build 2>/dev/null
  BIN=target/debug/sequel-mcp
fi
N="${1:-30}"   # warm-path iterations

iso_init
mkdir -p "$ISO_ROOT/config/sequel-mcp" "$ISO_ROOT/data/sequel-mcp"
: > "$ISO_ROOT/demo.sqlite"
cat > "$ISO_ROOT/config/sequel-mcp/config.json" <<JSON
{
  "version": 2,
  "revision": 1,
  "defaultConnection": "demo",
  "connections": [{
    "driver": "sqlite",
    "name": "demo",
    "path": "$ISO_ROOT/demo.sqlite",
    "database": "main",
    "policy": {
      "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
      "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 5000,
      "requireTouchID": false, "maxBackupRows": 100,
      "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
    },
    "tablePolicies": {}
  }],
  "retention": {}
}
JSON

# The node driver receives the explicit env map (nothing else is
# inherited by the children it spawns).
ENV_MAP_FILE="$(mktemp)"
iso_env_map > "$ENV_MAP_FILE"

run_bench() {
  node - "$BIN" "$N" "$ENV_MAP_FILE" <<'EOF'
const { spawn } = require("node:child_process");
const { readFileSync } = require("node:fs");
const [bin, nArg, envMapPath] = process.argv.slice(2);
const N = parseInt(nArg, 10);

// Explicit environment ONLY (equivalent to env -i): the isolation map
// plus nothing inherited from this process's environment.
const env = {};
for (const line of readFileSync(envMapPath, "utf8").split("\n")) {
  const i = line.indexOf("=");
  if (i > 0) env[line.slice(0, i)] = line.slice(i + 1);
}

const samples = {};
const now = () => performance.now();
const stats = (a) => {
  a.sort((x, y) => x - y);
  const med = a[Math.floor(a.length / 2)];
  const p95 = a[Math.min(a.length - 1, Math.ceil(a.length * 0.95) - 1)];
  return `median=${med.toFixed(2)}ms p95=${p95.toFixed(2)}ms max=${a[a.length-1].toFixed(2)}ms n=${a.length}`;
};

function once(cold) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, ["serve"], {
      stdio: ["pipe", "pipe", "inherit"],
      env,
    });
    let buf = "";
    const startedAt = now();
    const onLine = (line) => {
      try {
        const msg = JSON.parse(line);
        if (msg.id === 1) {
          samples.init = samples.init || [];
          if (cold) samples.init.push(now() - startedAt);
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
        } else if (msg.id === 2) {
          if (cold) {
            samples.toolsList = samples.toolsList || [];
            samples.toolsList.push(now() - startedAt);
          }
          child.kill();
          resolve();
        }
      } catch {}
    };
    child.stdout.on("data", (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const l = buf.slice(0, i); buf = buf.slice(i + 1);
        if (l.trim()) onLine(l);
      }
    });
    child.on("error", reject);
    child.stdin.write(JSON.stringify({
      "jsonrpc": "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bench", version: "0" } },
    }) + "\n");
  });
}

(async () => {
  // Cold: process spawn -> initialized, and -> tools/list.
  // Warm the filesystem cache deterministically before sampling.
  for (let i = 0; i < 3; i++) await once(false);
  for (let i = 0; i < N; i++) await once(true);
  console.log(`RUST_COLD_INIT ${stats(samples.init)}`);
  console.log(`RUST_COLD_TO_TOOLS_LIST ${stats(samples.toolsList)}`);
  // Warm tools/list within one process: reuse one server.
  const child = spawn(bin, ["serve"], { stdio: ["pipe", "pipe", "inherit"], env });
  let buf = "", nextId = 1;
  const warm = [];
  const pending = new Map();
  const onLine = (line) => {
    try {
      const msg = JSON.parse(line);
      if (pending.has(msg.id)) {
        const cb = pending.get(msg.id); pending.delete(msg.id); cb(msg);
      }
    } catch {}
  };
  child.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const l = buf.slice(0, i); buf = buf.slice(i + 1);
      if (l.trim()) onLine(l);
    }
  });
  const send = (obj) => child.stdin.write(JSON.stringify(obj) + "\n");
  const awaitId = (id) => new Promise((res) => pending.set(id, res));
  send({ jsonrpc: "2.0", id: nextId, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bench", version: "0" } } });
  await awaitId(nextId++);
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  for (let i = 0; i < N; i++) {
    const s = now();
    send({ jsonrpc: "2.0", id: nextId, method: "tools/list" });
    await awaitId(nextId++);
    warm.push(now() - s);
  }
  console.log(`RUST_WARM_TOOLS_LIST ${stats(warm)}`);
  // Full MCP query round trip over the ISOLATED sqlite connection.
  const firstQ = [];
  const warmQ = [];
  for (let i = 0; i < N; i++) {
    const st = now();
    send({ jsonrpc: "2.0", id: nextId, method: "tools/call", params: { name: "query", arguments: { sql: "SELECT 41 + 1 AS answer" } } });
    await awaitId(nextId++);
    (i < 3 ? firstQ : warmQ).push(now() - st);
  }
  firstQ.sort((a, b) => a - b);
  console.log(`RUST_MCP_SQLITE_QUERY_FIRST3 median=${firstQ[Math.floor(firstQ.length / 2)].toFixed(2)}ms n=${firstQ.length}`);
  console.log(`RUST_MCP_SQLITE_QUERY_WARM ${stats(warmQ)}`);
  child.kill();
})().catch((e) => { console.error(e); process.exit(1); });
EOF
}

echo "=== MCP process benchmarks (n=$N, isolated config)"
run_bench
echo "=== Environment"
echo "PROFILE=$PROFILE"
if [ "$PROFILE" = "release" ]; then
  echo "BENCH_CLASS=release/LTO (packaging-grade; same machine, same methodology as the debug directional runs)"
else
  echo "BENCH_CLASS=development/directional (debug profile, same machine; not a release performance claim)"
fi
echo "ISOLATION=fail-closed (ISO_ROOT printed above; env-map spawns; TEST_MODE active)"
echo "AUDIT_MODE=SQLite WAL + synchronous=NORMAL (AUDIT_WRITE measures API+transaction completion, not durable fsync)"
echo "MAC=$(sysctl -n hw.model 2>/dev/null || echo unknown)"
echo "ARCH=$(uname -m)"
echo "MACOS=$(sw_vers -productVersion 2>/dev/null || echo unknown)"
echo "SAMPLES=$N"
echo "=== Live-server benchmarks (local docker only)"
if [ -n "${SEQUEL_MCP_TEST_MYSQL:-}" ]; then
  iso_export_for_cargo
  SEQUEL_MCP_TEST_MYSQL="$SEQUEL_MCP_TEST_MYSQL" \
    cargo test --test bench_live -- --nocapture --test-threads=1 2>&1 | grep -E "FIRST_QUERY|WARM_|POOL_|CANCEL_|AUDIT_"
  rm -f "$ENV_MAP_FILE"
else
  echo "LIVE_SKIPPED=SEQUEL_MCP_TEST_MYSQL not set"
  rm -f "$ENV_MAP_FILE"
fi
