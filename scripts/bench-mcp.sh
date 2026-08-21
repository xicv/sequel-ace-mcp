#!/usr/bin/env bash
# D8: reproducible benchmarks. Deterministic process-level MCP harness
# (n samples, median/p95/max); live-server warm/cold queries when
# SEQUEL_MCP_TEST_MYSQL points at a server. Reports go to stdout in a
# parseable KEY=VALUE form; full samples to stderr.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build 2>/dev/null

BIN=target/debug/sequel-mcp
N="${1:-30}"   # warm-path iterations

run_bench() {
  node - "$BIN" "$N" <<'EOF'
const { spawn } = require("node:child_process");
const [bin, nArg] = process.argv.slice(2);
const N = parseInt(nArg, 10);

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
      env: { ...process.env },
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
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bench", version: "0" } },
    }) + "\n");
  });
}

// Cold: process spawn -> initialized, and -> tools/list.
(async () => {
  for (let i = 0; i < N; i++) await once(true);
  console.log(`RUST_COLD_INIT ${stats(samples.init)}`);
  console.log(`RUST_COLD_TO_TOOLS_LIST ${stats(samples.toolsList)}`);
  // Warm tools/list within one process: reuse one server.
  const child = spawn(bin, ["serve"], { stdio: ["pipe", "pipe", "inherit"] });
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
  child.kill();
})();
EOF
}

echo "=== MCP process benchmarks (n=$N)"
run_bench
echo "=== Live-server benchmarks"
if [ -n "${SEQUEL_MCP_TEST_MYSQL:-}" ]; then
  SEQUEL_MCP_TEST_MYSQL="$SEQUEL_MCP_TEST_MYSQL" cargo test --test bench_live -- --nocapture --test-threads=1
else
  echo "LIVE_SKIPPED=SEQUEL_MCP_TEST_MYSQL not set"
fi
