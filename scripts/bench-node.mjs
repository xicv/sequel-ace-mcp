// D8A: Node baseline under the SAME harness rules as the Rust bench —
// n samples, temp XDG isolation, identical readiness definition (id 1
// initialize response), median/p95/max, warm-cache priming.
//
// SAFETY: the spawned legacy server receives an EXPLICIT minimal
// environment (equivalent to env -i): PATH plus the isolated
// HOME/XDG/TEST-MODE map only. Nothing from this process's environment
// is inherited — no real config, no production variables.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The legacy TypeScript build to compare against is supplied by the
// operator (its location is machine-specific); nothing home-grown is
// baked into the script.
const LEGACY_BIN = process.env.SEQUEL_MCP_LEGACY_BIN;
if (!LEGACY_BIN) {
  console.error("bench-node: set SEQUEL_MCP_LEGACY_BIN to the legacy build entry (dist/index.js) to run the differential benchmark");
  process.exit(2);
}

const N = parseInt(process.argv[2] || "30", 10);
const dir = mkdtempSync(join(tmpdir(), "bench-node-"));
mkdirSync(join(dir, "cfg", "sequel-mcp"), { recursive: true });
mkdirSync(join(dir, "data", "sequel-mcp"), { recursive: true });
mkdirSync(join(dir, "home"), { recursive: true });
console.log(`ISO_ROOT=${dir}`);
writeFileSync(join(dir, "demo.sqlite"), "");
const cfgPath = join(dir, "cfg", "sequel-mcp", "config.json");
writeFileSync(cfgPath, JSON.stringify({
  version: 2, revision: 1, defaultConnection: "demo",
  connections: [{ driver: "sqlite", name: "demo", path: join(dir, "demo.sqlite"), database: "main",
    policy: { read: "allow", write: "deny", ddl: "deny", admin: "deny", txCtrl: "allow", rowCap: 100,
      stmtTimeoutMs: 5000, requireTouchID: false, maxBackupRows: 100, maxBackupBytes: 1048576, onBackupOverflow: "abort" },
    tablePolicies: {} }],
  retention: {},
}));
const env = {
  PATH: process.env.PATH,
  HOME: join(dir, "home"),
  XDG_CONFIG_HOME: join(dir, "cfg"),
  XDG_DATA_HOME: join(dir, "data"),
  SEQUEL_MCP_TEST_MODE: "1",
  SEQUEL_MCP_TEST_ROOT: dir,
};

const init = [];
const tools = [];

const once = () => new Promise((resolve, reject) => {
  const t0 = performance.now();
  const child = spawn("node", [LEGACY_BIN], { env, stdio: ["pipe", "pipe", "ignore"] });
  let buf = "";
  const timer = setTimeout(() => { child.kill(); reject(new Error("timeout")); }, 30000);
  child.on("error", (e) => { clearTimeout(timer); reject(e); });
  child.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id === 1) {
          init.push(performance.now() - t0);
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
        } else if (msg.id === 2) {
          tools.push(performance.now() - t0);
          clearTimeout(timer);
          child.kill();
          resolve();
        }
      } catch {}
    }
  });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bench", version: "0" } } }) + "\n");
});

const stats = (a) => {
  a.sort((x, y) => x - y);
  return `median=${a[Math.floor(a.length / 2)].toFixed(2)}ms p95=${a[Math.ceil(a.length * 0.95) - 1].toFixed(2)}ms max=${a[a.length - 1].toFixed(2)}ms n=${a.length}`;
};

async function main() {
  for (let i = 0; i < 3; i++) await once(); // warm fs cache
  init.length = 0; tools.length = 0;
  for (let i = 0; i < N; i++) await once();
  console.log(`NODE_COLD_INIT ${stats(init)}`);
  console.log(`NODE_COLD_TO_TOOLS_LIST ${stats(tools)}`);
}
main().catch((e) => { console.error("BENCH_FAILED", e.message); process.exit(1); });
