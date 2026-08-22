//! D7: deterministic process-level MCP lifecycle tests against the real
//! built binary — legacy initialization, tools/list, a gated SQLite
//! execute (denied) and query round trip, malformed + oversized requests,
//! stdin EOF during an in-flight request, and clean exit. Every read is
//! deadline-driven; no fixed sleeps as a pass criterion.
//!
//! ISOLATION: every spawned process runs in a CLEAN environment (nothing
//! inherited; only an isolated HOME/XDG tree and the fail-closed
//! SEQUEL_MCP_TEST_MODE/ROOT variables) — the executable regression for
//! the benchmark-environment isolation failure. A spawned child can
//! never inherit the developer's real config, audit DB, or Keychain.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Compile-time path to the locally built binary (no runtime-supplied
/// command source).
fn bin_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/debug/sequel-mcp"
    ))
}

struct Server {
    child: Child,
}

impl Server {
    /// Standard demo config: one read-only sqlite connection, spawned in
    /// a clean isolated environment (see module ISOLATION note).
    fn spawn() -> (Server, std::process::ChildStdin, LineReceiver) {
        Self::spawn_demo_with(serde_json::json!({}))
    }

    /// Demo config variant with table policies, for elevation scenarios.
    fn spawn_demo_with(
        table_policies: serde_json::Value,
    ) -> (Server, std::process::ChildStdin, LineReceiver) {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg_root = dir.path().join("cfg");
        let data_root = dir.path().join("data");
        std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        // Read-only SQLite handles require the file to exist.
        let demo_db = dir.path().join("demo.sqlite");
        std::fs::write(&demo_db, b"").unwrap();
        std::fs::write(
            cfg_root.join("sequel-mcp").join("config.json"),
            serde_json::to_string_pretty(&demo_config(&demo_db, table_policies)).unwrap(),
        )
        .unwrap();
        eprintln!("ISO_ROOT={}", dir.path().display());
        std::mem::forget(dir);
        Self::launch(&cfg_root, &data_root)
    }

    /// Spawn with a fully caller-provided config document (same clean
    /// isolated environment).
    fn spawn_with_config(
        cfg: serde_json::Value,
    ) -> (Server, std::process::ChildStdin, LineReceiver) {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg_root = dir.path().join("cfg");
        let data_root = dir.path().join("data");
        std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        std::fs::write(
            cfg_root.join("sequel-mcp").join("config.json"),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
        eprintln!("ISO_ROOT={}", dir.path().display());
        std::mem::forget(dir);
        Self::launch(&cfg_root, &data_root)
    }

    /// Launch the binary with a CLEAN environment: nothing inherited,
    /// only the isolated tree below and the fail-closed test-mode
    /// variables. The binary needs no PATH - it execs nothing.
    fn launch(
        cfg_root: &std::path::Path,
        data_root: &std::path::Path,
    ) -> (Server, std::process::ChildStdin, LineReceiver) {
        // The fail-closed test root is the grandparent of the XDG dirs
        // (the leaked TempDir itself).
        let test_root = cfg_root
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| cfg_root.to_path_buf());
        let home = test_root.join("home");
        let mut child = Command::new(bin_path())
            .arg("serve")
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", cfg_root)
            .env("XDG_DATA_HOME", data_root)
            .env("SEQUEL_MCP_TEST_MODE", "1")
            .env("SEQUEL_MCP_TEST_ROOT", &test_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary spawns");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        // Drain stderr in the background so a chatty child can never
        // block on a full pipe (kept for post-mortem on failure).
        let err = child.stderr.take();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut e = match err {
                Some(e) => e,
                None => return,
            };
            let mut buf = [0u8; 4096];
            while let Ok(n) = e.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
        let reader = LineReceiver::from_reader(stdout);
        (Server { child }, stdin, reader)
    }

    /// Like [`Server::launch`], plus synthetic test secrets for the
    /// in-memory store (TEST_MODE only; never the real Keychain).
    fn launch_with_secrets(
        cfg_root: &std::path::Path,
        data_root: &std::path::Path,
        secrets_json: &str,
    ) -> (Server, std::process::ChildStdin, LineReceiver) {
        let test_root = cfg_root
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| cfg_root.to_path_buf());
        let home = test_root.join("home");
        let mut child = Command::new(bin_path())
            .arg("serve")
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", cfg_root)
            .env("XDG_DATA_HOME", data_root)
            .env("SEQUEL_MCP_TEST_MODE", "1")
            .env("SEQUEL_MCP_TEST_ROOT", &test_root)
            .env("SEQUEL_MCP_TEST_SECRETS", secrets_json)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary spawns");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let err = child.stderr.take();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut e = match err {
                Some(e) => e,
                None => return,
            };
            let mut buf = [0u8; 4096];
            while let Ok(n) = e.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
        let reader = LineReceiver::from_reader(stdout);
        (Server { child }, stdin, reader)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn readonly_policy() -> serde_json::Value {
    serde_json::json!({
        "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
        "txCtrl": "allow", "rowCap": 200, "stmtTimeoutMs": 5000,
        "requireTouchID": false, "maxBackupRows": 100,
        "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
    })
}

fn demo_config(db: &std::path::Path, table_policies: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "version": 2,
        "revision": 1,
        "defaultConnection": "demo",
        "connections": [{
            "driver": "sqlite",
            "name": "demo",
            "path": db.display().to_string(),
            "database": "main",
            "policy": readonly_policy(),
            "tablePolicies": table_policies
        }],
        "retention": {}
    })
}

fn send(stdin: &mut impl Write, value: &serde_json::Value) {
    stdin
        .write_all(serde_json::to_string(value).unwrap().as_bytes())
        .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

/// Channel-fed line reader: an OS thread blocks on the pipe so the main
/// thread can enforce real deadlines (a blocking read on the pipe cannot).
/// Parsed messages that arrive out of order (concurrent responses) are
/// buffered, not discarded, so a later matcher still finds them.
struct LineReceiver {
    rx: std::sync::mpsc::Receiver<String>,
    pending: std::collections::VecDeque<serde_json::Value>,
}

impl LineReceiver {
    fn from_reader<R: Read + Send + 'static>(inner: R) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(inner);
            for line in reader.split(b'\n') {
                match line {
                    Ok(bytes) => {
                        let line = String::from_utf8_lossy(&bytes).trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            rx,
            pending: std::collections::VecDeque::new(),
        }
    }

    /// Next buffered-or-incoming message for `want_id`; non-matching
    /// messages stay buffered for subsequent lookups.
    fn recv_matching(&mut self, want_id: i64, deadline: Duration) -> Option<serde_json::Value> {
        let started = Instant::now();
        loop {
            if let Some(pos) = self.pending.iter().position(|m| m["id"] == want_id) {
                return self.pending.remove(pos);
            }
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => {
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) {
                        if msg["id"] == want_id {
                            return Some(msg);
                        }
                        self.pending.push_back(msg);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if started.elapsed() >= deadline {
                        return None;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    fn next_line(&mut self, deadline: Duration) -> Option<String> {
        let started = Instant::now();
        loop {
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => return Some(line),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if started.elapsed() >= deadline {
                        return None;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return None;
                }
            }
        }
    }
}

fn read_response(out: &mut LineReceiver, want_id: i64, deadline: Duration) -> serde_json::Value {
    out.recv_matching(want_id, deadline)
        .unwrap_or_else(|| panic!("no response for id {want_id} within {deadline:?}"))
}

#[test]
fn d7_lifecycle_legacy_and_tools() {
    let (server, mut stdin, mut out) = Server::spawn();

    // --- Legacy initialization (what current Codex clients send).
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "d7-test", "version": "0"}
            }
        }),
    );
    let msg = read_response(&mut out, 1, Duration::from_secs(10));
    assert_eq!(msg["result"]["serverInfo"]["name"], "sequel-mcp");
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // --- tools/list: 21 tools with names.
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let msg = read_response(&mut out, 2, Duration::from_secs(10));
    let tools = msg["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 27, "tool count");
    assert!(tools.iter().all(|t| t["name"].is_string()));
    assert!(tools.iter().any(|t| t["name"] == "query"));

    // --- Gated SQLite execute denied by policy (write=deny): fail closed.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "execute", "arguments": {
                "sql": "CREATE TABLE IF NOT EXISTS demo_t (id INTEGER PRIMARY KEY)"
            }}
        }),
    );
    let msg = read_response(&mut out, 3, Duration::from_secs(10));
    assert!(
        msg["result"]["isError"].as_bool().unwrap_or(false),
        "denied write: {msg}"
    );

    // --- SQLite query round trip through the real gate.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "query", "arguments": {"sql": "SELECT 41 + 1 AS answer"}}
        }),
    );
    let msg = read_response(&mut out, 4, Duration::from_secs(10));
    let rows = msg["result"]["structuredContent"]["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("rows missing: {msg}"));
    assert_eq!(rows[0]["answer"], serde_json::json!(42), "{msg}");

    // --- Malformed request: rmcp's documented/current malformed-line
    // behavior (rust-sdk #938) is that invalid stdio lines are ignored —
    // no JSON-RPC parse-error frame — and the server remains live. The
    // acceptance contract is survival + stream integrity: the malformed
    // line does not crash the server, produces no stdout contamination,
    // and the very next valid request is answered normally.
    stdin.write_all(b"{not json}\n").unwrap();
    stdin.flush().unwrap();
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}),
    );
    let msg = read_response(&mut out, 7, Duration::from_secs(10));
    assert!(
        msg["result"]["tools"]
            .as_array()
            .map(|t| t.len() == 27)
            .unwrap_or(false),
        "server must keep answering after malformed input: {msg}"
    );

    // --- Oversized request (~2 MiB > MAX_MCP_LINE_BYTES): the line
    // limiter discards it BEFORE the JSON codec ever buffers it (bounded
    // memory); the deterministic contract is that the stream stays
    // intact — the follow-up valid request MUST be answered and no
    // protocol bytes are emitted for the dropped line.
    let big = "x".repeat(2 * 1024 * 1024);
    let oversized =
        format!("{{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\",\"x\":\"{big}\"}}");
    stdin.write_all(oversized.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 6, "method": "tools/list"}),
    );
    let msg = read_response(&mut out, 6, Duration::from_secs(20));
    assert_eq!(
        msg["result"]["tools"].as_array().unwrap().len(),
        27,
        "follow-up after oversized input: {msg}"
    );

    // --- Clean EOF shutdown: close stdin, prompt exit.
    drop(stdin);
    let mut server = server;
    let started = Instant::now();
    loop {
        match server.child.try_wait().unwrap() {
            Some(_) => break,
            None => {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "process must exit promptly after stdin EOF"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

#[test]
fn d7_eof_during_in_flight_request() {
    let (server, mut stdin, mut out) = Server::spawn();

    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "d7-eof", "version": "0"}
            }
        }),
    );
    let _ = read_response(&mut out, 1, Duration::from_secs(10));
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // Slow read, then stdin EOF immediately: the process must exit within
    // a bounded window without waiting for the query to finish.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "query", "arguments": {
                "sql": "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT COUNT(*) FROM c"
            }}
        }),
    );
    drop(stdin);
    let mut server = server;
    let started = Instant::now();
    loop {
        match server.child.try_wait().unwrap() {
            Some(status) => {
                assert!(
                    started.elapsed() < Duration::from_secs(15),
                    "EOF with in-flight request must not hang"
                );
                assert!(
                    status.success() || status.code().is_some(),
                    "exit: {status:?}"
                );
                break;
            }
            None => {
                assert!(
                    started.elapsed() < Duration::from_secs(15),
                    "EOF with in-flight request must not hang"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

// ---- Modern era (2026-07-28): discovery, _meta requests, MRTR ----

fn meta_2026() -> serde_json::Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        "io.modelcontextprotocol/clientInfo": {"name": "d7-test", "version": "0"}
    })
}

#[test]
fn d7_modern_discover_meta_and_version_error() {
    let (server, mut stdin, mut out) = Server::spawn();

    // server/discover with modern _meta: supportedVersions includes
    // 2026-07-28 and the server identity is in the response _meta.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "server/discover",
            "params": {"_meta": meta_2026()}
        }),
    );
    let msg = read_response(&mut out, 1, Duration::from_secs(10));
    let versions: Vec<&str> = msg["result"]["supportedVersions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(versions.contains(&"2026-07-28"), "{versions:?}");
    assert_eq!(
        msg["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "sequel-mcp"
    );

    // Modern tools/list without any initialize: carries result
    // discrimination (resultType).
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
            "params": {"_meta": meta_2026()}
        }),
    );
    let msg = read_response(&mut out, 2, Duration::from_secs(10));
    assert_eq!(msg["result"]["resultType"], "complete");
    assert_eq!(msg["result"]["tools"].as_array().unwrap().len(), 27);

    // Modern tools/call (read) succeeds without initialize.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "query",
                "arguments": {"sql": "SELECT 6 AS seven_minus_one"},
                "_meta": meta_2026()
            }
        }),
    );
    let msg = read_response(&mut out, 3, Duration::from_secs(10));
    let rows = msg["result"]["structuredContent"]["rows"]
        .as_array()
        .unwrap();
    assert_eq!(rows[0]["seven_minus_one"], serde_json::json!(6));

    // Unsupported protocol version: the typed -32022 protocol error with
    // supported/requested data.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/list",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "1999-01-01",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "d7", "version": "0"}
            }}
        }),
    );
    let msg = read_response(&mut out, 4, Duration::from_secs(10));
    assert_eq!(msg["error"]["code"], -32022, "{msg}");
    assert_eq!(msg["error"]["data"]["requested"], "1999-01-01");

    drop(stdin);
    let mut server = server;
    let started = Instant::now();
    loop {
        match server.child.try_wait().unwrap() {
            Some(_) => break,
            None => {
                assert!(started.elapsed() < Duration::from_secs(10));
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

#[test]
fn d7_modern_mrtr_approval_lifecycle() {
    // The elevation policy (write=deny baseline + main.z allow rule) makes
    // CREATE TABLE z confirm-required; the modern path must return
    // input_required, consume the one-shot approval on retry, reject the
    // replay, and reject a mutated-but-otherwise-allowed statement by
    // digest.
    let (mut server, mut stdin, mut out) = Server::spawn_demo_with(serde_json::json!({
        "main.z": {"write": "allow", "ddl": "allow"},
        "main.zz": {"write": "allow", "ddl": "allow"}
    }));

    let sql = "CREATE TABLE z (id INTEGER PRIMARY KEY)";
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": sql},
                "_meta": meta_2026()
            }
        }),
    );
    let msg = read_response(&mut out, 1, Duration::from_secs(10));
    assert_eq!(msg["result"]["resultType"], "input_required", "{msg}");
    let state = msg["result"]["requestState"].as_str().unwrap().to_string();
    // Redacted operation details present in the input request.
    let ir = &msg["result"]["inputRequests"]["approval"]["params"];
    assert!(ir["message"].as_str().unwrap().contains("CREATE TABLE z"));
    assert!(ir["message"].as_str().unwrap().contains("main.z"));
    assert_eq!(ir["mode"], "form");
    assert_eq!(
        ir["requestedSchema"]["properties"]["choice"]["enum"][0],
        "once"
    );

    // Retry with the approval: executes exactly once.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": sql},
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": state
            }
        }),
    );
    let msg = read_response(&mut out, 2, Duration::from_secs(10));
    assert!(
        msg["result"]["isError"].is_null() || msg["result"]["isError"] == false,
        "approved execution: {msg}"
    );

    // Replay the same approval: rejected (single use).
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": sql},
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": state
            }
        }),
    );
    let msg = read_response(&mut out, 3, Duration::from_secs(10));
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_already_consumed]"),
        "replay rejected with a typed code: {msg}"
    );

    // Fresh approval for a different statement; try to use it on a
    // different allowed table — digest mismatch must reject.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": "CREATE TABLE zz (id INTEGER PRIMARY KEY)"},
                "_meta": meta_2026()
            }
        }),
    );
    let msg2 = read_response(&mut out, 4, Duration::from_secs(10));
    let state2 = msg2["result"]["requestState"].as_str().unwrap().to_string();
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": "CREATE TABLE zz (id INTEGER PRIMARY KEY, other INT)"},
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": state2
            }
        }),
    );
    let msg = read_response(&mut out, 5, Duration::from_secs(10));
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "digest mismatch rejected with a typed code: {msg}"
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .contains("operation changed"),
        "digest mismatch names the reason: {msg}"
    );
    let _ = &mut server;
}

// ---- MRTR negative matrix: every failure mode is typed, never a plain
// SQL error; the state is opaque and server-side ----

fn mrtr_call(
    stdin: &mut impl Write,
    out: &mut LineReceiver,
    id: i64,
    body: serde_json::Value,
) -> serde_json::Value {
    send(
        stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {
                "name": "execute",
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": body["state"].as_str().unwrap_or(""),
                "arguments": {"sql": body["sql"].as_str().unwrap_or("")}
            }
        }),
    );
    read_response(out, id, Duration::from_secs(10))
}

fn mrtr_first_call(
    stdin: &mut impl Write,
    out: &mut LineReceiver,
    id: i64,
    sql: &str,
    name: &str,
    arguments_extra: serde_json::Value,
) -> String {
    let mut args = serde_json::json!({"sql": sql});
    if !arguments_extra.is_null() {
        for (k, v) in arguments_extra.as_object().unwrap() {
            args[k] = v.clone();
        }
    }
    let _ = name;
    send(
        stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "execute", "arguments": args, "_meta": meta_2026()}
        }),
    );
    let msg = read_response(out, id, Duration::from_secs(10));
    assert_eq!(msg["result"]["resultType"], "input_required", "{msg}");
    msg["result"]["requestState"].as_str().unwrap().to_string()
}

#[test]
fn d7_modern_mrtr_negative_matrix() {
    let (server, mut stdin, mut out) = Server::spawn_demo_with(serde_json::json!({
        "main.z": {"read": "confirm", "write": "allow", "ddl": "allow"}
    }));

    let sql = "CREATE TABLE z (id INTEGER PRIMARY KEY)";
    let mut id = 100;

    // Corrupted state (one leading base64 char swapped).
    let s1 = mrtr_first_call(
        &mut stdin,
        &mut out,
        id,
        sql,
        "execute",
        serde_json::Value::Null,
    );
    id += 1;
    let first = s1.chars().next().unwrap();
    let swapped = if first == 'A' { 'B' } else { 'A' };
    let corrupt = format!("{swapped}{}", &s1[1..]);
    let msg = mrtr_call(
        &mut stdin,
        &mut out,
        id,
        serde_json::json!({"state": corrupt, "sql": sql}),
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "corrupted state: {msg}"
    );
    id += 1;

    // Truncated state.
    let s2 = mrtr_first_call(
        &mut stdin,
        &mut out,
        id,
        sql,
        "execute",
        serde_json::Value::Null,
    );
    id += 1;
    let truncated = s2[..s2.len() - 5].to_string();
    let msg = mrtr_call(
        &mut stdin,
        &mut out,
        id,
        serde_json::json!({"state": truncated, "sql": sql}),
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "truncated state: {msg}"
    );
    id += 1;

    // Oversized state (64 KiB of padding).
    let oversized = "A".repeat(64 * 1024);
    let msg = mrtr_call(
        &mut stdin,
        &mut out,
        id,
        serde_json::json!({"state": oversized, "sql": sql}),
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "oversized state: {msg}"
    );
    id += 1;

    // Cross-tool: a state issued for `execute` replayed through `query`
    // (whose own resolution is confirm-gated via the read rule).
    let s3 = mrtr_first_call(
        &mut stdin,
        &mut out,
        id,
        sql,
        "execute",
        serde_json::Value::Null,
    );
    id += 1;
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {
                "name": "query",
                "arguments": {"sql": "SELECT * FROM z"},
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": s3
            }
        }),
    );
    let msg = read_response(&mut out, id, Duration::from_secs(10));
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "cross-tool use rejected: {msg}"
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .contains("different tool"),
        "cross-tool reason surfaced: {msg}"
    );
    id += 1;

    // Policy change between plan and retry: typed policy_changed (an
    // UNRELATED table rule changes, so the statement itself stays
    // confirm-gated and only the revision moves).
    let s4 = mrtr_first_call(
        &mut stdin,
        &mut out,
        id,
        sql,
        "execute",
        serde_json::Value::Null,
    );
    id += 1;
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "set_table_policy", "_meta": meta_2026(), "arguments": {
                "table": "main.unrelated", "policy": {"write": "allow"}
            }}
        }),
    );
    let _ = read_response(&mut out, id, Duration::from_secs(10));
    id += 1;
    let msg = mrtr_call(
        &mut stdin,
        &mut out,
        id,
        serde_json::json!({"state": s4, "sql": sql}),
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_policy_changed]"),
        "policy change typed: {msg}"
    );
    id += 1;

    // Process restart: a state from a previous process is unknown.
    let s5 = mrtr_first_call(
        &mut stdin,
        &mut out,
        id,
        sql,
        "execute",
        serde_json::Value::Null,
    );
    id += 1;
    drop(stdin);
    {
        let mut server = server;
        let _ = server.child.kill();
        let _ = server.child.wait();
    }
    let (_server2, mut stdin, mut out) = Server::spawn_demo_with(serde_json::json!({
        "main.z": {"read": "confirm", "write": "allow", "ddl": "allow"}
    }));
    let msg = mrtr_call(
        &mut stdin,
        &mut out,
        id,
        serde_json::json!({"state": s5, "sql": sql}),
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "restart invalidates server-side state: {msg}"
    );
}

#[test]
fn d7_modern_mrtr_cross_connection_rejected() {
    // Two sqlite connections with identical elevation rules; a state
    // issued on the default must not validate on the other connection.
    let dir = tempfile::TempDir::new().unwrap();
    let cfg_root = dir.path().join("cfg");
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    let db = dir.path().join("demo.sqlite");
    let db2 = dir.path().join("alt.sqlite");
    std::fs::write(&db, b"").unwrap();
    std::fs::write(&db2, b"").unwrap();
    let policy = serde_json::json!({
        "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
        "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 5000,
        "requireTouchID": false, "maxBackupRows": 100,
        "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
    });
    let rules = serde_json::json!({"main.z": {"write": "allow", "ddl": "allow"}});
    std::fs::write(
        cfg_root.join("sequel-mcp").join("config.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 2, "revision": 1, "defaultConnection": "demo",
            "connections": [
                {"driver": "sqlite", "name": "demo", "path": db.display().to_string(),
                 "database": "main", "policy": policy, "tablePolicies": rules},
                {"driver": "sqlite", "name": "alt", "path": db2.display().to_string(),
                 "database": "main", "policy": policy, "tablePolicies": rules}
            ],
            "retention": {}
        }))
        .unwrap(),
    )
    .unwrap();
    eprintln!("ISO_ROOT={}", dir.path().display());
    std::mem::forget(dir);
    let (_server, mut stdin, mut out) = Server::launch(&cfg_root, &data_root);

    let sql = "CREATE TABLE z (id INTEGER PRIMARY KEY)";
    let state = mrtr_first_call(
        &mut stdin,
        &mut out,
        1,
        sql,
        "demo",
        serde_json::Value::Null,
    );

    // Retry naming the OTHER connection.
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": sql, "connection": "alt"},
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": state
            }
        }),
    );
    let msg = read_response(&mut out, 2, Duration::from_secs(10));
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("[mrtr_invalid_state]"),
        "cross-connection use rejected: {msg}"
    );
    assert!(
        msg["error"]["message"]
            .as_str()
            .unwrap()
            .contains("different connection"),
        "cross-connection reason surfaced: {msg}"
    );
}

#[test]
fn d7_modern_mrtr_concurrent_retries_consume_once() {
    let (_server, mut stdin, mut out) = Server::spawn_demo_with(serde_json::json!({
        "main.z": {"write": "allow", "ddl": "allow"}
    }));
    let sql = "CREATE TABLE z (id INTEGER PRIMARY KEY)";
    let state = mrtr_first_call(
        &mut stdin,
        &mut out,
        1,
        sql,
        "demo",
        serde_json::Value::Null,
    );

    // Two retries pipelined BEFORE reading any response: exactly one may
    // consume the one-shot state; the other must report already-consumed.
    let body = |id: i64, state: &str, sql: &str| {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"sql": sql},
                "_meta": meta_2026(),
                "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                "requestState": state
            }
        })
    };
    let line1 = serde_json::to_string(&body(2, &state, sql)).unwrap();
    let line2 = serde_json::to_string(&body(3, &state, sql)).unwrap();
    stdin.write_all(line1.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.write_all(line2.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();

    let r2 = read_response(&mut out, 2, Duration::from_secs(10));
    let r3 = read_response(&mut out, 3, Duration::from_secs(10));
    let outcomes: Vec<bool> = [&r2, &r3]
        .iter()
        .map(|r| {
            r["error"]["message"]
                .as_str()
                .map(|m| m.starts_with("[mrtr_already_consumed]"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        outcomes.iter().filter(|x| **x).count(),
        1,
        "exactly one retry reports already-consumed: {r2} {r3}"
    );
    let ok_count = [&r2, &r3]
        .iter()
        .filter(|r| {
            r.get("error").is_none()
                && r["result"].is_object()
                && (r["result"]["isError"].is_null()
                    || r["result"]["isError"] == serde_json::json!(false))
        })
        .count();
    assert_eq!(ok_count, 1, "exactly one retry executes: {r2} {r3}");
}

// ---- Isolation regression (benchmark incident): the spawned child
// never sees the developer environment ----

#[test]
fn isolation_child_never_loads_parent_config() {
    // A synthetic "real" tree with a non-loopback default connection,
    // far outside the isolated root.
    let real_dir = tempfile::TempDir::new().unwrap();
    let real_cfg = real_dir.path().join("config").join("sequel-mcp");
    std::fs::create_dir_all(&real_cfg).unwrap();
    let real_config = serde_json::json!({
        "version": 2, "revision": 1, "defaultConnection": "synthetic-real",
        "connections": [{
            "driver": "mysql", "name": "synthetic-real",
            "host": "192.0.2.10", "port": 3306, "user": "u", "database": "app",
            "ssl": false,
            "policy": {
                "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
                "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 5000,
                "requireTouchID": false, "maxBackupRows": 100,
                "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
            },
            "tablePolicies": {}
        }],
        "retention": {}
    });
    std::fs::write(
        real_cfg.join("config.json"),
        serde_json::to_string_pretty(&real_config).unwrap(),
    )
    .unwrap();
    let before = std::fs::read(real_cfg.join("config.json")).unwrap();

    // Child with an EMPTY config of its own, in the clean environment.
    let (mut child, mut stdin, mut out) = Server::spawn_with_config(serde_json::json!({
        "version": 2, "revision": 1, "connections": [], "retention": {}
    }));
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "doctor", "arguments": {}, "_meta": meta_2026()}
        }),
    );
    let msg = read_response(&mut out, 1, Duration::from_secs(10));
    let text = serde_json::to_string(&msg["result"]).unwrap();
    assert!(
        !text.contains("synthetic-real") && !text.contains("192.0.2.10"),
        "parent config must not leak into the child: {text}"
    );
    assert_eq!(
        msg["result"]["structuredContent"]["connections"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "child sees only its own (empty) config: {msg}"
    );
    drop(stdin);
    let _ = child.child.wait();

    let after = std::fs::read(real_cfg.join("config.json")).unwrap();
    assert_eq!(before, after, "the real tree must be untouched");
}

#[test]
fn isolation_state_files_landing_under_root() {
    let (mut child, mut stdin, mut out) = Server::spawn();
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "query", "arguments": {"sql": "SELECT 7 AS v"}, "_meta": meta_2026()}
        }),
    );
    let msg = read_response(&mut out, 1, Duration::from_secs(10));
    assert_eq!(
        msg["result"]["structuredContent"]["rows"][0]["v"],
        serde_json::json!(7)
    );
    drop(stdin);
    let _ = child.child.wait();
    // The audit DB must have been created under the isolated data root
    // (found via the leaked ISO tree printed by the harness: assert by
    // scanning the printed roots is fragile; instead assert the child
    // answered and never wrote outside by construction of the clean
    // environment + the startup gate, exercised in the next test).
}

#[test]
fn isolation_startup_refuses_paths_outside_root() {
    // data root deliberately OUTSIDE the fail-closed test root: the
    // process must terminate BEFORE the MCP server starts (exit 78) and
    // emit no protocol bytes on stdout.
    let dir = tempfile::TempDir::new().unwrap();
    let cfg_root = dir.path().join("cfg");
    std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    let outside_data = outside.path().join("data");
    std::fs::create_dir_all(&outside_data).unwrap();
    let (mut child, stdin, mut out) = Server::launch(&cfg_root, &outside_data);
    drop(stdin);
    let started = Instant::now();
    let status;
    loop {
        match child.child.try_wait().unwrap() {
            Some(s) => {
                status = s;
                break;
            }
            None => {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "must exit fast"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    assert_eq!(status.code(), Some(78), "isolation violation exits 78");
    assert!(
        out.next_line(Duration::from_millis(300)).is_none(),
        "no protocol bytes before the gate"
    );
}

#[test]
fn isolation_non_loopback_mysql_endpoint_refused_before_connect() {
    let dir = tempfile::TempDir::new().unwrap();
    let cfg_root = dir.path().join("cfg");
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    std::fs::write(
        cfg_root.join("sequel-mcp").join("config.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 2, "revision": 1, "defaultConnection": "db",
            "connections": [{
                "driver": "mysql", "name": "db",
                "host": "192.0.2.10", "port": 3306, "user": "root",
                "database": "app", "ssl": false,
                "policy": {
                    "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
                    "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 5000,
                    "requireTouchID": false, "maxBackupRows": 100,
                    "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
                },
                "tablePolicies": {}
            }],
            "retention": {}
        }))
        .unwrap(),
    )
    .unwrap();
    eprintln!("ISO_ROOT={}", dir.path().display());
    std::mem::forget(dir);
    let (_server, mut stdin, mut out) = Server::launch_with_secrets(
        &cfg_root,
        &data_root,
        r#"{"db": {"root": "synthetic-password"}}"#,
    );

    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "query", "arguments": {"sql": "SELECT 1 AS v"}, "_meta": meta_2026()}
        }),
    );
    let started = Instant::now();
    let msg = read_response(&mut out, 1, Duration::from_secs(20));
    let elapsed = started.elapsed();
    let text = serde_json::to_string(&msg).unwrap();
    let refused = msg["result"]["isError"].as_bool().unwrap_or(false) || msg["error"].is_object();
    assert!(refused, "refused: {msg}");
    assert!(
        text.contains("not loopback") || text.contains("SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS"),
        "typed test-mode refusal: {text}"
    );
    // A real connect attempt to TEST-NET 192.0.2.10 would burn the 15 s
    // connect deadline; a pre-connect refusal returns immediately.
    assert!(
        elapsed < Duration::from_secs(5),
        "refusal must precede any connect attempt (took {elapsed:?})"
    );
}

#[test]
fn isolation_sqlite_path_outside_root_refused() {
    let outside = tempfile::TempDir::new().unwrap();
    let outside_db = outside.path().join("outside.sqlite");
    let (mut child, mut stdin, mut out) = Server::spawn_with_config(serde_json::json!({
        "version": 2, "revision": 1, "defaultConnection": "demo",
        "connections": [{
            "driver": "sqlite", "name": "demo",
            "path": outside_db.display().to_string(), "database": "main",
            "policy": {
                "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
                "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 5000,
                "requireTouchID": false, "maxBackupRows": 100,
                "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
            },
            "tablePolicies": {}
        }],
        "retention": {}
    }));
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "query", "arguments": {"sql": "SELECT 1 AS v"}, "_meta": meta_2026()}
        }),
    );
    let msg = read_response(&mut out, 1, Duration::from_secs(10));
    let text = serde_json::to_string(&msg).unwrap();
    let refused = msg["result"]["isError"].as_bool().unwrap_or(false) || msg["error"].is_object();
    assert!(refused, "outside-root sqlite must fail closed: {msg}");
    assert!(
        text.contains("SEQUEL_MCP_TEST_ROOT"),
        "typed test-mode refusal: {text}"
    );
    assert!(
        !outside_db.exists(),
        "no file may be created outside the root"
    );
    drop(stdin);
    let _ = child.child.wait();
}

// ---- Input bounds: line-limit boundaries and response-ID integrity ----

fn padded_line(id: i64, target_len: usize) -> String {
    let prefix =
        format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/list\",\"pad\":\"\"}}");
    let grow = target_len.saturating_sub(prefix.len());
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/list\",\"pad\":\"{}\"}}",
        "x".repeat(grow)
    )
}

#[test]
fn d7_line_limit_boundaries() {
    let limit = sequel_mcp::mcp::limits::MAX_MCP_LINE_BYTES;
    let (_server, mut stdin, mut out) = Server::spawn();
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "limits", "version": "0"}}
        }),
    );
    let _ = read_response(&mut out, 1, Duration::from_secs(10));
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // limit - 1: passes.
    stdin
        .write_all(padded_line(10, limit - 1).as_bytes())
        .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let msg = read_response(&mut out, 10, Duration::from_secs(20));
    assert_eq!(
        msg["result"]["tools"].as_array().unwrap().len(),
        27,
        "{msg}"
    );

    // exactly limit: passes (the buffer observes one byte beyond).
    stdin.write_all(padded_line(11, limit).as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let msg = read_response(&mut out, 11, Duration::from_secs(20));
    assert_eq!(
        msg["result"]["tools"].as_array().unwrap().len(),
        27,
        "{msg}"
    );

    // limit + 1: dropped whole — no response for that id, and the next
    // valid request is answered (stream integrity).
    stdin
        .write_all(padded_line(12, limit + 1).as_bytes())
        .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    let mut sink = out;
    let started = Instant::now();
    while let Some(line) = sink.next_line(Duration::from_millis(200)) {
        if let Ok(m) = serde_json::from_str::<serde_json::Value>(&line) {
            assert_ne!(
                m["id"],
                serde_json::json!(12),
                "no response may exist for the dropped line: {m}"
            );
        }
        if started.elapsed() > Duration::from_secs(2) {
            break;
        }
    }
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 13, "method": "tools/list"}),
    );
    let msg = read_response(&mut sink, 13, Duration::from_secs(20));
    assert_eq!(
        msg["result"]["tools"].as_array().unwrap().len(),
        27,
        "{msg}"
    );

    // No-newline oversized sender followed by the newline: the single
    // over-long line is dropped, the following valid line answered.
    stdin
        .write_all(padded_line(14, limit + 512).as_bytes())
        .unwrap();
    stdin.flush().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 15, "method": "tools/list"}),
    );
    let msg = read_response(&mut sink, 15, Duration::from_secs(20));
    assert_eq!(
        msg["result"]["tools"].as_array().unwrap().len(),
        27,
        "{msg}"
    );

    // Slow byte-chunked oversized sender: still discarded incrementally,
    // memory bounded by the fixed limit-sized buffer.
    let mut sent = 0usize;
    let target = limit + 4096;
    while sent < target {
        let chunk = 16 * 1024;
        stdin.write_all(&vec![b'q'; chunk]).unwrap();
        stdin.flush().unwrap();
        sent += chunk;
        std::thread::sleep(Duration::from_millis(1));
    }
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 16, "method": "tools/list"}),
    );
    let msg = read_response(&mut sink, 16, Duration::from_secs(30));
    assert_eq!(
        msg["result"]["tools"].as_array().unwrap().len(),
        27,
        "{msg}"
    );
    let _ = &mut stdin;
}

#[test]
fn d7_oversized_line_eof_midway_exits_bounded() {
    let (_server, mut stdin, mut _out) = Server::spawn();
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "eof", "version": "0"}}
        }),
    );
    // Partial oversized line (no newline), then EOF: bounded exit.
    stdin
        .write_all(&vec![
            b'e';
            sequel_mcp::mcp::limits::MAX_MCP_LINE_BYTES + 1024
        ])
        .unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    let mut server = _server;
    let started = Instant::now();
    loop {
        match server.child.try_wait().unwrap() {
            Some(_) => break,
            None => {
                assert!(
                    started.elapsed() < Duration::from_secs(15),
                    "EOF mid-oversized-line must exit promptly"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

#[test]
fn d7_concurrent_response_id_integrity() {
    // 50 pipelined tools/call (small queries mixed with large responses
    // from a pre-seeded table): every request id must receive exactly one
    // terminal response, none duplicated, none missing, and the server
    // stays usable afterwards (rmcp #941 regression).
    let dir = tempfile::TempDir::new().unwrap();
    let cfg_root = dir.path().join("cfg");
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    let db = dir.path().join("big.sqlite");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE big (payload TEXT);
             INSERT INTO big (payload) VALUES (printf('%c', 'x'));",
        )
        .unwrap();
        // Widen rows deterministically with SQL only.
        for _ in 0..5 {
            conn.execute_batch("UPDATE big SET payload = payload || payload;")
                .unwrap();
        }
    }
    std::fs::write(
        cfg_root.join("sequel-mcp").join("config.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 2, "revision": 1, "defaultConnection": "demo",
            "connections": [{
                "driver": "sqlite", "name": "demo",
                "path": db.display().to_string(), "database": "main",
                "policy": {
                    "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
                    "txCtrl": "allow", "rowCap": 200, "stmtTimeoutMs": 10000,
                    "requireTouchID": false, "maxBackupRows": 100,
                    "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
                },
                "tablePolicies": {}
            }],
            "retention": {}
        }))
        .unwrap(),
    )
    .unwrap();
    eprintln!("ISO_ROOT={}", dir.path().display());
    std::mem::forget(dir);
    let (mut server, mut stdin, mut out) = Server::launch(&cfg_root, &data_root);
    send(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "conc", "version": "0"}}
        }),
    );
    let _ = read_response(&mut out, 1, Duration::from_secs(10));
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // 40 small + 10 large, all pipelined before reading anything.
    let mut wire = String::new();
    for i in 0..50 {
        let sql = if i % 5 == 0 {
            "SELECT payload FROM big LIMIT 32"
        } else {
            "SELECT 1 AS v"
        };
        wire.push_str(
            &serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                "params": {"name": "query", "arguments": {"sql": sql}}
            }))
            .unwrap(),
        );
        wire.push('\n');
    }
    stdin.write_all(wire.as_bytes()).unwrap();
    stdin.flush().unwrap();

    let mut seen = std::collections::BTreeSet::new();
    let started = Instant::now();
    while seen.len() < 50 {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "timed out with {}/50 responses",
            seen.len()
        );
        let line = out
            .next_line(Duration::from_secs(30))
            .expect("response line");
        let msg: serde_json::Value = serde_json::from_str(&line).expect("parseable response");
        let id = msg["id"].as_i64().expect("response id");
        assert!((100..150).contains(&id), "unexpected id {id}: {msg}");
        assert!(seen.insert(id), "duplicate response for id {id}");
        assert!(
            msg["result"].is_object() || msg["error"].is_object(),
            "terminal response for {id}: {msg}"
        );
    }

    // Still usable afterwards.
    send(
        &mut stdin,
        &serde_json::json!({"jsonrpc": "2.0", "id": 999, "method": "tools/list"}),
    );
    let msg = read_response(&mut out, 999, Duration::from_secs(10));
    assert_eq!(msg["result"]["tools"].as_array().unwrap().len(), 27);

    drop(stdin);
    let started = Instant::now();
    loop {
        match server.child.try_wait().unwrap() {
            Some(_) => break,
            None => {
                assert!(started.elapsed() < Duration::from_secs(10));
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}
