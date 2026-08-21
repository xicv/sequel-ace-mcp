//! D7: deterministic process-level MCP lifecycle tests against the real
//! built binary — legacy initialization, tools/list, a gated SQLite
//! execute (denied) and query round trip, malformed + oversized requests,
//! stdin EOF during an in-flight request, and clean exit. Every read is
//! deadline-driven; no fixed sleeps as a pass criterion.

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
    fn spawn() -> (Server, std::process::ChildStdin, LineReceiver) {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg_root = dir.path().join("cfg");
        let data_root = dir.path().join("data");
        std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
        // Read-only SQLite handles require the file to exist.
        std::fs::write(dir.path().join("demo.sqlite"), b"").unwrap();
        std::fs::write(
            cfg_root.join("sequel-mcp").join("config.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 2,
                "revision": 1,
                "defaultConnection": "demo",
                "connections": [{
                    "driver": "sqlite",
                    "name": "demo",
                    "path": dir.path().join("demo.sqlite").display().to_string(),
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
            }))
            .unwrap(),
        )
        .unwrap();
        std::mem::forget(dir);

        let mut child = Command::new(bin_path())
            .arg("serve")
            .env("XDG_CONFIG_HOME", &cfg_root)
            .env("XDG_DATA_HOME", &data_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary spawns");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
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

fn send(stdin: &mut impl Write, value: &serde_json::Value) {
    stdin
        .write_all(serde_json::to_string(value).unwrap().as_bytes())
        .unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

/// Channel-fed line reader: an OS thread blocks on the pipe so the main
/// thread can enforce real deadlines (a blocking read on the pipe cannot).
struct LineReceiver {
    rx: std::sync::mpsc::Receiver<String>,
    eof_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LineReceiver {
    fn from_reader<R: Read + Send + 'static>(inner: R) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let eof_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let eof_writer = std::sync::Arc::clone(&eof_flag);
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
            eof_writer.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        Self { rx, eof_flag }
    }

    fn eof_reached(&self) -> bool {
        self.eof_flag.load(std::sync::atomic::Ordering::SeqCst)
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
    let started = Instant::now();
    while started.elapsed() < deadline {
        if let Some(line) = out.next_line(deadline) {
            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line)
                && msg["id"] == want_id {
                    return msg;
                }
            continue;
        }
        break;
    }
    panic!("no response for id {want_id} within {deadline:?}");
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
    assert_eq!(tools.len(), 21, "tool count");
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

    // --- Malformed request: rmcp's stdio transport silently drops
    // unparseable lines (no JSON-RPC parse-error frame). The acceptance
    // contract is survival + stream integrity: the very next valid
    // request must be answered correctly.
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
            .map(|t| t.len() == 21)
            .unwrap_or(false),
        "server must keep answering after malformed input: {msg}"
    );

    // --- Oversized request (~2 MiB): no protocol corruption; the server
    // either answers a follow-up or closes cleanly.
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
    let started = Instant::now();
    let mut answered = false;
    'outer: while started.elapsed() < Duration::from_secs(10) {
        if let Some(line) = out.next_line(Duration::from_secs(10)) {
            if let Ok(m) = serde_json::from_str::<serde_json::Value>(&line)
                && m["id"] == 6 {
                    answered = true;
                    break 'outer;
                }
        } else {
            break;
        }
    }
    assert!(
        answered || out.eof_reached(),
        "server must answer or close cleanly after oversized input"
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
