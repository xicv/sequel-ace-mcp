//! `sequel-mcp` binary: CLI subcommands + MCP stdio server.

use clap::{Parser, Subcommand};
use sequel_mcp::config::ConfigStore;

#[derive(Parser)]
#[command(
    name = "sequel-mcp",
    version = sequel_mcp::PACKAGE_VERSION,
    about = "Local-first, policy-gated MySQL/MariaDB and SQLite access for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve MCP over stdio (the primary transport).
    Serve,
    /// Sanitized diagnostics for the local install.
    Doctor {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Answer a pending approval request from a running server
    /// (authenticated same-user IPC over the runtime socket).
    Approve {
        /// Socket path override (default: the runtime registry socket).
        #[arg(long)]
        socket: Option<String>,
        /// Non-interactive choice: once | session | decline.
        #[arg(long)]
        choice: Option<String>,
    },
    /// Native approvals companion window: watches the runtime socket and
    /// answers the server's confirmations with real clicks.
    Gui {
        /// Socket path override (default: the runtime registry socket).
        #[arg(long)]
        socket: Option<String>,
        /// Smoke test: close the window after N rendered frames.
        #[arg(long, hide = true)]
        smoke: Option<u32>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Serve => serve(),
        Command::Doctor { json } => doctor(json),
        Command::Approve { socket, choice } => approve(socket, choice),
        Command::Gui { socket, smoke } => sequel_mcp::gui::run_gui(sequel_mcp::gui::GuiOptions {
            socket: socket
                .map(std::path::PathBuf::from)
                .unwrap_or_else(sequel_mcp::gui::default_socket),
            smoke_frames: smoke,
        }),
    };
    std::process::exit(code);
}

fn serve() -> i32 {
    // Fail-closed test-mode isolation check BEFORE anything else: if
    // SEQUEL_MCP_TEST_MODE=1 is set, every derived path must live under
    // SEQUEL_MCP_TEST_ROOT or the process terminates without starting
    // the MCP server.
    if let Err(e) = sequel_mcp::app::test_mode::verify_startup() {
        eprintln!("sequel-mcp: refusing to start (test mode): {e}");
        return sequel_mcp::app::test_mode::EXIT_ISOLATION;
    }
    if sequel_mcp::app::test_mode::is_active()
        && let Ok(root) = std::env::var("SEQUEL_MCP_TEST_ROOT")
    {
        eprintln!("sequel-mcp: test mode active, isolated root {root}");
    }

    // Logs to stderr only; stdout belongs to the protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sequel-mcp: failed to start runtime: {e}");
            return 1;
        }
    };

    rt.block_on(async {
        use rmcp::ServiceExt;
        let server = sequel_mcp::mcp::SequelServer::with_approval_ipc();
        // Bounded stdio: stdin passes through the line-limit adapter so an
        // oversized JSON-RPC line is discarded before it is ever buffered.
        match server.serve(sequel_mcp::mcp::limits::limited_stdio()).await {
            Ok(service) => {
                eprintln!("sequel-mcp ready");
                if let Err(e) = service.waiting().await {
                    eprintln!("sequel-mcp: service error: {e}");
                    return 1;
                }
                0
            }
            Err(e) => {
                eprintln!("sequel-mcp: serve failed: {e}");
                1
            }
        }
    })
}

fn doctor(json: bool) -> i32 {
    let store = ConfigStore::new();
    let cfg = match store.load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("sequel-mcp doctor: config load failed: {e}");
            return 1;
        }
    };
    if json {
        let report = serde_json::json!({
            "app": sequel_mcp::PACKAGE_NAME,
            "version": sequel_mcp::PACKAGE_VERSION,
            "configPath": store.path().display().to_string(),
            "configVersion": cfg.version,
            "configRevision": cfg.revision,
            "connectionCount": cfg.connections.len(),
            "defaultConnection": cfg.default_connection,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        println!(
            "{} v{}",
            sequel_mcp::PACKAGE_NAME,
            sequel_mcp::PACKAGE_VERSION
        );
        println!(
            "config : {} (v{}, revision {})",
            store.path().display(),
            cfg.version,
            cfg.revision
        );
        println!(
            "connections: {} (default: {})",
            cfg.connections.len(),
            cfg.default_connection.as_deref().unwrap_or("(none)")
        );
    }
    0
}

fn approve(socket: Option<String>, choice: Option<String>) -> i32 {
    use std::io::BufRead;
    let path = socket
        .map(std::path::PathBuf::from)
        .unwrap_or_else(sequel_mcp::approval::ipc::ApprovalIpc::default_socket_path);
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&path) else {
        eprintln!(
            "sequel-mcp approve: no server at {} (is a server running?)",
            path.display()
        );
        return 1;
    };
    fn say(stream: &mut std::os::unix::net::UnixStream, v: &serde_json::Value) {
        use std::io::Write;
        let _ = stream.write_all(serde_json::to_string(v).unwrap_or_default().as_bytes());
        let _ = stream.write_all(b"\n");
        let _ = stream.flush();
    }
    fn read(stream: &std::os::unix::net::UnixStream) -> Option<String> {
        let mut reader = std::io::BufReader::new(stream.try_clone().ok()?);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim().to_string();
        if line.is_empty() { None } else { Some(line) }
    }
    say(
        &mut stream,
        &serde_json::json!({"op": "wait", "timeoutMs": 30000}),
    );
    let Some(line) = read(&stream) else {
        eprintln!("sequel-mcp approve: connection closed before a request arrived");
        return 1;
    };
    let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
        eprintln!("sequel-mcp approve: malformed reply from server");
        return 1;
    };
    if msg["op"] == "empty" {
        eprintln!("sequel-mcp approve: no pending approval (timed out waiting)");
        return 1;
    }
    if msg["op"] != "request" {
        eprintln!("sequel-mcp approve: unexpected reply: {msg}");
        return 1;
    }
    let req = &msg["request"];
    println!("pending approval");
    println!("  category  : {}", req["category"].as_str().unwrap_or("?"));
    println!(
        "  connection: {}",
        req["connection"].as_str().unwrap_or("?")
    );
    if let Some(db) = req["database"].as_str() {
        println!("  database  : {db}");
    }
    let tables: Vec<&str> = req["tables"]
        .as_array()
        .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
        .unwrap_or_default();
    if !tables.is_empty() {
        println!("  tables    : {}", tables.join(", "));
    }
    println!("  statement :");
    for line_text in req["snippet"].as_str().unwrap_or("").lines() {
        println!("    {line_text}");
    }
    let choice = match choice.as_deref() {
        Some(c @ ("once" | "session" | "decline")) => c.to_string(),
        Some(other) => {
            eprintln!("sequel-mcp approve: invalid --choice {other:?} (once|session|decline)");
            return 2;
        }
        None => loop {
            println!("authorize? [once/session/decline]");
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() {
                return 1;
            }
            match input.trim() {
                "once" | "session" | "decline" => break input.trim().to_string(),
                "" => {
                    eprintln!("sequel-mcp approve: EOF — treating as decline");
                    break "decline".to_string();
                }
                _ => continue,
            }
        },
    };
    say(
        &mut stream,
        &serde_json::json!({
            "op": "reply",
            "id": req["id"],
            "choice": choice,
        }),
    );
    match read(&stream)
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
    {
        Some(Ok(ack)) if ack["op"] == "ok" => {
            println!("recorded: {choice}");
            0
        }
        Some(Ok(ack)) => {
            eprintln!("sequel-mcp approve: server rejected the reply: {ack}");
            1
        }
        _ => {
            eprintln!("sequel-mcp approve: no acknowledgement from server");
            1
        }
    }
}
