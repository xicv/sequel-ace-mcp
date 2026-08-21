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
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Serve => serve(),
        Command::Doctor { json } => doctor(json),
    };
    std::process::exit(code);
}

fn serve() -> i32 {
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
        let server = sequel_mcp::mcp::SequelServer::with_defaults();
        match server.serve(rmcp::transport::stdio()).await {
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
