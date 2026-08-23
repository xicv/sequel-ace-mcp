//! Native approvals GUI: an egui companion window that watches the
//! authenticated approval IPC socket and answers gate confirmations with
//! real human clicks. It reuses the `sequel-mcp approve` protocol
//! verbatim (`wait` → `request` → id-bound `reply` → `ok`/`stale`/
//! `bad-choice`, one round per connection, reconnect forever).
//!
//! Layout of this module:
//! * [`companion`] — the testable long-poll client loop (no UI);
//! * [`app`] — the plain-data view state + event reducer (no UI types);
//! * [`window`] — the thin egui layer rendering the state.
//!
//! Security posture (inherited from the IPC design): the GUI never sees
//! secrets, never auto-approves, and every failure path fails closed —
//! if the window is closed or the human is absent, the server's own
//! deadline refuses the statement.

pub mod app;
pub mod companion;
pub mod window;

use crate::approval::ipc::ApprovalIpc;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct GuiOptions {
    /// Approval socket to watch (default: the runtime registry socket).
    pub socket: PathBuf,
    /// Smoke-test support: close the window after N rendered frames.
    pub smoke_frames: Option<u32>,
}

/// Run the approvals window on the current (main) thread. Blocks until
/// the window is closed. Returns a process exit code.
pub fn run_gui(opts: GuiOptions) -> i32 {
    let socket = opts.socket.clone();
    let (event_tx, event_rx) = std::sync::mpsc::channel::<companion::CompanionEvent>();
    let (choice_tx, choice_rx) = tokio::sync::mpsc::channel::<crate::approval::GrantChoice>(8);
    let companion_thread = std::thread::Builder::new()
        .name("approval-companion".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(companion::companion_loop(socket, event_tx, choice_rx));
        });
    if companion_thread.is_err() {
        eprintln!("sequel-mcp gui: failed to start the companion thread");
        return 1;
    }

    let state = app::ViewState::new(opts.socket.clone());
    let smoke = opts.smoke_frames;
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([680.0, 620.0])
            .with_title("sequel-mcp approvals"),
        ..Default::default()
    };
    match eframe::run_native(
        "sequel-mcp approvals",
        native_options,
        Box::new(move |_cc| {
            Ok(Box::new(window::ApprovalsApp::new(
                state, choice_tx, event_rx, smoke,
            )))
        }),
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sequel-mcp gui: window creation failed: {e}");
            1
        }
    }
}

/// One live (or recently recorded) server from the session registry.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionInfo {
    pub pid: u32,
    pub socket: String,
    pub started: String,
    pub alive: bool,
}

/// Discover servers registered under the default runtime registry.
/// Informational only — the window watches ONE socket (the registry
/// path); this list tells the human which servers are alive.
pub fn live_sessions() -> Vec<SessionInfo> {
    live_sessions_at(&crate::app::paths::runtime_dir().join("sessions"))
}

pub fn live_sessions_at(dir: &std::path::Path) -> Vec<SessionInfo> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(pid) = value["pid"].as_u64() else {
            continue;
        };
        out.push(SessionInfo {
            pid: u32::try_from(pid).unwrap_or(0),
            socket: value["socket"].as_str().unwrap_or("").to_string(),
            started: value["started"].as_str().unwrap_or("").to_string(),
            alive: pid_alive(pid),
        });
    }
    out.sort_by(|a, b| b.started.cmp(&a.started));
    out
}

fn pid_alive(pid: u64) -> bool {
    if pid == 0 {
        return false;
    }
    // Signal 0 is a pure existence probe; nothing is delivered.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Default socket for the CLI wiring (kept next to the GUI for symmetry
/// with `approve`).
pub fn default_socket() -> PathBuf {
    ApprovalIpc::default_socket_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_sessions_parses_and_flags_liveness() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        // A live server: this test process itself.
        std::fs::write(
            sessions.join("100.json"),
            serde_json::json!({
                "pid": std::process::id(),
                "socket": "/runtime/approval.sock",
                "started": "2026-08-23T01:00:00Z",
            })
            .to_string(),
        )
        .unwrap();
        // A dead server: pid far above any real pid on this machine.
        std::fs::write(
            sessions.join("200.json"),
            serde_json::json!({
                "pid": 4_000_000u64,
                "socket": "/runtime/approval.sock",
                "started": "2026-08-23T02:00:00Z",
            })
            .to_string(),
        )
        .unwrap();
        // Garbage and non-json neighbors must be ignored.
        std::fs::write(sessions.join("300.json"), "not json").unwrap();
        std::fs::write(sessions.join("readme.txt"), "hello").unwrap();

        let found = live_sessions_at(&sessions);
        assert_eq!(found.len(), 2, "{found:?}");
        // Most recent `started` first.
        assert_eq!(found[0].pid, 4_000_000);
        assert!(!found[0].alive, "pid 4000000 must read as dead");
        assert_eq!(found[1].pid, std::process::id());
        assert!(found[1].alive, "own pid must read as alive");
        assert_eq!(found[1].socket, "/runtime/approval.sock");
    }

    #[test]
    fn live_sessions_missing_dir_is_empty() {
        assert!(live_sessions_at(std::path::Path::new("/nonexistent/nowhere")).is_empty());
    }
}
