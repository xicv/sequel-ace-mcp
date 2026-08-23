//! Companion-side client for the approval IPC: the long-poll loop the
//! native GUI (and, in one-shot form, `sequel-mcp approve`) speaks.
//!
//! The server closes the connection after every exchange (`empty`, or an
//! ack to a reply), so a watching companion must reconnect and re-issue
//! `wait` forever. This module owns that loop:
//!
//! * connect → `{"op":"wait"}` → `request` | `empty` → id-bound reply →
//!   `ok` | `stale` | `bad-choice` → close → reconnect;
//! * connection loss is an EVENT, never a stop: the server may restart
//!   (its socket is re-created) and the loop must find it again;
//! * a choice is only consumed while a request is actually pending —
//! * the companion never fabricates answers and never auto-approves;
//!   with no UI input the server's own deadline fails the ask closed.

use crate::approval::GrantChoice;
use crate::approval::ipc::ApprovalRequest;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// How long a read may stall before the connection is considered dead.
/// Generous on purpose: the server legitimately holds a `wait` open for
/// its whole APPROVAL_IPC_TIMEOUT window (60 s) before answering
/// `empty`, so anything shorter would churn connections.
const READ_TIMEOUT: Duration = Duration::from_secs(75);

/// Write timeout: the protocol lines are tiny; anything slower is dead.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Reconnect backoff bounds after a connection failure.
const BACKOFF_START: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Max protocol line (mirrors the server's bound).
const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum CompanionEvent {
    /// TCP-style connect succeeded; `wait` is being sent.
    Connected { socket: PathBuf },
    /// `wait` delivered; no request yet in this window.
    Waiting,
    /// A confirmation request needs an answer.
    Request { request: ApprovalRequest },
    /// The server accepted the reply.
    Acked { id: String, choice: GrantChoice },
    /// The server rejected the reply: expired or answered elsewhere.
    Stale { id: String },
    /// The server rejected the choice string (protocol misuse).
    BadChoice { id: String },
    /// The window ended with nothing pending.
    Empty,
    /// Connection lost or never established; the loop continues.
    Disconnected { reason: String },
}

/// Handle side handed to the UI thread.
pub struct CompanionHandle {
    /// UI → companion: the choice for the currently pending request.
    /// `blocking_send` is safe from the (non-async) UI thread.
    pub choices: tokio::sync::mpsc::Sender<GrantChoice>,
    /// companion → UI events (drained with `try_recv` each frame).
    pub events: std::sync::mpsc::Receiver<CompanionEvent>,
}

/// Spawn the companion loop on the CURRENT tokio runtime (tests, or any
/// caller already inside a runtime).
pub fn spawn_companion(socket: PathBuf) -> CompanionHandle {
    let (event_tx, event_rx) = std::sync::mpsc::channel::<CompanionEvent>();
    let (choice_tx, choice_rx) = tokio::sync::mpsc::channel::<GrantChoice>(8);
    tokio::spawn(companion_loop(socket, event_tx, choice_rx));
    CompanionHandle {
        choices: choice_tx,
        events: event_rx,
    }
}

/// The reconnect loop, parameterized by its channels so the GUI thread
/// can create the channels outside its private runtime and keep the
/// receiving ends. Runs until the choice channel closes.
pub async fn companion_loop(
    socket: PathBuf,
    event_tx: std::sync::mpsc::Sender<CompanionEvent>,
    mut choice_rx: tokio::sync::mpsc::Receiver<GrantChoice>,
) {
    let mut backoff = BACKOFF_START;
    loop {
        match run_one_round(&socket, &event_tx, &mut choice_rx).await {
            RoundOutcome::SocketAlive => backoff = BACKOFF_START,
            RoundOutcome::SocketGone => {
                // Exponential backoff, capped: no busy-loop against a
                // missing server, but quick to notice a restart.
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, BACKOFF_MAX);
            }
            RoundOutcome::UiGone => break,
        }
    }
}

enum RoundOutcome {
    /// The round talked to a live server (even if it ended with `empty`
    /// or an ack): reconnect immediately — the next `wait` blocks server-
    /// side for up to the approval window, so this is not a busy loop.
    SocketAlive,
    /// Connect failed or the connection died mid-round: back off.
    SocketGone,
    /// The UI dropped its choice channel (window closed): stop the loop.
    UiGone,
}

async fn run_one_round(
    socket: &std::path::Path,
    event_tx: &std::sync::mpsc::Sender<CompanionEvent>,
    choice_rx: &mut tokio::sync::mpsc::Receiver<GrantChoice>,
) -> RoundOutcome {
    let stream = match UnixStream::connect(socket).await {
        Ok(stream) => stream,
        Err(e) => {
            let _ = event_tx.send(CompanionEvent::Disconnected {
                reason: format!("connect: {e}"),
            });
            return RoundOutcome::SocketGone;
        }
    };
    let _ = event_tx.send(CompanionEvent::Connected {
        socket: socket.to_path_buf(),
    });

    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    // Same first line the CLI sends; the server ignores the extra field.
    let hello = serde_json::json!({"op": "wait", "timeoutMs": 30000});
    if write_line(&mut wr, &hello).await.is_err() {
        let _ = event_tx.send(CompanionEvent::Disconnected {
            reason: "wait write failed".into(),
        });
        return RoundOutcome::SocketGone;
    }
    let _ = event_tx.send(CompanionEvent::Waiting);

    let line = match tokio::time::timeout(READ_TIMEOUT, read_line(&mut reader)).await {
        Ok(Some(line)) => line,
        Ok(None) | Err(_) => {
            let _ = event_tx.send(CompanionEvent::Disconnected {
                reason: "connection closed or timed out while waiting".into(),
            });
            return RoundOutcome::SocketGone;
        }
    };
    let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
        let _ = event_tx.send(CompanionEvent::Disconnected {
            reason: "malformed line from server".into(),
        });
        return RoundOutcome::SocketGone;
    };
    match msg["op"].as_str().unwrap_or("") {
        "empty" => {
            let _ = event_tx.send(CompanionEvent::Empty);
            // The server closes; the next round reconnects.
            return RoundOutcome::SocketAlive;
        }
        "request" => {}
        other => {
            let _ = event_tx.send(CompanionEvent::Disconnected {
                reason: format!("unexpected op {other:?}"),
            });
            return RoundOutcome::SocketGone;
        }
    }

    let Ok(request) = serde_json::from_value::<ApprovalRequest>(msg["request"].clone()) else {
        let _ = event_tx.send(CompanionEvent::Disconnected {
            reason: "unparseable request payload".into(),
        });
        return RoundOutcome::SocketGone;
    };
    let id = request.id.clone();
    let _ = event_tx.send(CompanionEvent::Request { request });

    // Wait for the UI's answer. No client-side deadline: if the user is
    // slow the SERVER expires the ask and our reply comes back `stale`.
    let Some(choice) = choice_rx.recv().await else {
        // UI dropped the channel (window closed): stop the loop.
        return RoundOutcome::UiGone;
    };
    let choice_str = match choice {
        GrantChoice::Once => "once",
        GrantChoice::Session => "session",
        GrantChoice::Decline => "decline",
    };
    let reply = serde_json::json!({"op": "reply", "id": id, "choice": choice_str});
    if write_line(&mut wr, &reply).await.is_err() {
        let _ = event_tx.send(CompanionEvent::Disconnected {
            reason: "reply write failed".into(),
        });
        return RoundOutcome::SocketGone;
    }
    let ack_line = match tokio::time::timeout(READ_TIMEOUT, read_line(&mut reader)).await {
        Ok(Some(line)) => line,
        _ => {
            let _ = event_tx.send(CompanionEvent::Disconnected {
                reason: "connection closed before ack".into(),
            });
            return RoundOutcome::SocketGone;
        }
    };
    let Ok(ack) = serde_json::from_str::<serde_json::Value>(&ack_line) else {
        let _ = event_tx.send(CompanionEvent::Disconnected {
            reason: "malformed ack".into(),
        });
        return RoundOutcome::SocketGone;
    };
    match ack["op"].as_str().unwrap_or("") {
        "ok" => {
            let _ = event_tx.send(CompanionEvent::Acked { id, choice });
        }
        "stale" => {
            let _ = event_tx.send(CompanionEvent::Stale { id });
        }
        _ => {
            let _ = event_tx.send(CompanionEvent::BadChoice { id });
        }
    }
    RoundOutcome::SocketAlive
}

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await.ok()?;
    let line = line.trim().to_string();
    if line.is_empty() || line.len() > MAX_LINE {
        return None;
    }
    Some(line)
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, async {
        stream
            .write_all(serde_json::to_string(value).unwrap_or_default().as_bytes())
            .await?;
        stream.write_all(b"\n").await?;
        stream.flush().await
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ConfirmOutcome;
    use crate::approval::ipc::ApprovalIpc;
    use std::sync::Arc;

    fn sample_request(id: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: id.into(),
            category: "write".into(),
            connection: "local-dev".into(),
            database: Some("app".into()),
            tables: vec!["app.users".into()],
            snippet: "UPDATE users SET name = 'x' WHERE id = 2".into(),
        }
    }

    /// Drain events until one matching `pred` arrives (bounded).
    async fn next_event(
        rx: &std::sync::mpsc::Receiver<CompanionEvent>,
        pred: impl Fn(&CompanionEvent) -> bool,
    ) -> CompanionEvent {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            while let Ok(event) = rx.try_recv() {
                if pred(&event) {
                    return event;
                }
            }
            assert!(Instant::now() < deadline, "timed out waiting for event");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    use std::time::Instant;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn companion_round_trip_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        let socket = ipc.socket_path().to_path_buf();
        let handle = spawn_companion(socket);

        let ask = tokio::spawn({
            let ipc = Arc::clone(&ipc);
            async move { ipc.ask(sample_request("r1")).await }
        });
        let event = next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Request { .. })
        })
        .await;
        let CompanionEvent::Request { request } = event else {
            unreachable!()
        };
        assert_eq!(request.id, "r1");
        assert_eq!(request.tables, vec!["app.users".to_string()]);
        handle.choices.send(GrantChoice::Once).await.unwrap();
        let ack = next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Acked { .. })
        })
        .await;
        assert_eq!(
            ack,
            CompanionEvent::Acked {
                id: "r1".into(),
                choice: GrantChoice::Once
            }
        );
        assert_eq!(
            ask.await.unwrap(),
            ConfirmOutcome::Chosen(GrantChoice::Once)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn companion_round_trip_decline() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        let handle = spawn_companion(ipc.socket_path().to_path_buf());

        let ask = tokio::spawn({
            let ipc = Arc::clone(&ipc);
            async move { ipc.ask(sample_request("r2")).await }
        });
        next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Request { .. })
        })
        .await;
        handle.choices.send(GrantChoice::Decline).await.unwrap();
        next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Acked { .. })
        })
        .await;
        assert_eq!(
            ask.await.unwrap(),
            ConfirmOutcome::Chosen(GrantChoice::Decline)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn companion_survives_server_restart() {
        // The GUI's whole job: keep watching across server death. Kill the
        // hub (socket unlinked), let the companion hit Disconnected, then
        // bring a NEW hub up at the same path and answer through it.
        let dir = tempfile::TempDir::new().unwrap();
        let socket = {
            let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
            ipc.socket_path().to_path_buf()
            // ipc dropped here: socket + session file removed.
        };
        let handle = spawn_companion(socket.clone());
        let gone = next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Disconnected { .. })
        })
        .await;
        let CompanionEvent::Disconnected { reason } = gone else {
            unreachable!()
        };
        assert!(!reason.is_empty());

        // Server comes back at the same path.
        let ipc2 = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(ipc2.socket_path(), socket.as_path());
        let ask = tokio::spawn({
            let ipc = Arc::clone(&ipc2);
            async move { ipc.ask(sample_request("r3")).await }
        });
        next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Request { .. })
        })
        .await;
        handle.choices.send(GrantChoice::Session).await.unwrap();
        next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Acked { .. })
        })
        .await;
        assert_eq!(
            ask.await.unwrap(),
            ConfirmOutcome::Chosen(GrantChoice::Session)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn companion_reports_missing_server() {
        let dir = tempfile::TempDir::new().unwrap();
        let handle = spawn_companion(dir.path().join("nope.sock"));
        // A Disconnected must arrive, and the loop must KEEP retrying:
        // if it had exited, no second event would ever come and the
        // bounded wait below would fail.
        next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Disconnected { .. })
        })
        .await;
        next_event(&handle.events, |e| {
            matches!(e, CompanionEvent::Disconnected { .. })
        })
        .await;
    }
}
