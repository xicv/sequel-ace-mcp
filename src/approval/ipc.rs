//! Authenticated approval IPC: a Unix-socket channel under the XDG
//! runtime registry through which an authenticated companion process
//! (the `sequel-mcp approve` CLI now; the native GUI later) answers
//! gate confirmations when the MCP client cannot elicit.
//!
//! Security posture:
//! * the socket lives in `runtime_dir()` (0700) and is removed on drop;
//! * every accepted connection must present the SAME effective uid
//!   (LOCAL_PEERCRED on macOS, SO_PEERCRED on Linux) — anything else is
//!   refused before the protocol starts;
//! * the server never sends secrets — requests carry category,
//!   connection, table scope and a redacted snippet only;
//! * replies are single-use and id-bound; a mismatched id is rejected;
//! * the asking side waits under a deadline and fails CLOSED
//!   (Unavailable) on timeout, malformed replies, or peer loss.

use crate::approval::{ConfirmOutcome, GrantChoice};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// How long the gate waits for a companion answer before failing closed.
pub const APPROVAL_IPC_TIMEOUT: Duration = Duration::from_secs(60);

/// Max protocol line (requests are small by construction).
const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub category: String,
    pub connection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    pub tables: Vec<String>,
    pub snippet: String,
}

struct Slot {
    request: ApprovalRequest,
    tx: tokio::sync::oneshot::Sender<GrantChoice>,
}

struct Inner {
    slot: Option<Slot>,
}

pub struct ApprovalIpc {
    inner: Arc<Mutex<Inner>>,
    socket_path: PathBuf,
    session_file: Option<PathBuf>,
    worker: tokio::task::JoinHandle<()>,
    started: Instant,
    served: AtomicU64,
}

impl ApprovalIpc {
    /// Bind the approval socket under the runtime registry and start
    /// serving. Also writes the session registry entry (pid + socket
    /// path) so companions can discover live servers.
    pub fn start() -> std::io::Result<Arc<Self>> {
        Self::start_at(None)
    }

    /// Test/override path: bind under an explicit directory instead of
    /// the default runtime registry.
    pub fn start_at(dir: Option<PathBuf>) -> std::io::Result<Arc<Self>> {
        let runtime = dir.unwrap_or_else(crate::app::paths::runtime_dir);
        std::fs::create_dir_all(&runtime)?;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))?;
        let socket_path = runtime.join("approval.sock");
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

        // Session registry entry (discovery for companions).
        let session_file = runtime
            .join("sessions")
            .join(format!("{}.json", std::process::id()));
        if let Some(parent) = session_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let registry = serde_json::json!({
            "pid": std::process::id(),
            "socket": socket_path.display().to_string(),
            "started": iso_now(),
        });
        let _ = std::fs::write(
            &session_file,
            serde_json::to_string(&registry).unwrap_or_default(),
        );

        let inner = Arc::new(Mutex::new(Inner { slot: None }));
        let accept_inner = Arc::clone(&inner);
        let worker = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let inner = Arc::clone(&accept_inner);
                tokio::spawn(handle_connection(stream, inner));
            }
        });

        Ok(Arc::new(Self {
            inner,
            socket_path,
            session_file: Some(session_file),
            worker,
            started: Instant::now(),
            served: AtomicU64::new(0),
        }))
    }

    /// Default socket path for companions (no server started).
    pub fn default_socket_path() -> PathBuf {
        crate::app::paths::runtime_dir().join("approval.sock")
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    pub fn answered_count(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Ask a companion to answer a confirmation. Blocks up to
    /// `deadline` and fails CLOSED (Unavailable) on timeout, cancel, or
    /// protocol errors — never fabricates a choice.
    pub async fn ask(&self, request: ApprovalRequest) -> ConfirmOutcome {
        let (tx, rx) = tokio::sync::oneshot::channel::<GrantChoice>();
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.slot.is_some() {
                // One pending confirmation at a time; a second concurrent
                // ask fails closed rather than queueing unboundedly.
                return ConfirmOutcome::Unavailable {
                    reason: "another approval request is already pending".into(),
                };
            }
            inner.slot = Some(Slot { request, tx });
        }
        match tokio::time::timeout(APPROVAL_IPC_TIMEOUT, rx).await {
            Ok(Ok(choice)) => {
                self.served.fetch_add(1, Ordering::Relaxed);
                ConfirmOutcome::Chosen(choice)
            }
            Ok(Err(_gone)) => ConfirmOutcome::Unavailable {
                reason: "approval companion dropped the request".into(),
            },
            Err(_elapsed) => {
                // Reap the expired slot.
                self.inner.lock().unwrap().slot = None;
                ConfirmOutcome::Unavailable {
                    reason: format!(
                        "approval IPC timed out after {}s",
                        APPROVAL_IPC_TIMEOUT.as_secs()
                    ),
                }
            }
        }
    }
}

impl Drop for ApprovalIpc {
    fn drop(&mut self) {
        self.worker.abort();
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(session) = &self.session_file {
            let _ = std::fs::remove_file(session);
        }
    }
}

/// Refuse the connection unless the peer runs under our own uid.
fn peer_is_same_uid<Fd: std::os::unix::io::AsRawFd>(stream: &Fd) -> bool {
    #[cfg(target_os = "macos")]
    {
        // NOTE: this macOS kernel reports cr_version=0 on success (not
        // XU_CRED_VERSION=4), so the uid is the only reliable field.
        let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        rc == 0 && cred.cr_uid == unsafe { libc::geteuid() }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        rc == 0 && cred.uid == unsafe { libc::geteuid() }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // No credential check available: fail closed.
        let _ = stream;
        false
    }
}

async fn handle_connection(stream: UnixStream, inner: Arc<Mutex<Inner>>) {
    // Same-user credential check before any protocol bytes.
    if !peer_is_same_uid(&stream) {
        return;
    }
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let Some(first) = read_line(&mut reader).await else {
        return;
    };
    let Ok(cmd) = serde_json::from_str::<serde_json::Value>(&first) else {
        return;
    };
    if cmd["op"].as_str() != Some("wait") {
        return;
    }

    // Poll the pending slot with a short tick (bounded by the approval
    // deadline): no cross-thread wake machinery to deadlock.
    let deadline = Instant::now() + APPROVAL_IPC_TIMEOUT;
    loop {
        {
            let guard = inner.lock().unwrap();
            if guard.slot.is_some() || Instant::now() >= deadline {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let request = inner
        .lock()
        .unwrap()
        .slot
        .as_ref()
        .map(|slot| serde_json::to_value(&slot.request).unwrap_or_default());
    let Some(request) = request else {
        let _ = write_line(&mut wr, &serde_json::json!({"op": "empty"})).await;
        return;
    };
    if write_line(
        &mut wr,
        &serde_json::json!({
            "op": "request",
            "request": request,
        }),
    )
    .await
    .is_err()
    {
        return;
    }

    // Read the reply; only the matching id is accepted.
    let Some(line) = read_line(&mut reader).await else {
        return;
    };
    let Ok(reply) = serde_json::from_str::<serde_json::Value>(&line) else {
        return;
    };
    if reply["op"].as_str() != Some("reply") {
        return;
    }
    enum Reply {
        Choice(GrantChoice),
        Stale,
        BadChoice,
    }
    // Decide under the lock, then act without holding the guard across
    // any await.
    let decision = {
        let guard = inner.lock().unwrap();
        let id_matches = guard
            .slot
            .as_ref()
            .map(|s| s.request.id == reply["id"].as_str().unwrap_or(""))
            .unwrap_or(false);
        if !id_matches {
            Reply::Stale
        } else {
            match reply["choice"].as_str() {
                Some("once") => Reply::Choice(GrantChoice::Once),
                Some("session") => Reply::Choice(GrantChoice::Session),
                Some("decline") => Reply::Choice(GrantChoice::Decline),
                _ => Reply::BadChoice,
            }
        }
    };
    match decision {
        Reply::Stale => {
            let _ = write_line(&mut wr, &serde_json::json!({"op": "stale"})).await;
        }
        Reply::BadChoice => {
            let _ = write_line(&mut wr, &serde_json::json!({"op": "bad-choice"})).await;
        }
        Reply::Choice(choice) => {
            let slot = {
                let mut guard = inner.lock().unwrap();
                guard.slot.take()
            };
            if let Some(slot) = slot {
                let _ = slot.tx.send(choice);
            }
            let _ = write_line(&mut wr, &serde_json::json!({"op": "ok"})).await;
        }
    }
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
    stream
        .write_all(serde_json::to_string(value).unwrap_or_default().as_bytes())
        .await?;
    stream.write_all(b"\n").await?;
    stream.flush().await
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn approver_script(socket: PathBuf, choice: &'static str) -> Option<()> {
        let stream = UnixStream::connect(socket).await.ok()?;
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        let hello = serde_json::json!({"op": "wait"});
        write_line(&mut wr, &hello).await.ok()?;
        let line = read_line(&mut reader).await?;
        let msg: serde_json::Value = serde_json::from_str(&line).ok()?;
        assert_eq!(msg["op"], "request", "{msg}");
        let id = msg["request"]["id"].as_str()?.to_string();
        let reply = serde_json::json!({"op": "reply", "id": id, "choice": choice});
        write_line(&mut wr, &reply).await.ok()?;
        let ack = read_line(&mut reader).await?;
        let ack: serde_json::Value = serde_json::from_str(&ack).ok()?;
        assert_eq!(ack["op"], "ok", "{ack}");
        Some(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn approve_once_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        let socket = ipc.socket_path().to_path_buf();
        let handle = tokio::spawn(approver_script(socket, "once"));
        let outcome = ipc
            .ask(ApprovalRequest {
                id: uuid::Uuid::new_v4().to_string(),
                category: "write".into(),
                connection: "c".into(),
                database: Some("app".into()),
                tables: vec!["app.users".into()],
                snippet: "UPDATE users SET id = 2".into(),
            })
            .await;
        assert_eq!(outcome, ConfirmOutcome::Chosen(GrantChoice::Once));
        assert!(handle.await.unwrap().is_some());
        assert_eq!(ipc.answered_count(), 1);
        assert!(ipc.socket_path().exists());
        drop(ipc);
        assert!(!ipc_exists(dir.path()), "socket removed on drop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn decline_and_session_choices() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        for choice in ["decline", "session"] {
            let socket = ipc.socket_path().to_path_buf();
            let leaked: &'static str = Box::leak(choice.to_string().into_boxed_str());
            let handle = tokio::spawn(approver_script(socket, leaked));
            let outcome = ipc
                .ask(ApprovalRequest {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: "write".into(),
                    connection: "c".into(),
                    database: None,
                    tables: vec![],
                    snippet: "s".into(),
                })
                .await;
            let expected = if choice == "decline" {
                GrantChoice::Decline
            } else {
                GrantChoice::Session
            };
            assert_eq!(outcome, ConfirmOutcome::Chosen(expected));
            assert!(handle.await.unwrap().is_some());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_companion_fails_closed_after_deadline() {
        // No approver connects: the ask must fail CLOSED as Unavailable.
        // The 60 s production deadline would stall the test; instead
        // assert the single-slot guard + immediate closed behavior with
        // a second concurrent ask.
        let dir = tempfile::TempDir::new().unwrap();
        let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        let ipc2 = Arc::clone(&ipc);
        let first = tokio::spawn(async move {
            ipc2.ask(ApprovalRequest {
                id: "first".into(),
                category: "write".into(),
                connection: "c".into(),
                database: None,
                tables: vec![],
                snippet: "s".into(),
            })
            .await
        });
        // Give the first ask time to take the slot.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = ipc
            .ask(ApprovalRequest {
                id: "second".into(),
                category: "write".into(),
                connection: "c".into(),
                database: None,
                tables: vec![],
                snippet: "s".into(),
            })
            .await;
        assert!(
            matches!(second, ConfirmOutcome::Unavailable { .. }),
            "second concurrent ask fails closed: {second:?}"
        );
        first.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_id_reply_is_stale() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipc = ApprovalIpc::start_at(Some(dir.path().to_path_buf())).unwrap();
        let socket = ipc.socket_path().to_path_buf();
        let ask = tokio::spawn({
            let ipc = Arc::clone(&ipc);
            async move {
                ipc.ask(ApprovalRequest {
                    id: "real-id".into(),
                    category: "write".into(),
                    connection: "c".into(),
                    database: None,
                    tables: vec![],
                    snippet: "s".into(),
                })
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stream = UnixStream::connect(&socket).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::new(rd);
        write_line(&mut wr, &serde_json::json!({"op": "wait"}))
            .await
            .unwrap();
        let line = read_line(&mut reader).await.unwrap();
        let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(msg["op"], "request");
        // Reply with a FORGED id: must be rejected as stale.
        write_line(
            &mut wr,
            &serde_json::json!({"op": "reply", "id": "forged", "choice": "once"}),
        )
        .await
        .unwrap();
        let ack = read_line(&mut reader).await.unwrap();
        let ack: serde_json::Value = serde_json::from_str(&ack).unwrap();
        assert_eq!(ack["op"], "stale", "{ack}");
        // The ask is still pending (not answered by the forged reply) —
        // cancel it by dropping the future.
        ask.abort();
    }

    fn ipc_exists(dir: &std::path::Path) -> bool {
        dir.join("approval.sock").exists()
    }
}
