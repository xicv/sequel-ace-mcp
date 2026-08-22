//! SSH direct-tunnel transport (russh port of the legacy tunnel runtime).
//!
//! Topology per connection: `mysql_async` always connects to a LOCAL
//! loopback endpoint; every local TCP connection is bridged onto a fresh
//! `direct_tcpip` channel of ONE multiplexed SSH session to the bastion,
//! which forwards to the MySQL host/port as seen FROM the bastion.
//! Host keys are verified against known_hosts through the strict/lenient
//! policy engine — mismatches and revoked keys are rejected in every
//! mode; only genuinely unknown hosts may be accepted under lenient.
//!
//! Hardening (#4A): concurrent first users of the same tunnel coalesce
//! on ONE establishment; every tunnel carries a monotonic GENERATION
//! that also keys the MySQL pool, so a reused loopback port can never
//! splice an old pool onto a new transport (ABA); retirement follows a
//! fixed order (drain → evict pools → stop listener → wind down channel
//! tasks → disconnect the session); the cache is LRU and bounded;
//! keepalive is tunable for half-open detection; the tunnel cache key
//! binds the config revision, the SSH credential generation, and the
//! known_hosts content, so rotating any of them invalidates the cached
//! session. Test-mode rules apply to the bastion endpoint before any
//! socket is opened.

use crate::config::{SshAuthMethod, SshHostKeyPolicy, SshTunnel};
use crate::sql::known_hosts;
use russh::client::{self, Handle};
use russh::keys::PublicKeyBase64;
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Deadline for establishing the SSH session (connect + KEX + auth).
pub const SSH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Deadline for opening a single forwarded channel (a stale/half-open
/// session must fail the local connection promptly, not hang it).
pub const CHANNEL_OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum distinct tunnels kept in the process-wide cache (LRU).
pub const MAX_TUNNELS: usize = 8;

/// Keepalive interval. Default 30 s; tunable (1..=300) via
/// `SEQUEL_MCP_SSH_KEEPALIVE_SECS` — an operational knob that also lets
/// the half-open tests run with a realistic detection budget.
pub fn keepalive_interval() -> std::time::Duration {
    let secs = std::env::var("SEQUEL_MCP_SSH_KEEPALIVE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 300);
    std::time::Duration::from_secs(secs)
}

#[derive(Debug, Error)]
pub enum SshError {
    #[error("{0}")]
    Transport(String),
    #[error("authentication as {user:?} failed on {host}:{port}")]
    Auth {
        host: String,
        port: u16,
        user: String,
    },
    #[error("host key rejected for {host}:{port}: {reason}")]
    HostKey {
        host: String,
        port: u16,
        reason: String,
    },
    #[error("tunnel setup: {0}")]
    Setup(String),
}

/// `russh` client handler whose only job is host-key verification via
/// the ported known_hosts engine (strict = fail closed; lenient accepts
/// ONLY genuinely unknown hosts — mismatches and revoked keys are
/// rejected in every mode).
struct HostKeyHandler {
    policy: SshHostKeyPolicy,
    entries: Vec<known_hosts::KnownHostEntry>,
    host: String,
    port: u16,
    logs: Mutex<Vec<String>>,
}

impl client::Handler for HostKeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let raw = server_public_key.public_key_bytes();
        let mut logs: Vec<String> = Vec::new();
        let decision = known_hosts::decide_host_key(
            self.policy,
            &self.host,
            self.port,
            &self.entries,
            &raw,
            &mut |line| logs.push(line),
        );
        self.logs.lock().unwrap().extend(logs);
        Ok(decision == known_hosts::HostKeyDecision::Accept)
    }
}

/// A lease on a tunnel: the loopback endpoint for `mysql_async` plus the
/// transport GENERATION. The generation participates in the MySQL pool
/// key, so a pool can never outlive its tunnel and get spliced onto a
/// later transport that reuses the same ephemeral port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelLease {
    pub host: String,
    pub port: u16,
    pub generation: u64,
}

struct TunnelEntry {
    /// Local loopback listener address handed to `mysql_async`.
    local: std::net::SocketAddr,
    /// Multiplexed SSH session; channels are opened per TCP connection.
    handle: Arc<Handle<HostKeyHandler>>,
    /// Sender whose message ends the accept-loop task.
    shutdown: mpsc::Sender<()>,
    generation: u64,
    /// Set on retirement: the accept loop stops taking new connections.
    draining: Arc<AtomicBool>,
    last_used: Mutex<std::time::Instant>,
    /// Live forwarder tasks (diagnostics + test assertions).
    live_tasks: Arc<AtomicU64>,
}

impl TunnelEntry {
    fn is_dead(&self) -> bool {
        self.handle.is_closed()
    }
    fn touch(&self) {
        *self.last_used.lock().unwrap() = std::time::Instant::now();
    }
}

struct Tunnels {
    map: HashMap<String, Arc<TunnelEntry>>,
    next_generation: u64,
    /// Per-key async guards so concurrent first users coalesce on ONE
    /// establishment instead of racing N SSH sessions.
    inflight: HashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

static TUNNELS: OnceLock<Mutex<Tunnels>> = OnceLock::new();

fn tunnels() -> &'static Mutex<Tunnels> {
    TUNNELS.get_or_init(|| {
        Mutex::new(Tunnels {
            map: HashMap::new(),
            next_generation: 1,
            inflight: HashMap::new(),
        })
    })
}

/// Number of live tunnels (diagnostics/tests).
pub fn tunnel_count() -> usize {
    tunnels().lock().unwrap().map.len()
}

/// Connection-name fragments of the live tunnel keys (LRU tests).
pub fn tunnel_connection_names() -> Vec<String> {
    tunnels()
        .lock()
        .unwrap()
        .map
        .keys()
        .map(|k| k.split('\u{1}').next().unwrap_or("").to_string())
        .collect()
}

/// Live forwarder tasks across all tunnels (drain assertions).
pub fn tunnel_live_tasks() -> u64 {
    tunnels()
        .lock()
        .unwrap()
        .map
        .values()
        .map(|e| e.live_tasks.load(Ordering::Relaxed))
        .sum()
}

/// Drop every cached tunnel and retire each one in order (tests).
pub fn invalidate_all() {
    let entries: Vec<Arc<TunnelEntry>> = {
        let mut state = tunnels().lock().unwrap();
        state.map.drain().map(|(_, e)| e).collect()
    };
    for entry in entries {
        retire(&entry);
    }
}

/// Retire one tunnel in the fixed order: mark draining (no new channel
/// creation) → evict the MySQL pools keyed to this generation → stop
/// the listener → let channel tasks wind down → disconnect the SSH
/// session.
fn retire(entry: &TunnelEntry) {
    entry.draining.store(true, Ordering::SeqCst);
    let evicted = super::pool::evict_by_generation(entry.generation);
    if evicted > 0 {
        eprintln!(
            "[sequel-mcp] ssh tunnel gen {}: evicted {evicted} associated MySQL pool(s)",
            entry.generation
        );
    }
    let _ = entry.shutdown.try_send(());
    // Disconnect the SSH session; outstanding channel copies error out
    // and their tasks finish. Fire-and-forget with a bounded handle.
    let handle = Arc::clone(&entry.handle);
    tokio::spawn(async move {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "tunnel retired", "en")
            .await;
    });
}

impl SshTunnel {
    fn auth_method_label(&self) -> &'static str {
        match self.auth_method {
            SshAuthMethod::Password => "password",
            SshAuthMethod::Key => "key",
        }
    }
}

/// 16-hex-char content stamp of the known_hosts file (empty string when
/// no explicit file is configured — the default path's absence is not a
/// distinguishing identity).
fn known_hosts_stamp(path: Option<&std::path::Path>) -> String {
    let Some(path) = path else {
        return String::new();
    };
    let mut h = sha2::Sha256::new();
    match std::fs::read(path) {
        Ok(bytes) => h.update(&bytes),
        // Unreadable files fail closed in the checked loader; the stamp
        // only needs to be deterministic per file identity.
        Err(_) => h.update(format!("unreadable:{}", path.display())),
    }
    format!(
        "{:016x}",
        u64::from_be_bytes(h.finalize()[..8].try_into().expect("8 bytes"))
    )
}

/// In-process credential generation for the SSH secret (never the
/// secret itself): a process-keyed HMAC digest, hex-encoded for keying.
fn ssh_credential_fragment(ssh_password: Option<&str>) -> String {
    let cred = super::pool::CredentialGeneration::derive(ssh_password.unwrap_or(""));
    cred.key_fragment()
}

#[allow(clippy::too_many_arguments)]
fn tunnel_key(
    conn_name: &str,
    ssh: &SshTunnel,
    ssh_password: Option<&str>,
    target: &str,
    port: u16,
    policy_revision: u64,
    kh_stamp: &str,
) -> String {
    let target_endpoint = format!("{target}:{port}");
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
        conn_name,
        ssh.host,
        ssh.port,
        ssh.user,
        ssh.auth_method_label(),
        kh_stamp,
        ssh_credential_fragment(ssh_password),
        policy_revision,
        target_endpoint
    )
}

/// Return a lease on a (reused or freshly established) SSH tunnel for
/// `conn_name`'s SSH config, forwarding to `target_host:target_port` as
/// reachable from the bastion. Concurrent first callers coalesce on one
/// establishment. The lease's generation MUST be carried into the MySQL
/// pool key (`verified_pool(.., tunnel_generation)`).
pub async fn tunnel_endpoint(
    conn_name: &str,
    ssh: &SshTunnel,
    ssh_password: Option<&str>,
    target_host: &str,
    target_port: u16,
    policy_revision: u64,
) -> Result<TunnelLease, SshError> {
    // Fail-closed test-mode gate on the BASTION endpoint before any
    // socket is opened (docker bastions publish on loopback).
    crate::app::test_mode::check_mysql_endpoint(&ssh.host, ssh.port).map_err(SshError::Setup)?;

    let kh_path = ssh.known_hosts_path.as_deref().map(std::path::Path::new);
    let kh_stamp = known_hosts_stamp(kh_path);
    let key = tunnel_key(
        conn_name,
        ssh,
        ssh_password,
        target_host,
        target_port,
        policy_revision,
        &kh_stamp,
    );

    // Fast path: a live tunnel for exactly this identity.
    {
        let state = tunnels().lock().unwrap();
        if let Some(entry) = state.map.get(&key)
            && !entry.is_dead()
            && !entry.draining.load(Ordering::SeqCst)
        {
            entry.touch();
            return Ok(TunnelLease {
                host: "127.0.0.1".into(),
                port: entry.local.port(),
                generation: entry.generation,
            });
        }
    }

    // Coalescing: one establishment per key even under a thundering
    // herd — everyone serializes on the per-key guard, and waits find
    // the winner's entry on the double-check.
    let guard = {
        let mut state = tunnels().lock().unwrap();
        Arc::clone(state.inflight.entry(key.clone()).or_default())
    };
    let _hold = guard.lock().await;

    {
        let state = tunnels().lock().unwrap();
        if let Some(entry) = state.map.get(&key)
            && !entry.is_dead()
            && !entry.draining.load(Ordering::SeqCst)
        {
            entry.touch();
            return Ok(TunnelLease {
                host: "127.0.0.1".into(),
                port: entry.local.port(),
                generation: entry.generation,
            });
        }
    }

    let entry = establish(ssh, ssh_password, target_host, target_port).await?;

    let mut state = tunnels().lock().unwrap();
    state.inflight.remove(&key);
    // Retire stale tunnels of the SAME connection (identity rotation:
    // credential, known_hosts content, or policy revision changed).
    let conn_prefix = format!("{conn_name}\u{1}");
    let stale: Vec<String> = state
        .map
        .keys()
        .filter(|k| k.as_str() != key.as_str() && k.starts_with(&conn_prefix))
        .cloned()
        .collect();
    for k in stale {
        if let Some(e) = state.map.remove(&k) {
            retire(&e);
        }
    }
    // Drop dead entries; enforce the LRU bound by retiring the
    // least-recently-used victims.
    let dead: Vec<String> = state
        .map
        .iter()
        .filter(|(_, e)| e.is_dead())
        .map(|(k, _)| k.clone())
        .collect();
    for k in dead {
        if let Some(e) = state.map.remove(&k) {
            retire(&e);
        }
    }
    while state.map.len() >= MAX_TUNNELS {
        let victim = state
            .map
            .iter()
            .min_by_key(|(_, e)| *e.last_used.lock().unwrap())
            .map(|(k, _)| k.clone());
        let Some(victim) = victim else { break };
        if let Some(e) = state.map.remove(&victim) {
            eprintln!(
                "[sequel-mcp] ssh tunnel cache full ({}); retiring LRU entry",
                MAX_TUNNELS
            );
            retire(&e);
        }
    }
    let generation = entry.generation;
    let port = entry.local.port();
    state.map.insert(key, entry);
    Ok(TunnelLease {
        host: "127.0.0.1".into(),
        port,
        generation,
    })
}

async fn establish(
    ssh: &SshTunnel,
    ssh_password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<Arc<TunnelEntry>, SshError> {
    let kh_path = ssh.known_hosts_path.as_deref().map(std::path::Path::new);
    let entries =
        known_hosts::load_known_hosts_checked(kh_path).map_err(|e| SshError::HostKey {
            host: ssh.host.clone(),
            port: ssh.port,
            reason: e,
        })?;
    let handler = HostKeyHandler {
        policy: ssh.host_key_policy.unwrap_or(SshHostKeyPolicy::Lenient),
        entries,
        host: ssh.host.clone(),
        port: ssh.port,
        logs: Mutex::new(Vec::new()),
    };

    let keepalive = keepalive_interval();
    let config = Arc::new(client::Config {
        keepalive_interval: Some(keepalive),
        keepalive_max: 3,
        nodelay: true,
        ..client::Config::default()
    });

    let addr = (ssh.host.as_str(), ssh.port);
    let session = async {
        let mut handle = client::connect(config, addr, handler)
            .await
            .map_err(|e| SshError::Transport(format!("connect to bastion: {e}")))?;
        // Authenticate with EXACTLY the configured method — no silent
        // fallback between password and key. The secret doubles as the
        // private-key passphrase under key auth.
        let auth = match ssh.auth_method {
            SshAuthMethod::Password => {
                let Some(password) = ssh_password else {
                    return Err(SshError::Setup(format!(
                        "no SSH password stored for {:?} (expected under \"<connection>::ssh\")",
                        ssh.user
                    )));
                };
                handle
                    .authenticate_password(ssh.user.clone(), password)
                    .await
                    .map_err(|e| SshError::Transport(format!("password auth transport: {e}")))?
            }
            SshAuthMethod::Key => {
                let Some(path) = &ssh.private_key_path else {
                    return Err(SshError::Setup(
                        "key auth configured without privateKeyPath".into(),
                    ));
                };
                let expanded = crate::app::paths::expand_tilde(path);
                let key = russh::keys::load_secret_key(&expanded, ssh_password)
                    .map_err(|e| SshError::Setup(format!("load private key: {e}")))?;
                use russh::keys::Algorithm;
                match key.algorithm() {
                    Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. } => {}
                    other => {
                        return Err(SshError::Setup(format!(
                            "unsupported private key algorithm {other:?} (supported: ed25519, rsa, ecdsa)"
                        )));
                    }
                }
                // Let the server's advertised algorithms pick the RSA
                // signature hash (SHA-512 preferred, SHA-256 next;
                // legacy ssh-rsa/SHA-1 is never selected).
                let hash_alg = if key.algorithm().is_rsa() {
                    match handle.best_supported_rsa_hash().await {
                        Ok(best) => best.unwrap_or(Some(russh::keys::HashAlg::Sha256)),
                        Err(_) => Some(russh::keys::HashAlg::Sha256),
                    }
                } else {
                    None
                };
                handle
                    .authenticate_publickey(
                        ssh.user.clone(),
                        russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
                    )
                    .await
                    .map_err(|e| SshError::Transport(format!("publickey auth transport: {e}")))?
            }
        };
        if !matches!(auth, russh::client::AuthResult::Success) {
            return Err(SshError::Auth {
                host: ssh.host.clone(),
                port: ssh.port,
                user: ssh.user.clone(),
            });
        }
        Ok(handle)
    };
    let handle = tokio::time::timeout(SSH_CONNECT_TIMEOUT, session)
        .await
        .map_err(|_| {
            SshError::Transport(format!(
                "ssh session timeout after {}s",
                SSH_CONNECT_TIMEOUT.as_secs()
            ))
        })??;

    // Local loopback forwarder: one fresh direct-tcpip channel per
    // accepted TCP connection, bounded by CHANNEL_OPEN_TIMEOUT so a
    // stale session fails the connection instead of hanging it.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| SshError::Setup(format!("local bind: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| SshError::Setup(format!("local addr: {e}")))?;

    let generation = {
        let mut state = tunnels().lock().unwrap();
        let assigned = state.next_generation;
        state.next_generation += 1;
        assigned
    };

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let forward_host = target_host.to_string();
    let forward_port = u32::from(target_port);
    let shared = Arc::new(handle);
    let accept_session = Arc::clone(&shared);
    let draining = Arc::new(AtomicBool::new(false));
    let live_tasks: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let accept_draining = Arc::clone(&draining);
    let accept_tasks = Arc::clone(&live_tasks);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                accepted = listener.accept() => {
                    let Ok((socket, _peer)) = accepted else { break };
                    if accept_draining.load(Ordering::SeqCst) || accept_session.is_closed() {
                        break;
                    }
                    let session = Arc::clone(&accept_session);
                    let host = forward_host.clone();
                    let tasks = Arc::clone(&accept_tasks);
                    accept_tasks.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let target = format!("{host}:{forward_port}");
                        let channel = tokio::time::timeout(
                            CHANNEL_OPEN_TIMEOUT,
                            session.channel_open_direct_tcpip(host, forward_port, "127.0.0.1", 0),
                        )
                        .await;
                        match channel {
                            Ok(Ok(channel)) => {
                                // ChannelStream is the full tokio-IO view
                                // of a channel; split gives owned halves
                                // for the bidirectional copy.
                                let (mut chan_r, mut chan_w) =
                                    tokio::io::split(channel.into_stream());
                                let (mut sock_r, mut sock_w) = socket.into_split();
                                let a = tokio::io::copy(&mut sock_r, &mut chan_w);
                                let b = tokio::io::copy(&mut chan_r, &mut sock_w);
                                let _ = tokio::join!(a, b);
                            }
                            Ok(Err(e)) => {
                                eprintln!(
                                    "[sequel-mcp] ssh forwarder: channel open to {target} failed: {e:?}"
                                );
                                // Dropping the socket closes it: the MySQL
                                // handshake fails promptly.
                            }
                            Err(_) => {
                                eprintln!(
                                    "[sequel-mcp] ssh forwarder: channel open to {target} timed out after {}s (stale session?)",
                                    CHANNEL_OPEN_TIMEOUT.as_secs()
                                );
                            }
                        }
                        tasks.fetch_sub(1, Ordering::Relaxed);
                    });
                }
            }
        }
    });

    Ok(Arc::new(TunnelEntry {
        local,
        handle: shared,
        shutdown: shutdown_tx,
        generation,
        draining,
        last_used: Mutex::new(std::time::Instant::now()),
        live_tasks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SshTunnel;

    fn sample_tunnel() -> SshTunnel {
        SshTunnel {
            host: "bastion".into(),
            port: 22,
            user: "sshuser".into(),
            auth_method: SshAuthMethod::Password,
            ..SshTunnel::default()
        }
    }

    #[test]
    fn tunnel_key_separates_identity() {
        let ssh = sample_tunnel();
        let a = tunnel_key("c1", &ssh, Some("pw"), "db", 3306, 1, "stamp");
        let mut ssh2 = ssh.clone();
        ssh2.user = "other".into();
        let b = tunnel_key("c1", &ssh2, Some("pw"), "db", 3306, 1, "stamp");
        assert_ne!(a, b);
        assert_ne!(
            a,
            tunnel_key("c1", &ssh, Some("pw"), "other", 3306, 1, "stamp")
        );
        assert_ne!(
            a,
            tunnel_key("c1", &ssh, Some("pw"), "db", 3307, 1, "stamp")
        );
        assert_ne!(
            a,
            tunnel_key("c2", &ssh, Some("pw"), "db", 3306, 1, "stamp")
        );
        // Rotation inputs: credential, known_hosts content, revision.
        assert_ne!(
            a,
            tunnel_key("c1", &ssh, Some("different"), "db", 3306, 1, "stamp")
        );
        assert_ne!(
            a,
            tunnel_key("c1", &ssh, Some("pw"), "db", 3306, 2, "stamp")
        );
        assert_ne!(
            a,
            tunnel_key("c1", &ssh, Some("pw"), "db", 3306, 1, "stamp2")
        );
    }

    #[test]
    fn credential_fragment_hides_the_secret() {
        let f = ssh_credential_fragment(Some("top-secret-password"));
        assert_eq!(f.len(), 32, "hex of a 16-byte digest");
        assert!(!f.contains("top-secret"));
        assert_ne!(f, ssh_credential_fragment(Some("other")));
        // A missing and an empty secret are the same non-secret here.
        assert_eq!(
            ssh_credential_fragment(None),
            ssh_credential_fragment(Some(""))
        );
    }

    #[test]
    fn known_hosts_stamp_tracks_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("kh");
        std::fs::write(&f, b"content-a").unwrap();
        let s1 = known_hosts_stamp(Some(&f));
        let s2 = known_hosts_stamp(Some(&f));
        assert_eq!(s1, s2, "stable per content");
        std::fs::write(&f, b"content-b").unwrap();
        assert_ne!(s1, known_hosts_stamp(Some(&f)));
        assert_eq!(known_hosts_stamp(None), "");
    }
}
