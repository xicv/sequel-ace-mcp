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
    #[error("authentication aborted as {user:?} on {host}:{port}: {reason}")]
    AuthAborted {
        host: String,
        port: u16,
        user: String,
        reason: String,
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

/// Why an auth exchange can end WITHOUT a server verdict. russh
/// (0.62 and 0.63 alike) collapses a dead session into
/// `AuthResult::Failure` with an empty remaining-method set (the reply
/// channel closes and `wait_recv_reply` maps `None` to `Failure`), so
/// the 0.10.2 incident — RSA signing compiled out, ssh-key rejecting
/// the signature as `AlgorithmUnsupported { algorithm: Rsa { hash:
/// None } }` AFTER the server had already answered USERAUTH_PK_OK —
/// surfaced as "authentication failed", indistinguishable from a
/// rejected credential. This reason must make the difference visible.
/// (russh 0.63.2 also logs-and-fails this case inside the session task
/// — Eugeny/russh#758 — but the caller-visible shape is unchanged, so
/// this discrimination remains ours.)
fn auth_abort_reason(key_is_rsa: bool) -> String {
    if key_is_rsa && cfg!(not(feature = "rsa")) {
        "no server verdict was delivered — the SSH session ended mid-auth. \
         This build cannot SIGN RSA keys: russh's `rsa` feature is missing \
         (enabled by sequel-mcp's default `rsa` feature). The key itself is \
         fine and the server had not rejected it"
            .into()
    } else if key_is_rsa {
        "no server verdict was delivered — the SSH session ended mid-auth, a \
         signing/transport failure and NOT a rejected credential. For RSA keys \
         the classic cause is a build without russh's `rsa` feature; \
         RUST_LOG=russh=debug shows the underlying error"
            .into()
    } else {
        "no server verdict was delivered — the SSH session ended mid-auth, a \
         transport failure and NOT a rejected credential; RUST_LOG=russh=debug \
         shows the underlying error"
            .into()
    }
}

/// True when the error means "we could not produce the signature the
/// protocol asked for" rather than "the network/auth exchange broke".
/// ssh-key reports exactly this shape when RSA signing support is
/// compiled out (`Rsa { hash: None }` = the negotiated hash never
/// reached the signer).
fn is_signature_algorithm_error(e: &russh::Error) -> bool {
    matches!(
        e,
        russh::Error::SshKey(russh::keys::ssh_key::Error::AlgorithmUnsupported { .. })
    )
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
    /// Shared with `establish` so the TOFU/mismatch commentary is
    /// actually EMITTED (stderr — protocol-safe) after connect returns
    /// instead of silently buffered (review finding).
    logs: std::sync::Arc<Mutex<Vec<String>>>,
}

impl client::Handler for HostKeyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // The known_hosts engine compares raw key bytes. russh 0.63 can
        // also surface host CERTIFICATES here; no stored entry can ever
        // match one, so they fail closed rather than being reduced to
        // their signing key (which would smuggle an unverified
        // certificate's key past the pin).
        let raw = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.public_key_bytes(),
            russh::keys::PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
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
    let bridge = ssh
        .docker
        .as_ref()
        .map(|d| format!("{}:{}", d.container, d.bridge_tool.as_str()))
        .unwrap_or_default();
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
        conn_name,
        ssh.host,
        ssh.port,
        ssh.user,
        ssh.auth_method_label(),
        kh_stamp,
        ssh_credential_fragment(ssh_password),
        policy_revision,
        target_endpoint,
        bridge
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

/// When `ssh.docker` is configured, per-connection forwarding runs over
/// an SSH **exec** channel (`docker exec -i <container> <tool> …`)
/// instead of direct-tcpip — the bridge that works even where sshd
/// denies TCP forwarding. All argv components are validated (no shell,
/// no spaces), so the exec command line is a plain join.
fn bridge_command(
    ssh: &SshTunnel,
    target_host: &str,
    target_port: u16,
) -> Result<Option<String>, SshError> {
    let Some(docker) = &ssh.docker else {
        return Ok(None);
    };
    let argv = super::docker::bridge_argv(
        &docker.container,
        docker.bridge_tool,
        target_host,
        target_port,
    )
    .map_err(|e| SshError::Setup(format!("docker bridge: {e}")))?;
    Ok(Some(argv.join(" ")))
}

async fn establish(
    ssh: &SshTunnel,
    ssh_password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<Arc<TunnelEntry>, SshError> {
    let bridge_cmd = bridge_command(ssh, target_host, target_port)?;
    let kh_path = ssh.known_hosts_path.as_deref().map(std::path::Path::new);
    let entries =
        known_hosts::load_known_hosts_checked(kh_path).map_err(|e| SshError::HostKey {
            host: ssh.host.clone(),
            port: ssh.port,
            reason: e,
        })?;
    let logs = std::sync::Arc::new(Mutex::new(Vec::new()));
    let handler = HostKeyHandler {
        policy: ssh.host_key_policy.unwrap_or(SshHostKeyPolicy::Lenient),
        entries,
        host: ssh.host.clone(),
        port: ssh.port,
        logs: logs.clone(),
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
        // Host-key commentary (TOFU accepts, migration-compat warnings)
        // must reach the operator, not rot in a buffer.
        for line in logs.lock().unwrap().drain(..) {
            eprintln!("[sequel-mcp] SSH {}:{} {line}", ssh.host, ssh.port);
        }
        // Authenticate with EXACTLY the configured method — no silent
        // fallback between password and key. The secret doubles as the
        // private-key passphrase under key auth.
        let mut key_algorithm_was_rsa = false;
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
                key_algorithm_was_rsa = key.algorithm().is_rsa();
                let hash_alg = if key_algorithm_was_rsa {
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
                    .map_err(|e| {
                        // A signature we cannot produce is NOT a
                        // transport problem: name it as an aborted
                        // auth so it cannot masquerade as a rejected
                        // credential (the 0.10.2 incident).
                        if is_signature_algorithm_error(&e) {
                            SshError::AuthAborted {
                                host: ssh.host.clone(),
                                port: ssh.port,
                                user: ssh.user.clone(),
                                reason: auth_abort_reason(key_algorithm_was_rsa),
                            }
                        } else {
                            SshError::Transport(format!("publickey auth transport: {e}"))
                        }
                    })?
            }
        };
        match auth {
            russh::client::AuthResult::Success => {}
            russh::client::AuthResult::Failure {
                remaining_methods, ..
            } => {
                // A genuine USERAUTH_FAILURE carries the server's
                // remaining-method list. russh 0.62 ALSO maps "the
                // session died during auth" — reply channel closed,
                // e.g. the signature could not be produced — to
                // Failure, but with an EMPTY method set. Collapsing
                // both into Auth is what made the 0.10.2 RSA signing
                // failure read as a rejected credential.
                if remaining_methods.is_empty() {
                    return Err(SshError::AuthAborted {
                        host: ssh.host.clone(),
                        port: ssh.port,
                        user: ssh.user.clone(),
                        reason: auth_abort_reason(key_algorithm_was_rsa),
                    });
                }
                return Err(SshError::Auth {
                    host: ssh.host.clone(),
                    port: ssh.port,
                    user: ssh.user.clone(),
                });
            }
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
                    let bridge_cmd = bridge_cmd.clone();
                    tokio::spawn(async move {
                        let target = format!("{host}:{forward_port}");
                        // Bridge connections open a session channel and
                        // exec the (validated, space-free) docker bridge
                        // argv; direct connections use direct-tcpip.
                        let channel = tokio::time::timeout(
                            CHANNEL_OPEN_TIMEOUT,
                            async {
                                match &bridge_cmd {
                                    Some(cmd) => {
                                        let ch = session.channel_open_session().await?;
                                        ch.exec(true, cmd.as_str()).await?;
                                        Ok::<_, russh::Error>(ch)
                                    }
                                    None => session
                                        .channel_open_direct_tcpip(
                                            host,
                                            forward_port,
                                            "127.0.0.1",
                                            0,
                                        )
                                        .await,
                                }
                            },
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
        // Bridge identity (container + tool) is part of the key.
        let mut bridged = ssh.clone();
        bridged.docker = Some(crate::config::SshDocker {
            container: "db".into(),
            bridge_tool: crate::config::BridgeTool::Nc,
        });
        assert_ne!(
            a,
            tunnel_key("c1", &bridged, Some("pw"), "127.0.0.1", 3306, 1, "stamp")
        );
        let mut bridged2 = bridged.clone();
        bridged2.docker = Some(crate::config::SshDocker {
            container: "db".into(),
            bridge_tool: crate::config::BridgeTool::Socat,
        });
        assert_ne!(
            tunnel_key("c1", &bridged, Some("pw"), "127.0.0.1", 3306, 1, "stamp"),
            tunnel_key("c1", &bridged2, Some("pw"), "127.0.0.1", 3306, 1, "stamp")
        );
    }

    #[test]
    fn bridge_command_forms() {
        use crate::config::{BridgeTool, SshDocker};
        let mk = |tool| SshTunnel {
            host: "bastion".into(),
            port: 22,
            user: "u".into(),
            auth_method: SshAuthMethod::Key,
            docker: Some(SshDocker {
                container: "db-1".into(),
                bridge_tool: tool,
            }),
            ..SshTunnel::default()
        };
        assert_eq!(
            bridge_command(&mk(BridgeTool::Nc), "127.0.0.1", 3306)
                .unwrap()
                .unwrap(),
            "docker exec -i db-1 nc 127.0.0.1 3306"
        );
        assert_eq!(
            bridge_command(&mk(BridgeTool::Ncat), "127.0.0.1", 3306)
                .unwrap()
                .unwrap(),
            "docker exec -i db-1 ncat 127.0.0.1 3306"
        );
        assert_eq!(
            bridge_command(&mk(BridgeTool::Socat), "127.0.0.1", 3306)
                .unwrap()
                .unwrap(),
            "docker exec -i db-1 socat - TCP:127.0.0.1:3306"
        );
        // No docker config: direct-tcpip path.
        let plain = SshTunnel::default();
        assert_eq!(bridge_command(&plain, "db", 3306).unwrap(), None);
        // Invalid inputs fail typed before any connection.
        let mut bad = mk(BridgeTool::Nc);
        bad.docker = Some(SshDocker {
            container: "bad name!".into(),
            bridge_tool: BridgeTool::Nc,
        });
        assert!(bridge_command(&bad, "127.0.0.1", 3306).is_err());
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

    #[test]
    fn auth_abort_reason_never_claims_rejection() {
        // RSA: the reason must point at signing support (the feature
        // gap), never at the credential. Wording differs between a
        // feature-less build ("cannot SIGN") and a full build ("NOT a
        // rejected credential"), so accept either shape.
        let rsa = auth_abort_reason(true);
        assert!(rsa.to_lowercase().contains("rsa"), "{rsa}");
        assert!(
            rsa.to_lowercase().contains("not rejected")
                || rsa.to_lowercase().contains("not a rejected credential")
                || rsa.to_lowercase().contains("cannot sign"),
            "must not read as a rejected credential: {rsa}"
        );
        // Non-RSA: generic transport wording, no RSA red herring.
        let other = auth_abort_reason(false);
        assert!(
            other.to_lowercase().contains("not a rejected credential"),
            "{other}"
        );
        assert!(!other.to_lowercase().contains("rsa"), "{other}");
    }

    #[test]
    fn signature_algorithm_error_discriminates() {
        // The exact ssh-key shape from the 0.10.2 incident: an RSA
        // signature whose negotiated hash never reached the signer.
        let unsupported = russh::Error::SshKey(russh::keys::ssh_key::Error::AlgorithmUnsupported {
            algorithm: russh::keys::Algorithm::Rsa { hash: None },
        });
        assert!(is_signature_algorithm_error(&unsupported));
        // Other SshKey errors stay transport-classified.
        let other = russh::Error::SshKey(russh::keys::ssh_key::Error::AlgorithmUnknown);
        assert!(!is_signature_algorithm_error(&other));
    }
}
