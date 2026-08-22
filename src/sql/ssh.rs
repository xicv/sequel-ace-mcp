//! SSH direct-tunnel transport (russh port of the legacy tunnel runtime).
//!
//! Topology per connection: `mysql_async` always connects to a LOCAL
//! loopback endpoint; every local TCP connection is bridged onto a fresh
//! `direct_tcpip` channel of ONE multiplexed SSH session to the bastion,
//! which forwards to the MySQL host/port as seen FROM the bastion.
//! Host keys are verified against known_hosts through the same
//! strict/lenient policy as the legacy server — strict fails closed
//! (unknown host or mismatched key = no connection).
//!
//! Tunnels are process-wide and bounded (like the pool manager): the
//! same bastion session is reused across queries; a dead session is
//! evicted and the next request re-establishes it. Test-mode rules
//! apply: the bastion endpoint must be loopback or explicitly
//! allow-listed before any socket is opened.

use crate::config::{SshAuthMethod, SshHostKeyPolicy, SshTunnel};
use crate::sql::known_hosts;
use russh::client::{self, Handle};
use russh::keys::PublicKeyBase64;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Deadline for establishing the SSH session (connect + KEX + auth),
/// matching the pool's connect timeout so blackhole bastions fail with
/// a typed error instead of hanging.
pub const SSH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum distinct tunnels kept in the process-wide cache.
pub const MAX_TUNNELS: usize = 8;

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
/// the ported known_hosts engine (strict = fail closed, lenient = accept
/// with a loud log line, matching the legacy semantics).
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

struct TunnelEntry {
    /// Local loopback listener address handed to `mysql_async`.
    local: std::net::SocketAddr,
    /// Multiplexed SSH session; channels are opened per TCP connection.
    handle: Arc<Handle<HostKeyHandler>>,
    /// Sender whose drop signals the accept-loop task to stop.
    shutdown: mpsc::Sender<()>,
}

static TUNNELS: OnceLock<Mutex<HashMap<String, Arc<TunnelEntry>>>> = OnceLock::new();

fn tunnels() -> &'static Mutex<HashMap<String, Arc<TunnelEntry>>> {
    TUNNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Number of live tunnels (diagnostics/tests).
pub fn tunnel_count() -> usize {
    tunnels().lock().unwrap().len()
}

/// Drop every cached tunnel (tests).
pub fn invalidate_all() {
    let mut map = tunnels().lock().unwrap();
    for (_, entry) in map.drain() {
        let _ = entry.shutdown.try_send(());
    }
}

fn tunnel_key(conn_name: &str, ssh: &SshTunnel, target: &str, port: u16) -> String {
    let target_endpoint = format!("{target}:{port}");
    format!(
        "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
        conn_name,
        ssh.host,
        ssh.port,
        ssh.user,
        ssh.auth_method_label(),
        ssh.known_hosts_path.as_deref().unwrap_or(""),
        target_endpoint
    )
}

impl SshTunnel {
    fn auth_method_label(&self) -> &'static str {
        match self.auth_method {
            SshAuthMethod::Password => "password",
            SshAuthMethod::Key => "key",
        }
    }
}

/// Return the local `(host, port)` endpoint of a (reused or freshly
/// established) SSH tunnel for `conn`'s SSH config, forwarding to
/// `target_host:target_port` as reachable from the bastion. The MySQL
/// pool must key itself on this endpoint, never on the raw config.
pub async fn tunnel_endpoint(
    conn_name: &str,
    ssh: &SshTunnel,
    ssh_password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<(String, u16), SshError> {
    // Fail-closed test-mode gate on the BASTION endpoint before any
    // socket is opened (docker bastions publish on loopback).
    crate::app::test_mode::check_mysql_endpoint(&ssh.host, ssh.port).map_err(SshError::Setup)?;

    let key = tunnel_key(conn_name, ssh, target_host, target_port);
    {
        let map = tunnels().lock().unwrap();
        if let Some(entry) = map.get(&key)
            && !entry.handle.is_closed()
        {
            return Ok(("127.0.0.1".into(), entry.local.port()));
        }
    }

    let entry = establish(ssh, ssh_password, target_host, target_port).await?;

    let mut map = tunnels().lock().unwrap();
    // Drop dead entries opportunistically; bound the cache (arbitrary
    // victim — callers re-establish transparently).
    let dead: Vec<String> = map
        .iter()
        .filter(|(_, e)| e.handle.is_closed())
        .map(|(k, _)| k.clone())
        .collect();
    for k in dead {
        if let Some(e) = map.remove(&k) {
            let _ = e.shutdown.try_send(());
        }
    }
    while map.len() >= MAX_TUNNELS {
        let Some((k, e)) = map.iter().next().map(|(k, v)| (k.clone(), v.clone())) else {
            break;
        };
        let _ = e.shutdown.try_send(());
        map.remove(&k);
    }
    let (host, port) = ("127.0.0.1".to_string(), entry.local.port());
    map.insert(key, entry);
    Ok((host, port))
}

async fn establish(
    ssh: &SshTunnel,
    ssh_password: Option<&str>,
    target_host: &str,
    target_port: u16,
) -> Result<Arc<TunnelEntry>, SshError> {
    let known_hosts_path = ssh.known_hosts_path.as_deref().map(std::path::Path::new);
    let entries =
        known_hosts::load_known_hosts_checked(known_hosts_path).map_err(|e| SshError::HostKey {
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

    let config = Arc::new(client::Config {
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..client::Config::default()
    });

    let addr = (ssh.host.as_str(), ssh.port);
    let session = async {
        let mut handle = client::connect(config, addr, handler)
            .await
            .map_err(|e| SshError::Transport(format!("connect to bastion: {e}")))?;
        // authenticate with EXACTLY the configured method — no silent
        // fallback between password and key.
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
                let key = russh::keys::load_secret_key(&expanded, None)
                    .map_err(|e| SshError::Setup(format!("load private key: {e}")))?;
                handle
                    .authenticate_publickey(
                        ssh.user.clone(),
                        // Non-RSA keys ignore the hash alg; RSA defaults
                        // to SHA-256 signatures rather than legacy SHA-1.
                        russh::keys::PrivateKeyWithHashAlg::new(
                            Arc::new(key),
                            Some(russh::keys::HashAlg::Sha256),
                        ),
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
    // accepted TCP connection.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| SshError::Setup(format!("local bind: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| SshError::Setup(format!("local addr: {e}")))?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let forward_host = target_host.to_string();
    let forward_port = u32::from(target_port);
    let shared = Arc::new(handle);
    let accept_session = Arc::clone(&shared);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                accepted = listener.accept() => {
                    let Ok((socket, _peer)) = accepted else { break };
                    if accept_session.is_closed() { break; }
                    let session = Arc::clone(&accept_session);
                    let host = forward_host.clone();
                    tokio::spawn(async move {
                        let target = format!("{host}:{forward_port}");
                        let channel = session
                            .channel_open_direct_tcpip(host, forward_port, "127.0.0.1", 0)
                            .await;
                        let Ok(channel) = channel else {
                            eprintln!(
                                "[sequel-mcp] ssh forwarder: channel open to {target} failed: {:?}",
                                channel.err()
                            );
                            return;
                        };
                        // ChannelStream is the full tokio-IO view of a
                        // channel; split gives owned halves for the
                        // bidirectional copy.
                        let (mut chan_r, mut chan_w) = tokio::io::split(channel.into_stream());
                        let (mut sock_r, mut sock_w) = socket.into_split();
                        let a = tokio::io::copy(&mut sock_r, &mut chan_w);
                        let b = tokio::io::copy(&mut chan_r, &mut sock_w);
                        let _ = tokio::join!(a, b);
                    });
                }
            }
        }
    });

    Ok(Arc::new(TunnelEntry {
        local,
        handle: shared,
        shutdown: shutdown_tx,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_key_separates_identity() {
        let ssh = SshTunnel {
            host: "bastion".into(),
            port: 22,
            user: "sshuser".into(),
            auth_method: SshAuthMethod::Password,
            ..SshTunnel::default()
        };
        let a = tunnel_key("c1", &ssh, "db", 3306);
        let mut ssh2 = ssh.clone();
        ssh2.user = "other".into();
        let b = tunnel_key("c1", &ssh2, "db", 3306);
        assert_ne!(a, b);
        let c = tunnel_key("c1", &ssh, "other", 3306);
        assert_ne!(a, c);
        let d = tunnel_key("c1", &ssh, "db", 3307);
        assert_ne!(a, d);
        let e = tunnel_key("c2", &ssh, "db", 3306);
        assert_ne!(a, e);
    }
}
