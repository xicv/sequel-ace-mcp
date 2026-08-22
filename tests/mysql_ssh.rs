//! SSH direct-transport live tests: a bastion container with its port on
//! loopback and a MariaDB container reachable ONLY through the bastion on
//! a private docker network (scripts/test-ssh.sh builds the topology,
//! exports the fixtures, and drives the bastion death/restart phases
//! between filtered cargo invocations — the tests themselves spawn no
//! processes). Nothing here touches any real configuration.

use sequel_mcp::app::gate::{self, GateDeps, RunSqlArgs};
use sequel_mcp::config::{MySqlConnection, SshAuthMethod, SshHostKeyPolicy, SshTunnel};
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use sequel_mcp::sql::ssh::{self, SshError};
use sequel_mcp::vault::keychain::{InMemorySecretStore, SecretStore as _};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

struct Fixture {
    bastion_host: String,
    bastion_port: u16,
    ssh_user: String,
    ssh_password: String,
    known_good: PathBuf,
    known_mismatch: PathBuf,
    known_unknown: PathBuf,
    key_encrypted: Option<PathBuf>,
    key_ecdsa: Option<PathBuf>,
    ssh_password_rotated: Option<String>,
    known_revoked: PathBuf,
    known_malformed: PathBuf,
    known_missing: PathBuf,
    key_path: PathBuf,
    mysql_user: String,
    mysql_password: String,
}

fn fixture() -> Option<Fixture> {
    let bastion = std::env::var("SEQUEL_MCP_TEST_SSH_BASTION").ok()?;
    let mut parts = bastion.splitn(4, ':');
    let bastion_host = parts.next()?.to_string();
    let bastion_port = parts.next()?.parse().ok()?;
    let ssh_user = parts.next()?.to_string();
    let ssh_password = parts.next()?.to_string();
    let creds = std::env::var("SEQUEL_MCP_TEST_SSH_MYSQL_CREDS").ok()?;
    let mut creds = creds.splitn(2, ':');
    let mysql_user = creds.next()?.to_string();
    let mysql_password = creds.next()?.to_string();
    Some(Fixture {
        bastion_host,
        bastion_port,
        ssh_user,
        ssh_password,
        known_good: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KNOWN_GOOD").ok()?),
        known_mismatch: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KNOWN_MISMATCH").ok()?),
        known_unknown: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KNOWN_UNKNOWN").ok()?),
        key_encrypted: std::env::var("SEQUEL_MCP_TEST_SSH_KEY_ENC")
            .ok()
            .map(PathBuf::from),
        key_ecdsa: std::env::var("SEQUEL_MCP_TEST_SSH_KEY_ECDSA")
            .ok()
            .map(PathBuf::from),
        ssh_password_rotated: std::env::var("SEQUEL_MCP_TEST_SSH_PASSWORD2").ok(),
        known_revoked: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KNOWN_REVOKED").ok()?),
        known_malformed: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KNOWN_MALFORMED").ok()?),
        known_missing: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KNOWN_MISSING").ok()?),
        key_path: PathBuf::from(std::env::var("SEQUEL_MCP_TEST_SSH_KEY").ok()?),
        mysql_user,
        mysql_password,
    })
}

fn ssh_tunnel(fx: &Fixture, known_hosts: &std::path::Path, auth: SshAuthMethod) -> SshTunnel {
    ssh_tunnel_policy(fx, known_hosts, auth, SshHostKeyPolicy::Strict)
}

fn ssh_tunnel_policy(
    fx: &Fixture,
    known_hosts: &std::path::Path,
    auth: SshAuthMethod,
    policy: SshHostKeyPolicy,
) -> SshTunnel {
    let private_key_path = if auth == SshAuthMethod::Key {
        Some(fx.key_path.display().to_string())
    } else {
        None
    };
    SshTunnel {
        host: fx.bastion_host.clone(),
        port: fx.bastion_port,
        user: fx.ssh_user.clone(),
        auth_method: auth,
        private_key_path,
        host_key_policy: Some(policy),
        known_hosts_path: Some(known_hosts.display().to_string()),
        ..SshTunnel::default()
    }
}

fn mysql_conn_tls(
    ssh: Option<SshTunnel>,
    mysql_user: &str,
    ssl_server_name: Option<&str>,
) -> MySqlConnection {
    MySqlConnection {
        ssl: ssl_server_name.is_some(),
        ssl_server_name: ssl_server_name.map(str::to_string),
        ..mysql_conn(ssh, mysql_user)
    }
}

fn tls_variant_active() -> bool {
    std::env::var("SEQUEL_MCP_TEST_SSH_TLS").ok().as_deref() == Some("1")
}

fn mysql_conn(ssh: Option<SshTunnel>, mysql_user: &str) -> MySqlConnection {
    // In the mysql84+TLS variant every connection verifies the server
    // certificate against the ORIGINAL database name through
    // sslServerName while the transport is the loopback tunnel.
    let (ssl, ssl_server_name, ssl_ca_path) = if tls_variant_active() {
        (
            true,
            Some("db.internal.test".to_string()),
            std::env::var("SEQUEL_MCP_TEST_SSH_TLS_CA").ok(),
        )
    } else {
        (false, None, None)
    };
    MySqlConnection {
        name: "ssh-t".into(),
        host: "db".into(), // reachable only from the bastion's network
        port: 3306,
        user: mysql_user.to_string(),
        database: Some("app".into()),
        ssl,
        ssl_server_name,
        ssl_ca_path,
        ssh,
        ..MySqlConnection::default()
    }
}

async fn run_through_tunnel(
    fx: &Fixture,
    conn: &MySqlConnection,
    tunnel: &SshTunnel,
    sql: &str,
) -> Result<sequel_mcp::sql::mysql::ExecuteResult, SshError> {
    let policy = policy_from_preset(PolicyPresetName::Administration);
    run_through_tunnel_with_policy(fx, conn, tunnel, sql, policy).await
}

async fn run_through_tunnel_with_policy(
    fx: &Fixture,
    conn: &MySqlConnection,
    tunnel: &SshTunnel,
    sql: &str,
    policy: sequel_mcp::policy::model::Policy,
) -> Result<sequel_mcp::sql::mysql::ExecuteResult, SshError> {
    let endpoint = ssh::tunnel_endpoint(
        &conn.name,
        tunnel,
        Some(fx.ssh_password.as_str()),
        &conn.host,
        conn.port,
        1,
    )
    .await?;
    let classified = classify_statement(sql, Dialect::MySql).unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    std::mem::forget(dir);
    execute_mysql_statement(MySqlExecuteParams {
        connection: conn,
        request_id: format!("req-{}", uuid::Uuid::new_v4()),
        databases_for_log: vec![],
        password: Zeroizing::new(fx.mysql_password.clone()),
        sql,
        classified: &classified,
        policy: &policy,
        database: None,
        audit: Some(audit),
        revision: 1,
        tunnel_endpoint: Some(endpoint),
        expected_ddl_targets: None,
    })
    .await
    .map_err(|e| SshError::Transport(e.to_string()))
}

fn int_cell(v: &serde_json::Value) -> i64 {
    match v {
        serde_json::Value::Number(n) => n.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        other => panic!("{other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_direct_transport_strict_password() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();

    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);

    run_through_tunnel(&fx, &conn, &tunnel, "DROP TABLE IF EXISTS ssh_t")
        .await
        .unwrap();
    run_through_tunnel(
        &fx,
        &conn,
        &tunnel,
        "CREATE TABLE ssh_t (id INT PRIMARY KEY)",
    )
    .await
    .unwrap();
    for i in 1..=3i64 {
        run_through_tunnel(
            &fx,
            &conn,
            &tunnel,
            &format!("INSERT INTO ssh_t (id) VALUES ({i})"),
        )
        .await
        .unwrap();
    }
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT COUNT(*) AS n FROM ssh_t")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["n"]), 3, "rows flow through the tunnel");

    // Reuse: the same bastion session and local endpoint serve every
    // query above — exactly one tunnel entry for the whole matrix.
    assert_eq!(ssh::tunnel_count(), 1, "one multiplexed tunnel");
    let again = ssh::tunnel_endpoint("ssh-t", &tunnel, Some(&fx.ssh_password), "db", 3306, 1)
        .await
        .unwrap();
    assert_eq!(ssh::tunnel_count(), 1, "a second endpoint call reuses");
    assert!(again.port > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_strict_host_key_mismatch_fails_closed() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    // A decoy key planted in known_hosts: strict policy must refuse the
    // REAL server key — no SSH session, no tunnel, nothing cached.
    let tunnel = ssh_tunnel(&fx, &fx.known_mismatch, SshAuthMethod::Password);
    let err = ssh::tunnel_endpoint("mismatch", &tunnel, Some(&fx.ssh_password), "db", 3306, 1)
        .await
        .unwrap_err();
    match &err {
        // russh surfaces check_server_key=false as a key-exchange
        // disagreement; both shapes mean "refused before auth".
        SshError::Transport(msg) => {
            assert!(
                msg.contains("connect to bastion") || msg.contains("key"),
                "host-key mismatch refused: {msg}"
            );
        }
        SshError::HostKey { .. } => {}
        other => panic!("expected host-key rejection, got {other:?}"),
    }
    assert_eq!(ssh::tunnel_count(), 0, "no tunnel may be cached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_strict_unknown_host_fails_closed() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    // known_hosts with NO entry for this host/port: strict rejects.
    let tunnel = ssh_tunnel(&fx, &fx.known_unknown, SshAuthMethod::Password);
    let err = ssh::tunnel_endpoint("unknown", &tunnel, Some(&fx.ssh_password), "db", 3306, 1)
        .await
        .unwrap_err();
    let msg = match &err {
        SshError::Transport(m) => m.clone(),
        SshError::HostKey { reason, .. } => reason.clone(),
        other => panic!("expected host-key rejection, got {other:?}"),
    };
    assert!(
        msg.contains("connect to bastion") || msg.contains("key"),
        "unknown host refused: {msg}"
    );
    assert_eq!(ssh::tunnel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_key_auth_strict() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Key);
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 41 + 1 AS answer")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["answer"]), 42);
}

/// Phase driven by scripts/test-ssh.sh AFTER `docker stop` of the
/// bastion: a fresh process attempts the tunnel and must receive a
/// bounded, typed transport failure — never a hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_bastion_death_typed_refusal() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let started = std::time::Instant::now();
    let err = ssh::tunnel_endpoint("dead", &tunnel, Some(&fx.ssh_password), "db", 3306, 1)
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "refusal must be bounded (took {:?})",
        started.elapsed()
    );
    match &err {
        SshError::Transport(m) => {
            assert!(
                m.contains("connect to bastion") || m.contains("timeout"),
                "typed transport failure: {m}"
            );
        }
        other => panic!("expected transport failure, got {other:?}"),
    }
}

/// Phase driven by scripts/test-ssh.sh AFTER `docker start` + a
/// known_hosts refresh: the query must flow again through the fresh
/// session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_bastion_reconnect_after_restart() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 2 AS v")
        .await
        .unwrap();
    assert_eq!(
        int_cell(&r.rows[0]["v"]),
        2,
        "reconnected through a fresh session"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_strict_revoked_key_denied() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    // The REAL key, explicitly marked @revoked: every mode rejects.
    let tunnel = ssh_tunnel(&fx, &fx.known_revoked, SshAuthMethod::Password);
    let err = ssh::tunnel_endpoint("revoked", &tunnel, Some(&fx.ssh_password), "db", 3306, 1)
        .await
        .unwrap_err();
    let msg = match &err {
        SshError::Transport(m) => m.clone(),
        SshError::HostKey { reason, .. } => reason.clone(),
        other => panic!("expected host-key rejection, got {other:?}"),
    };
    assert!(
        msg.contains("connect to bastion") || msg.contains("key"),
        "revoked key refused: {msg}"
    );
    assert_eq!(ssh::tunnel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_explicit_known_hosts_missing_denied() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    // An explicitly configured known_hosts file that does not exist is
    // a deny in every mode — never a silently-empty host set.
    let tunnel = ssh_tunnel(&fx, &fx.known_missing, SshAuthMethod::Password);
    let err = ssh::tunnel_endpoint(
        "missingfile",
        &tunnel,
        Some(&fx.ssh_password),
        "db",
        3306,
        1,
    )
    .await
    .unwrap_err();
    match &err {
        SshError::HostKey { reason, .. } => assert!(reason.contains("unreadable"), "{reason}"),
        other => panic!("expected host-key denial, got {other:?}"),
    }
    assert_eq!(ssh::tunnel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_malformed_known_hosts_denied() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_malformed, SshAuthMethod::Password);
    let err = ssh::tunnel_endpoint("malformed", &tunnel, Some(&fx.ssh_password), "db", 3306, 1)
        .await
        .unwrap_err();
    match &err {
        SshError::HostKey { reason, .. } => assert!(reason.contains("malformed"), "{reason}"),
        other => panic!("expected host-key denial, got {other:?}"),
    }
    assert_eq!(ssh::tunnel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_lenient_unknown_accepts_with_warning_path() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    // Migration-compatibility mode: a genuinely UNKNOWN host is the only
    // thing lenient may accept. The query must still succeed end to end.
    let tunnel = ssh_tunnel_policy(
        &fx,
        &fx.known_unknown,
        SshAuthMethod::Password,
        SshHostKeyPolicy::Lenient,
    );
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 3 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_lenient_mismatch_denied() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    // THE reviewer gate: lenient must NOT accept a key MISMATCH. The
    // decoy fixture names this host with a different key.
    let tunnel = ssh_tunnel_policy(
        &fx,
        &fx.known_mismatch,
        SshAuthMethod::Password,
        SshHostKeyPolicy::Lenient,
    );
    let err = ssh::tunnel_endpoint(
        "lenient-mismatch",
        &tunnel,
        Some(&fx.ssh_password),
        "db",
        3306,
        1,
    )
    .await
    .unwrap_err();
    let msg = match &err {
        SshError::Transport(m) => m.clone(),
        SshError::HostKey { reason, .. } => reason.clone(),
        other => panic!("expected host-key rejection, got {other:?}"),
    };
    assert!(
        msg.contains("connect to bastion") || msg.contains("key"),
        "lenient mismatch refused: {msg}"
    );
    assert_eq!(ssh::tunnel_count(), 0);
}

/// 32 concurrent first callers must coalesce on EXACTLY ONE SSH
/// session / tunnel; every lease shares the port, and concurrent
/// queries all succeed through the multiplexed channels.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ssh_concurrent_single_session() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = Arc::new(ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password));
    let mut joins = tokio::task::JoinSet::new();
    for i in 0..32u64 {
        let tunnel = Arc::clone(&tunnel);
        let pw = fx.ssh_password.clone();
        let mpw = fx.mysql_password.clone();
        let mu = fx.mysql_user.clone();
        joins.spawn(async move {
            let lease = ssh::tunnel_endpoint("conc", &tunnel, Some(pw.as_str()), "db", 3306, 1)
                .await
                .unwrap();
            let conn = MySqlConnection {
                user: mu,
                ssh: Some((*tunnel).clone()),
                ..mysql_conn(None, "")
            };
            let policy = policy_from_preset(PolicyPresetName::Administration);
            let sql = format!("SELECT {i} AS v");
            let classified = classify_statement(&sql, Dialect::MySql).unwrap();
            let dir = tempfile::TempDir::new().unwrap();
            let audit = Arc::new(
                sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap(),
            );
            std::mem::forget(dir);
            let r = execute_mysql_statement(MySqlExecuteParams {
                connection: &conn,
                request_id: format!("req-{i}"),
                databases_for_log: vec![],
                password: Zeroizing::new(mpw),
                sql: &sql,
                classified: &classified,
                policy: &policy,
                database: None,
                audit: Some(audit),
                revision: 1,
                tunnel_endpoint: Some(lease),
                expected_ddl_targets: None,
            })
            .await
            .unwrap();
            r.rows[0]["v"].clone()
        });
    }
    let mut count = 0;
    while let Some(res) = joins.join_next().await {
        let v = res.unwrap();
        // Engines type literal columns differently (number vs numeric
        // string); both are correct answers here.
        assert!(
            v.is_number() || v.as_str().map(|s| s.parse::<i64>().is_ok()) == Some(true),
            "query answered: {v:?}"
        );
        count += 1;
    }
    assert_eq!(count, 32);
    assert_eq!(ssh::tunnel_count(), 1, "one multiplexed session");
}

/// Cache cap 8 + LRU eviction + generation-coupled pool eviction: the
/// 8 newer distinct tunnels retire the least-recently-used victim, and
/// the retired tunnel's MySQL pool is disconnected with it; channel
/// tasks drain to zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_tunnel_cache_cap_lru_and_pool_eviction() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);

    // Warm the LRU victim first AND run one query through it so its
    // MySQL pool exists and is keyed to its generation.
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 1 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 1);
    assert_eq!(ssh::tunnel_count(), 1);
    assert_eq!(pool_manager().pool_count(), 1, "victim pool exists");

    // 8 more distinct tunnels fill the cache; their presence retires
    // the LRU victim (the first tunnel) and its pool with it.
    for i in 0..8 {
        let name = format!("cap-{i}");
        ssh::tunnel_endpoint(
            &name,
            &tunnel,
            Some(fx.ssh_password.as_str()),
            "db",
            3306,
            1,
        )
        .await
        .unwrap();
    }
    assert_eq!(ssh::tunnel_count(), ssh::MAX_TUNNELS, "cache is full");
    let names = ssh::tunnel_connection_names();
    assert!(
        !names.iter().any(|n| n == "ssh-t"),
        "LRU victim retired: {names:?}"
    );
    assert_eq!(
        pool_manager().pool_count(),
        0,
        "retired tunnel's MySQL pool evicted with it"
    );
    let started = std::time::Instant::now();
    while ssh::tunnel_live_tasks() > 0 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "channel tasks must drain"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Encrypted Ed25519 key auth: the `<conn>::ssh` secret doubles as the
/// private-key passphrase.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_encrypted_ed25519_key_auth() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    let Some(key) = fx.key_encrypted.clone() else {
        eprintln!("skipping: encrypted key fixture not generated");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let mut tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Key);
    tunnel.private_key_path = Some(key.display().to_string());
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 5 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 5);
}

/// ECDSA key auth (unencrypted).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_ecdsa_key_auth() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    let Some(key) = fx.key_ecdsa.clone() else {
        eprintln!("skipping: ecdsa key fixture not generated");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let mut tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Key);
    tunnel.private_key_path = Some(key.display().to_string());
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 6 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 6);
}

/// Credential rotation: with the server-side password rotated by the
/// script, the OLD credential must fail authentication (no stale
/// authenticated session is silently reused) and the NEW one works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_rotation_old_credential_rejected() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    let Some(rotated) = fx.ssh_password_rotated.clone() else {
        eprintln!("skipping: rotation fixture not provided");
        return;
    };
    ssh::invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let err = ssh::tunnel_endpoint(
        "rotated",
        &tunnel,
        Some(fx.ssh_password.as_str()),
        "db",
        3306,
        1,
    )
    .await
    .unwrap_err();
    match &err {
        SshError::Auth { user, .. } => assert_eq!(*user, fx.ssh_user),
        other => panic!("expected typed Auth failure for old credential, got {other:?}"),
    }
    let lease = ssh::tunnel_endpoint("rotated", &tunnel, Some(rotated.as_str()), "db", 3306, 1)
        .await
        .unwrap();
    assert!(lease.port > 0);
}

/// TLS-over-SSH (mysql84 variant only): the server certificate is
/// issued for db.internal.test; verification runs against the ORIGINAL
/// database name through sslServerName while the transport is the
/// loopback tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_tls_over_tunnel_hostname_match() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    if std::env::var("SEQUEL_MCP_TEST_SSH_TLS").ok().as_deref() != Some("1") {
        eprintln!("skipping: TLS variant not active (mariadb matrix)");
        return;
    }
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let conn = mysql_conn_tls(
        Some(tunnel.clone()),
        &fx.mysql_user,
        Some("db.internal.test"),
    );
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 11 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 11);
}

/// TLS hostname mismatch through the tunnel: verification must fail
/// closed (typed execution error), never connect on a wrong name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_tls_over_tunnel_hostname_mismatch_denied() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    if std::env::var("SEQUEL_MCP_TEST_SSH_TLS").ok().as_deref() != Some("1") {
        eprintln!("skipping: TLS variant not active (mariadb matrix)");
        return;
    }
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let mut conn = mysql_conn_tls(Some(tunnel.clone()), &fx.mysql_user, Some("wrong.example"));
    conn.ssl_ca_path = std::env::var("SEQUEL_MCP_TEST_SSH_TLS_CA").ok();
    let started = std::time::Instant::now();
    let err = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 12 AS v")
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "mismatch fails fast"
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("tls") || msg.contains("ssl") || msg.contains("certificate"),
        "typed TLS failure: {msg}"
    );
}

/// Phase D (script-driven): a live session + established query, then a
/// full packet blackhole (iptables DROP — no FIN/RST) lands mid-test.
/// The in-flight session must be detected dead within the keepalive
/// budget and the query must fail with a TYPED error inside a bounded
/// window — never hang, never silently succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_halfopen_stale_session_bounded() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    let sentinel = std::env::var("SEQUEL_MCP_TEST_SSH_SENTINEL").ok();
    let Some(sentinel) = sentinel else {
        panic!("phase D requires SEQUEL_MCP_TEST_SSH_SENTINEL");
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);

    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 1 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 1, "pre-blackhole query ok");
    // The Administration preset's statement timeout is 60 s; the
    // half-open assertion below uses a SHORT-timeout policy so the
    // failure window reflects the transport budgets (keepalive +
    // channel-open + grace), not the statement clock.
    let mut short_policy = policy_from_preset(PolicyPresetName::Administration);
    short_policy.stmt_timeout_ms = 3000;

    // Wait for the blackhole to land (bounded).
    let started = std::time::Instant::now();
    loop {
        if std::path::Path::new(&sentinel).exists() {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "sentinel never appeared"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // The stale session cannot carry traffic: the query fails with a
    // typed error inside the keepalive/channel-open budget. No retry,
    // no silent success.
    let started = std::time::Instant::now();
    let err = run_through_tunnel_with_policy(&fx, &conn, &tunnel, "SELECT 2 AS v", short_policy)
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(45),
        "half-open failure must be bounded (took {:?})",
        started.elapsed()
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("timed out")
            || msg.contains("timeout")
            || msg.contains("error")
            || msg.contains("uncertain"),
        "typed failure: {msg}"
    );

    // MUTATION during the blackhole: typed failure, exactly one
    // attempt, no automatic replay (the recovery phase asserts the row
    // never landed).
    let started = std::time::Instant::now();
    let err = run_through_tunnel_with_policy(
        &fx,
        &conn,
        &tunnel,
        "INSERT INTO ssh_t (id) VALUES (4242)",
        {
            let mut p = policy_from_preset(PolicyPresetName::Administration);
            p.stmt_timeout_ms = 3000;
            p
        },
    )
    .await
    .unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(45),
        "mutation failure bounded (took {:?})",
        started.elapsed()
    );
    let _ = err;
}

/// Phase D recovery: after the blackhole clears, a fresh process
/// establishes a new session and queries normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_blackhole_recovery() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 9 AS v")
        .await
        .unwrap();
    assert_eq!(int_cell(&r.rows[0]["v"]), 9);
    // The mutation attempted during the blackhole was NOT replayed: the
    // row never landed.
    let r = run_through_tunnel(
        &fx,
        &conn,
        &tunnel,
        "SELECT COUNT(*) AS n FROM ssh_t WHERE id = 4242",
    )
    .await
    .unwrap();
    assert_eq!(int_cell(&r.rows[0]["n"]), 0, "no automatic mutation replay");
}

/// Optional SSH cold/warm benchmark phase (enabled by the script via
/// SEQUEL_MCP_TEST_SSH_BENCH=1; runs with --nocapture so the stats
/// print). Cold = fresh tunnel establishment per sample (distinct
/// connection identities); warm = repeated queries over ONE tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_bench_cold_warm() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    if std::env::var("SEQUEL_MCP_TEST_SSH_BENCH").ok().as_deref() != Some("1") {
        eprintln!("skipping: bench phase not requested");
        return;
    }
    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let tunnel = ssh_tunnel(&fx, &fx.known_good, SshAuthMethod::Password);
    let n = 20u64;

    let mut cold = Vec::new();
    for i in 0..n {
        let name = format!("bench-{i}");
        ssh::invalidate_all();
        let started = std::time::Instant::now();
        let lease = ssh::tunnel_endpoint(
            &name,
            &tunnel,
            Some(fx.ssh_password.as_str()),
            "db",
            3306,
            1,
        )
        .await
        .unwrap();
        cold.push(started.elapsed().as_secs_f64() * 1000.0);
        let _ = lease;
    }
    let stats = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        format!(
            "median={:.2}ms p95={:.2}ms max={:.2}ms n={}",
            v[v.len() / 2],
            v[(v.len() * 95 / 100).min(v.len() - 1)],
            v[v.len() - 1],
            v.len()
        )
    };
    eprintln!("SSH_COLD_ESTABLISH {}", stats(&mut cold));

    ssh::invalidate_all();
    pool_manager().invalidate_all();
    let conn = mysql_conn(Some(tunnel.clone()), &fx.mysql_user);
    let _ = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 1 AS v")
        .await
        .unwrap();
    let mut warm = Vec::new();
    for _ in 0..n {
        let started = std::time::Instant::now();
        let r = run_through_tunnel(&fx, &conn, &tunnel, "SELECT 41 + 1 AS answer")
            .await
            .unwrap();
        assert_eq!(int_cell(&r.rows[0]["answer"]), 42);
        warm.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    eprintln!("SSH_WARM_QUERY {}", stats(&mut warm));
    eprintln!("BENCH_CLASS=development/directional (debug profile, docker topology)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_gate_end_to_end_with_secrets() {
    let Some(fx) = fixture() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_SSH_* not set");
        return;
    };
    ssh::invalidate_all();
    pool_manager().invalidate_all();

    // Full gate path: config with an SSH connection, secrets injected
    // into an in-memory store (mysql + "<conn>::ssh" password).
    let dir = tempfile::TempDir::new().unwrap();
    let cfg_path = dir.path().join("cfg.json");
    let audit_path = dir.path().join("audit.sqlite");
    let policy = serde_json::json!({
        "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
        "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 15000,
        "requireTouchID": false, "maxBackupRows": 100,
        "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
    });
    std::fs::write(
        &cfg_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 2, "revision": 1, "defaultConnection": "tun",
            "connections": [{
                "driver": "mysql", "name": "tun",
                "host": "db", "port": 3306, "user": fx.mysql_user,
                "database": "app",
                "ssl": tls_variant_active(),
                "sslServerName": if tls_variant_active() { Some("db.internal.test") } else { None },
                "sslCaPath": std::env::var("SEQUEL_MCP_TEST_SSH_TLS_CA").ok(),
                "ssh": {
                    "host": fx.bastion_host, "port": fx.bastion_port,
                    "user": fx.ssh_user, "authMethod": "password",
                    "hostKeyPolicy": "strict",
                    "knownHostsPath": fx.known_good.display().to_string()
                },
                "policy": policy, "tablePolicies": {}
            }],
            "retention": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let secrets = Arc::new(InMemorySecretStore::new());
    secrets
        .set_password("tun", &fx.mysql_user, &fx.mysql_password)
        .unwrap();
    secrets
        .set_password("tun::ssh", &fx.ssh_user, &fx.ssh_password)
        .unwrap();

    let mut deps = GateDeps::with_sink(Box::new(gate::UnavailableSink));
    deps.config = Arc::new(sequel_mcp::config::ConfigStore::with_path(cfg_path));
    deps.audit = Arc::new(sequel_mcp::audit::AuditDb::at_path(&audit_path).unwrap());
    deps.auth = Arc::new(sequel_mcp::vault::touchid::SessionAuthenticator::new(
        Box::new(sequel_mcp::vault::touchid::NoTouchId),
    ));
    deps.secrets = secrets;

    let out = gate::run_sql(
        &deps,
        &RunSqlArgs {
            connection: None,
            sql: "SELECT 7 AS v".into(),
            database: None,
            expected_ddl_targets: None,
        },
        true,
    )
    .expect("gate query through the tunnel");
    assert_eq!(int_cell(&out.rows[0]["v"]), 7);
    assert_eq!(out.connection, "tun");
    std::mem::forget(dir);
}
