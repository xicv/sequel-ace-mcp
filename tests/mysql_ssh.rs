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

fn mysql_conn(ssh: Option<SshTunnel>, mysql_user: &str) -> MySqlConnection {
    MySqlConnection {
        name: "ssh-t".into(),
        host: "db".into(), // reachable only from the bastion's network
        port: 3306,
        user: mysql_user.to_string(),
        database: Some("app".into()),
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
    let endpoint = ssh::tunnel_endpoint(
        &conn.name,
        tunnel,
        Some(fx.ssh_password.as_str()),
        &conn.host,
        conn.port,
    )
    .await?;
    let policy = policy_from_preset(PolicyPresetName::Administration);
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
    let again = ssh::tunnel_endpoint("ssh-t", &tunnel, Some(&fx.ssh_password), "db", 3306)
        .await
        .unwrap();
    assert_eq!(ssh::tunnel_count(), 1, "a second endpoint call reuses");
    assert!(again.1 > 0);
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
    let err = ssh::tunnel_endpoint("mismatch", &tunnel, Some(&fx.ssh_password), "db", 3306)
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
    let err = ssh::tunnel_endpoint("unknown", &tunnel, Some(&fx.ssh_password), "db", 3306)
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
    let err = ssh::tunnel_endpoint("dead", &tunnel, Some(&fx.ssh_password), "db", 3306)
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
    let err = ssh::tunnel_endpoint("revoked", &tunnel, Some(&fx.ssh_password), "db", 3306)
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
    let err = ssh::tunnel_endpoint("missingfile", &tunnel, Some(&fx.ssh_password), "db", 3306)
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
    let err = ssh::tunnel_endpoint("malformed", &tunnel, Some(&fx.ssh_password), "db", 3306)
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
                "database": "app", "ssl": false,
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
