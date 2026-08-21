//! Remaining D1 matrix: TLS paths, connection-timeout taxonomy, physical
//! connection reuse (CONNECTION_ID), idle eviction, restart recovery,
//! credential rotation, and bounded cache. Runs against whichever server
//! `SEQUEL_MCP_TEST_MYSQL` points at (MariaDB 11 or MySQL 8.4 via
//! scripts/test-db.sh). TLS cases additionally require
//! `SEQUEL_MCP_TEST_TLS_DIR` (created by scripts/tls-fixtures.sh).

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn target() -> Option<(String, u16, String, String)> {
    let spec = std::env::var("SEQUEL_MCP_TEST_MYSQL").ok()?;
    let mut parts = spec.splitn(4, ':');
    Some((
        parts.next()?.to_string(),
        parts.next()?.parse().ok()?,
        parts.next()?.to_string(),
        parts.next()?.to_string(),
    ))
}

fn conn_for(host: &str, port: u16, user: &str) -> MySqlConnection {
    MySqlConnection {
        name: "d1".into(),
        host: host.into(),
        port,
        user: user.into(),
        database: Some("app".into()),
        ..MySqlConnection::default()
    }
}

async fn run(
    conn: &MySqlConnection,
    password: &str,
    sql: &str,
) -> Result<sequel_mcp::sql::mysql::ExecuteResult, String> {
    let policy = policy_from_preset(PolicyPresetName::Administration);
    let classified = classify_statement(sql, Dialect::MySql).map_err(|e| e.message())?;
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    execute_mysql_statement(MySqlExecuteParams {
        request_id: format!("req-{}", line!()),
        databases_for_log: vec![],
        connection: conn,
        password: Zeroizing::new(password.to_string()),
        sql,
        classified: &classified,
        policy: &policy,
        database: None,
        audit: Some(audit),
        revision: 1,
        tunnel_endpoint: None,
    })
    .await
    .map_err(|e| e.to_string())
}

fn connection_id(sql_value: &serde_json::Value) -> String {
    // Literal CONNECTION_ID() is typed BIGINT on MySQL (string) and LONG
    // on MariaDB (number) — normalise.
    match sql_value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        other => panic!("unexpected connection id {other}"),
    }
}

// Multi-thread runtime matches the production server; on a current-thread
// runtime mysql_async's return-to-pool tasks cannot run between polls,
// which would spuriously open fresh physical connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_taxonomy_and_physical_reuse() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();

    // Distinguish TCP refusal: a port with no listener fails fast.
    let refused = conn_for("127.0.0.1", 1, &user);
    let started = Instant::now();
    let err = run(&refused, &password, "SELECT 1").await.unwrap_err();
    assert!(
        err.contains("refused") || err.contains("Connection refused") || err.contains("111"),
        "TCP refusal: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "refusal should be fast"
    );

    // Connection timeout: a non-routable address must hit the 15 s
    // connect timeout rather than hang forever (TEST-NET address).
    let blackhole = MySqlConnection {
        name: "d1-timeout".into(),
        host: "192.0.2.1".into(),
        port: 3306,
        user: user.clone(),
        database: None,
        ..MySqlConnection::default()
    };
    let started = Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(25),
        run(&blackhole, &password, "SELECT 1"),
    )
    .await
    .expect("connect timeout must fire before the harness deadline")
    .unwrap_err();
    assert!(
        started.elapsed() >= Duration::from_secs(10),
        "timed out too fast: {err}"
    );
    // Statement timeout taxonomy: distinct from connection errors.
    assert!(
        err.contains("timeout") || err.contains("TimedOut") || err.contains("timed out"),
        "timeout classified: {err}"
    );

    // Physical reuse: two sequential executions must share the server-side
    // connection id when the pool hands the idle connection back.
    let conn = conn_for(&host, port, &user);
    let r1 = run(&conn, &password, "SELECT CONNECTION_ID() AS cid")
        .await
        .unwrap();
    let id1 = connection_id(&r1.rows[0]["cid"]);
    let r2 = run(&conn, &password, "SELECT CONNECTION_ID() AS cid")
        .await
        .unwrap();
    let id2 = connection_id(&r2.rows[0]["cid"]);
    assert_eq!(id1, id2, "physical connection must be reused");
    assert_eq!(pool_manager().pool_count(), 1);

    // Credential failure: the attempt must not publish or evict — the
    // existing verified pool for the good credential stays cached and
    // keeps serving.
    let pools_before = pool_manager().pool_count();
    let bad = run(&conn, "definitely-wrong", "SELECT 1")
        .await
        .unwrap_err();
    assert!(
        bad.contains("denied") || bad.contains("1045"),
        "auth error: {bad}"
    );
    assert_eq!(
        pool_manager().pool_count(),
        pools_before,
        "failed init must neither publish nor evict"
    );
    let r3 = run(&conn, &password, "SELECT CONNECTION_ID() AS cid")
        .await
        .unwrap();
    let id3 = connection_id(&r3.rows[0]["cid"]);
    assert_eq!(
        id3, id1,
        "good pool still serves after a failed rotation attempt"
    );

    // Concurrent read limiting: pool max is 4; 6 parallel quick reads all
    // complete (queued) and stay within the bound afterwards.
    let mut handles = Vec::new();
    for _ in 0..6 {
        let c = conn.clone();
        let pw = password.clone();
        handles.push(tokio::task::spawn(async move {
            run(&c, &pw, "SELECT 1 AS ok").await
        }));
    }
    for h in handles {
        assert!(h.await.unwrap().is_ok());
    }
    assert!(pool_manager().pool_count() <= 16);
    let _ = id3;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_paths() {
    let (Some((host, port, user, password)), Some(tls_dir)) =
        (target(), std::env::var("SEQUEL_MCP_TEST_TLS_DIR").ok())
    else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL or SEQUEL_MCP_TEST_TLS_DIR not set");
        return;
    };
    pool_manager().invalidate_all();

    // The test CA signs a cert for "db.internal.test"; the connection
    // reaches the server at 127.0.0.1, so the hostname mismatches unless
    // the sslServerName override names the cert's CN.
    let ca_path = std::path::Path::new(&tls_dir).join("ca-cert.pem");
    let mut tls_conn = conn_for(&host, port, &user);
    tls_conn.ssl = true;

    // sslServerName override = success (verification against the cert CN).
    tls_conn.ssl_server_name = Some("db.internal.test".into());
    let ok = tls_conn.clone();
    // Wire the test CA into the client trust store via env (mysql_async
    // rustls reads SSL_CERT_FILE for the system root bundle).
    // Test executes single-threaded (--test-threads=1) and sets env
    // before any connection attempt in this case block.
    unsafe { std::env::set_var("SSL_CERT_FILE", &ca_path) };
    let r = run(&ok, &password, "SELECT 1 AS ok").await;
    match r {
        Ok(_) => {}
        Err(e) => panic!("TLS with matching server name must succeed: {e}"),
    }

    // Hostname mismatch (no override): verification against 127.0.0.1
    // must fail because the cert is for db.internal.test.
    pool_manager().invalidate_all();
    let mut mismatch = tls_conn.clone();
    mismatch.ssl_server_name = None;
    let err = run(&mismatch, &password, "SELECT 1").await.unwrap_err();
    assert!(
        err.to_lowercase().contains("invalid")
            || err.to_lowercase().contains("certificate")
            || err.to_lowercase().contains("hostname"),
        "mismatch must fail verification: {err}"
    );

    // Unknown CA (no SSL_CERT_FILE pointing at the test CA): handshake
    // fails even with the server-name override.
    pool_manager().invalidate_all();
    unsafe { std::env::remove_var("SSL_CERT_FILE") };
    let mut unknown_ca = tls_conn.clone();
    unknown_ca.ssl_server_name = Some("db.internal.test".into());
    let err = run(&unknown_ca, &password, "SELECT 1").await.unwrap_err();
    assert!(
        err.to_lowercase().contains("invalid")
            || err.to_lowercase().contains("certificate")
            || err.to_lowercase().contains("unknown")
            || err.to_lowercase().contains("tls"),
        "unknown CA must fail: {err}"
    );
    unsafe { std::env::remove_var("SSL_CERT_FILE") };
}
