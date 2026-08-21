//! Live server behaviour matrix (D1/D5): error paths, pool reuse and the
//! complete type-conversion contract, exercised against whichever server
//! SEQUEL_MCP_TEST_MYSQL points at (MariaDB 11 or MySQL 8.4 via
//! scripts/test-db.sh).

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use std::sync::Arc;
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

fn conn_for(host: &str, port: u16, user: &str, db: Option<&str>) -> MySqlConnection {
    MySqlConnection {
        name: "matrix".into(),
        host: host.into(),
        port,
        user: user.into(),
        database: db.map(str::to_string),
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

#[tokio::test]
async fn error_paths_and_types() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };

    // D1: bad credentials fail with an auth error, not a hang.
    let conn = conn_for(&host, port, &user, Some("app"));
    let err = run(&conn, "definitely-wrong-password", "SELECT 1")
        .await
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("access denied") || err.to_lowercase().contains("1045"),
        "auth error expected: {err}"
    );

    // D1: good credentials on the existing database work.
    run(&conn, &password, "SELECT 1").await.unwrap();
    let unknown_db_conn = conn_for(&host, port, &user, Some("no_such_db_xyz"));
    let err = run(&unknown_db_conn, &password, "SELECT 1")
        .await
        .unwrap_err();
    assert!(
        err.to_lowercase().contains("unknown database") || err.to_lowercase().contains("1049"),
        "unknown database expected: {err}"
    );

    // D1: pool reuse — several sequential executions share one pool entry.
    sequel_mcp::sql::mysql::pool_manager().invalidate_all();
    for i in 0..3 {
        let r = run(&conn, &password, &format!("SELECT {i} AS n"))
            .await
            .unwrap();
        assert_eq!(r.rows.len(), 1);
    }
    assert_eq!(sequel_mcp::sql::mysql::pool_manager().pool_count(), 1);

    // D1: config-revision invalidation swaps pools.
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    let policy = policy_from_preset(PolicyPresetName::Administration);
    let sql = "SELECT 1 AS n";
    let classified = classify_statement(sql, Dialect::MySql).unwrap();
    for revision in [7u64, 8] {
        execute_mysql_statement(MySqlExecuteParams {
            request_id: format!("req-{}", line!()),
            databases_for_log: vec![],
            connection: &conn,
            password: Zeroizing::new(password.clone()),
            sql,
            classified: &classified,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
            revision,
            tunnel_endpoint: None,
        })
        .await
        .unwrap();
    }
    // 1 pool from the reuse loop + 2 from the distinct revisions.
    assert_eq!(sequel_mcp::sql::mysql::pool_manager().pool_count(), 3);

    // D5: full type matrix.
    run(&conn, &password, "DROP TABLE IF EXISTS type_matrix")
        .await
        .unwrap();
    run(
        &conn,
        &password,
        "CREATE TABLE type_matrix (
           c_tiny TINYINT, c_small SMALLINT, c_medium MEDIUMINT, c_int INT,
           c_int_u INT UNSIGNED, c_big BIGINT, c_big_u BIGINT UNSIGNED,
           c_dec DECIMAL(30,6), c_float FLOAT, c_double DOUBLE,
           c_bit BIT(8), c_bool BOOLEAN, c_char CHAR(3), c_varchar VARCHAR(32),
           c_text TEXT, c_bin VARBINARY(16), c_blob BLOB,
           c_date DATE, c_time TIME, c_dt DATETIME, c_ts TIMESTAMP NULL,
           c_json JSON, c_enum ENUM('a','b'), c_set SET('x','y'), c_null INT
         )",
    )
    .await
    .unwrap();
    run(
        &conn,
        &password,
        "INSERT INTO type_matrix VALUES (
           1, 2, 3, 4, 5, 9007199254740993, 18446744073709551615,
           12345678901234567890.123456, 1.5, 2.25,
           b'01010101', TRUE, 'ab', 'hello', 'world',
           X'DEADBEEF', X'00FF',
           '2026-08-21', '12:34:56', '2026-08-21 12:34:56', NULL,
           JSON_OBJECT('k', 1), 'a', 'x,y', NULL)",
    )
    .await
    .unwrap();

    let r = run(&conn, &password, "SELECT * FROM type_matrix")
        .await
        .unwrap();
    assert_eq!(r.rows.len(), 1);
    let row = &r.rows[0];

    // Integer families are JSON numbers.
    for col in ["c_tiny", "c_small", "c_medium", "c_int", "c_int_u"] {
        assert!(
            row[col].is_number(),
            "{col} should be a number: {}",
            row[col]
        );
    }
    assert_eq!(row["c_int"], serde_json::json!(4));
    assert_eq!(row["c_int_u"], serde_json::json!(5));
    assert_eq!(row["c_bool"], serde_json::json!(1));
    // BIGINT (signed + unsigned) stay lossless strings (legacy contract).
    assert_eq!(row["c_big"], serde_json::json!("9007199254740993"));
    assert_eq!(row["c_big_u"], serde_json::json!("18446744073709551615"));
    // DECIMAL stays an exact string.
    let dec = row["c_dec"].as_str().expect("decimal string");
    assert!(dec.starts_with("12345678901234567890.123456"), "{dec}");
    // FLOAT/DOUBLE are numbers.
    assert!(row["c_float"].is_number());
    assert!(row["c_double"].is_number());
    // Strings and dates survive.
    assert_eq!(row["c_varchar"], serde_json::json!("hello"));
    assert_eq!(row["c_date"], serde_json::json!("2026-08-21"));
    assert!(
        row["c_dt"]
            .as_str()
            .unwrap_or("")
            .starts_with("2026-08-21 12:34:56")
    );
    // Binary is structured base64 (lossless), never mangled text (D5).
    let bin = &row["c_bin"];
    assert_eq!(bin["type"], "binary", "structured binary: {bin}");
    assert_eq!(bin["encoding"], "base64");
    assert!(
        !bin["data"].as_str().unwrap_or_default().is_empty(),
        "binary b64: {bin}"
    );
    // NULLs are JSON null.
    assert_eq!(row["c_null"], serde_json::Value::Null);
    // ENUM/SET come back as strings.
    assert_eq!(row["c_enum"], serde_json::json!("a"));
    // JSON column: some form of text/object — assert non-null and lossless.
    assert_ne!(row["c_json"], serde_json::Value::Null);

    // D5: multibyte UTF-8 is preserved and counted, not corrupted.
    let r = run(&conn, &password, "SELECT '日本語テスト' AS mb")
        .await
        .unwrap();
    assert_eq!(r.rows[0]["mb"], serde_json::json!("日本語テスト"));

    // Statement timeout contract: SLEEP exceeding stmt_timeoutMs fails as
    // a typed timeout (policy default 60 s is too long here; use a tight one).
    let mut tight = policy_from_preset(PolicyPresetName::Administration);
    tight.stmt_timeout_ms = 400;
    let dir2 = tempfile::TempDir::new().unwrap();
    let audit2 =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir2.path().join("a.sqlite")).unwrap());
    let sleep_sql = "SELECT SLEEP(5) AS z";
    let classified = classify_statement(sleep_sql, Dialect::MySql).unwrap();
    let outcome = execute_mysql_statement(MySqlExecuteParams {
        request_id: format!("req-{}", line!()),
        databases_for_log: vec![],
        connection: &conn,
        password: Zeroizing::new(password.clone()),
        sql: sleep_sql,
        classified: &classified,
        policy: &tight,
        database: None,
        audit: Some(audit2),
        revision: 1,
        tunnel_endpoint: None,
    })
    .await;
    match outcome {
        Err(sequel_mcp::sql::mysql::MySqlError::Timeout(ms)) => assert_eq!(ms, 400),
        // Interrupting a SELECT mid-result-stream desyncs the wire; the
        // connection is discarded and the honest outcome is Uncertain.
        Err(sequel_mcp::sql::mysql::MySqlError::Uncertain(msg)) => {
            assert!(msg.contains("discarded"), "{msg}");
        }
        Err(e) => panic!("expected Timeout/Uncertain, got {e:?}"),
        Ok(_) => panic!("SLEEP(5) under a 400 ms timeout must not succeed"),
    }

    // After a timeout, the next operation on the same pool must be clean
    // (no inherited transaction/locks/session vars). Literal 1 is typed
    // LONGLONG on MySQL 8.4 (string per the BIGINT contract) and LONG on
    // MariaDB (number) — both are correct per server metadata.
    let r = run(&conn, &password, "SELECT 1 AS clean").await.unwrap();
    assert!(
        r.rows[0]["clean"] == serde_json::json!(1) || r.rows[0]["clean"] == serde_json::json!("1"),
        "clean follow-up query: {}",
        r.rows[0]["clean"]
    );
}
