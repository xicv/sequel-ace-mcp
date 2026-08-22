//! Live MySQL/MariaDB integration test. Runs only when
//! SEQUEL_MCP_TEST_MYSQL points at a reachable server
//! (e.g. `127.0.0.1:3307` via the local test container); otherwise skips.

use sequel_mcp::audit::AuditDb;
use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use std::sync::Arc;
use zeroize::Zeroizing;

fn test_target() -> Option<(String, u16, String, String)> {
    let spec = std::env::var("SEQUEL_MCP_TEST_MYSQL").ok()?;
    // host:port:user:password
    let mut parts = spec.splitn(4, ':');
    let host = parts.next()?.to_string();
    let port: u16 = parts.next()?.parse().ok()?;
    let user = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    Some((host, port, user, password))
}

fn conn_for(host: &str, port: u16, user: &str) -> MySqlConnection {
    MySqlConnection {
        name: "it-mysql".into(),
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
    policy: &sequel_mcp::policy::model::Policy,
    audit: &Arc<AuditDb>,
) -> Result<sequel_mcp::sql::mysql::ExecuteResult, String> {
    let classified = classify_statement(sql, Dialect::MySql).map_err(|e| e.message())?;
    execute_mysql_statement(MySqlExecuteParams {
        request_id: format!("req-{}", line!()),
        databases_for_log: vec![],
        connection: conn,
        password: Zeroizing::new(password.to_string()),
        sql,
        classified: &classified,
        policy,
        database: None,
        audit: Some(audit.clone()),
        revision: 1,
        tunnel_endpoint: None,
        expected_ddl_targets: None,
    })
    .await
    .map_err(|e| e.to_string())
}

#[tokio::test]
async fn mysql_end_to_end() {
    let Some((host, port, user, password)) = test_target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    let dir = tempfile::TempDir::new().unwrap();
    let audit = Arc::new(AuditDb::at_path(&dir.path().join("audit.sqlite")).unwrap());
    let conn = conn_for(&host, port, &user);
    let admin = {
        let mut p = policy_from_preset(PolicyPresetName::Administration);
        p.require_touch_id = false;
        p
    };

    // DDL
    run(
        &conn,
        &password,
        "DROP TABLE IF EXISTS jobs",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    let r = run(
        &conn,
        &password,
        "CREATE TABLE jobs (id BIGINT PRIMARY KEY, amount DECIMAL(20,4), qty INT, note TEXT)",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(r.affected_rows, 0);

    // INSERT with insert-hint backup (autoincrement range).
    let r = run(
        &conn,
        &password,
        "INSERT INTO jobs (id, amount, qty, note) VALUES (1, 1234567890123456.7890, 7, 'seed')",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(r.affected_rows, 1);
    assert!(r.backup_id.is_some(), "insert-hint backup expected");

    // UPDATE with row backup (FOR UPDATE pre-image select).
    let r = run(
        &conn,
        &password,
        "UPDATE jobs SET note = 'changed' WHERE id = 1",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(r.affected_rows, 1);
    assert!(r.backup_id.is_some(), "row backup expected");

    // SELECT with numeric fidelity: DECIMAL and BIGINT stay lossless
    // strings (legacy bigNumberStrings), INT coerces to a number.
    let r = run(
        &conn,
        &password,
        "SELECT id, amount, qty FROM jobs WHERE id = 1",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.fields, vec!["id", "amount", "qty"]);
    let amount = r.rows[0]["amount"].as_str().expect("decimal as string");
    assert!(
        amount.replace('.', "").chars().all(|c| c.is_ascii_digit()),
        "lossless decimal digits: {amount}"
    );
    // BIGINT ids stay strings for lossless round-tripping.
    assert_eq!(r.rows[0]["id"], serde_json::json!("1"));
    // INT columns are numbers, like the legacy driver.
    assert_eq!(r.rows[0]["qty"], serde_json::json!(7));

    // Row cap streaming.
    run(
        &conn,
        &password,
        "INSERT INTO jobs (id, amount, qty, note) VALUES (2, 2.5, 8, 'x'), (3, 3.5, 9, 'y')",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    let mut capped = admin.clone();
    capped.row_cap = 1;
    let r = run(
        &conn,
        &password,
        "SELECT id FROM jobs ORDER BY id",
        &capped,
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(r.rows.len(), 1);
    assert!(r.truncated);

    // Pool reuse: a second execution goes through the same pooled registry.
    let r2 = run(
        &conn,
        &password,
        "SELECT COUNT(*) AS n FROM jobs",
        &admin,
        &audit,
    )
    .await
    .unwrap();
    // COUNT(*) is BIGINT — a lossless string under bigNumberStrings.
    assert_eq!(r2.rows[0]["n"], serde_json::json!("3"));
    assert!(sequel_mcp::sql::mysql::pool_manager().pool_count() >= 1);

    // Backups were persisted.
    let backups = sequel_mcp::backup::list_backups(&audit, Some("it-mysql"), 10).unwrap();
    assert!(backups.len() >= 2, "hint + row backups: {:?}", backups);
}
