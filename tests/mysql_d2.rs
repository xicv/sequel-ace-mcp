//! Live D2 cancellation tests: deadline → KILL QUERY → interruption →
//! rollback → verified-clean reuse / discard. Runs against whichever
//! server `SEQUEL_MCP_TEST_MYSQL` names (MariaDB 11 / MySQL 8.4).

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlError, MySqlExecuteParams, execute_mysql_statement};
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
        name: "d2".into(),
        host: host.into(),
        port,
        user: user.into(),
        database: Some("app".into()),
        ..MySqlConnection::default()
    }
}

struct Ctx {
    conn: MySqlConnection,
    password: String,
    audit: Arc<sequel_mcp::audit::AuditDb>,
}

fn ctx(host: &str, port: u16, user: &str, password: &str) -> Ctx {
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    std::mem::forget(dir); // keep audit db alive for the test duration
    Ctx {
        conn: conn_for(host, port, user),
        password: password.to_string(),
        audit,
    }
}

async fn run_with_policy(
    ctx: &Ctx,
    sql: &str,
    policy: &sequel_mcp::policy::model::Policy,
) -> Result<sequel_mcp::sql::mysql::ExecuteResult, MySqlError> {
    let classified = classify_statement(sql, Dialect::MySql).unwrap();
    execute_mysql_statement(MySqlExecuteParams {
        request_id: format!("req-{}", line!()),
        databases_for_log: vec![],
        connection: &ctx.conn,
        password: Zeroizing::new(ctx.password.clone()),
        sql,
        classified: &classified,
        policy,
        database: None,
        audit: Some(ctx.audit.clone()),
        revision: 1,
        tunnel_endpoint: None,
    })
    .await
}

async fn exec_raw(ctx: &Ctx, sql: &str) -> Vec<serde_json::Value> {
    let policy = policy_from_preset(PolicyPresetName::Administration);
    let r = run_with_policy(ctx, sql, &policy).await.unwrap();
    r.rows
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_kills_statement_and_preserves_state() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();
    let ctx = ctx(&host, port, &user, &password);

    // Fixtures: a counter table and a stored sleep via UDF-free UPDATE.
    exec_raw(&ctx, "DROP TABLE IF EXISTS d2_items").await;
    exec_raw(
        &ctx,
        "CREATE TABLE d2_items (id INT PRIMARY KEY, value INT)",
    )
    .await;
    exec_raw(&ctx, "INSERT INTO d2_items (id, value) VALUES (1, 100)").await;

    // --- Case 1: mutating timeout. The UPDATE sleeps server-side; under a
    // 400 ms deadline the KILL QUERY path must interrupt it, roll back,
    // and leave the row unchanged.
    let mut tight = policy_from_preset(PolicyPresetName::Administration);
    tight.stmt_timeout_ms = 400;
    let started = Instant::now();
    let outcome = run_with_policy(
        &ctx,
        "UPDATE d2_items SET value = value + 1 WHERE id = 1 AND SLEEP(5) = 0",
        &tight,
    )
    .await;
    let elapsed = started.elapsed();
    match &outcome {
        Err(MySqlError::Timeout(ms)) => assert_eq!(*ms, 400),
        Err(MySqlError::Uncertain(_)) => {}
        other => panic!("expected Timeout/Uncertain, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(6),
        "cancellation must be prompt: {elapsed:?}"
    );

    // Mutation did NOT commit.
    let rows = exec_raw(&ctx, "SELECT value FROM d2_items WHERE id = 1").await;
    let value = match &rows[0]["value"] {
        serde_json::Value::Number(n) => n.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        other => panic!("{other}"),
    };
    assert_eq!(value, 100, "timed-out mutation must not commit");

    // No lingering statement on the server for this user.
    let procs = exec_raw(
        &ctx,
        "SELECT COUNT(*) AS n FROM information_schema.processlist WHERE INFO LIKE '%SLEEP(5)%' AND ID <> CONNECTION_ID()",
    )
    .await;
    let n = match &procs[0]["n"] {
        serde_json::Value::Number(v) => v.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        other => panic!("{other}"),
    };
    assert_eq!(n, 0, "interrupted statement must leave the process list");

    // The next operation on the pool works (clean state or fresh conn).
    let rows = exec_raw(&ctx, "SELECT value FROM d2_items WHERE id = 1").await;
    let _ = rows;

    // --- Case 2: read timeout via KILL (SELECT SLEEP is also covered by
    // MAX_EXECUTION_TIME, but the client deadline fires first at 300 ms).
    let mut read_policy = policy_from_preset(PolicyPresetName::ReadOnly);
    read_policy.stmt_timeout_ms = 300;
    let started = Instant::now();
    let outcome = run_with_policy(&ctx, "SELECT SLEEP(5) AS z", &read_policy).await;
    let elapsed = started.elapsed();
    assert!(
        matches!(
            outcome,
            Err(MySqlError::Timeout(300)) | Err(MySqlError::Uncertain(_))
        ),
        "{outcome:?}"
    );
    assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");

    // --- Case 3: lock wait between two physical connections. Conn A
    // holds a row lock inside a transaction (via a pooled op that we then
    // leave dangling by using a dedicated raw pool), while conn B's UPDATE
    // on the same row must hit its deadline and be interrupted.
    //
    // Setup uses an explicit separate pooled connection held open.
    let pool_conn = {
        let pool = pool_manager()
            .verified_pool(
                &ctx.conn,
                &Zeroizing::new(ctx.password.clone()),
                None,
                1,
                None,
                None,
            )
            .await
            .unwrap();
        pool.get_conn().await.unwrap()
    };
    let mut holder = pool_conn;
    use mysql_async::prelude::Queryable as _;
    holder.query_drop("BEGIN").await.unwrap();
    holder
        .exec_drop("UPDATE d2_items SET value = 101 WHERE id = 1", ())
        .await
        .unwrap();

    let mut lock_policy = policy_from_preset(PolicyPresetName::Administration);
    lock_policy.stmt_timeout_ms = 500;
    let started = Instant::now();
    let outcome = run_with_policy(
        &ctx,
        "UPDATE d2_items SET value = 999 WHERE id = 1",
        &lock_policy,
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        matches!(
            outcome,
            Err(MySqlError::Timeout(500)) | Err(MySqlError::Uncertain(_))
        ),
        "{outcome:?}"
    );
    assert!(elapsed < Duration::from_secs(6), "{elapsed:?}");

    // Release A's lock and confirm B never landed.
    holder.query_drop("ROLLBACK").await.unwrap();
    let rows = exec_raw(&ctx, "SELECT value FROM d2_items WHERE id = 1").await;
    let value = match &rows[0]["value"] {
        serde_json::Value::Number(n) => n.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        other => panic!("{other}"),
    };
    assert_eq!(value, 100, "lock-waiting update must not commit");

    // --- Server still healthy afterwards.
    let rows = exec_raw(&ctx, "SELECT 1 AS ok").await;
    assert!(!rows.is_empty());
}
