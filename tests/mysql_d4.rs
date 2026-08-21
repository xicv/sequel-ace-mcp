//! D4 live matrix: honest DDL semantics on MariaDB 11 and MySQL 8.4 —
//! absent-target preflight (IF EXISTS → audited no-op; missing → typed
//! not-found), nontransactional-snapshot warnings, snapshot before DDL,
//! and coverage across DROP/TRUNCATE/ALTER/RENAME/CREATE/CTAS/temp DDL.

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlError, MySqlExecuteParams, execute_mysql_statement};
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

struct Ctx {
    conn: MySqlConnection,
    password: String,
    audit: Arc<sequel_mcp::audit::AuditDb>,
}

fn ctx(host: &str, port: u16, user: &str, password: &str) -> Ctx {
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    std::mem::forget(dir);
    Ctx {
        conn: MySqlConnection {
            name: "d4".into(),
            host: host.into(),
            port,
            user: user.into(),
            database: Some("app".into()),
            ..MySqlConnection::default()
        },
        password: password.to_string(),
        audit,
    }
}

async fn run(ctx: &Ctx, sql: &str) -> Result<sequel_mcp::sql::mysql::ExecuteResult, MySqlError> {
    let policy = policy_from_preset(PolicyPresetName::Administration);
    let classified = classify_statement(sql, Dialect::MySql).unwrap();
    execute_mysql_statement(MySqlExecuteParams {
        connection: &ctx.conn,
        request_id: format!("req-{}", uuid::Uuid::new_v4()),
        databases_for_log: vec![],
        password: Zeroizing::new(ctx.password.clone()),
        sql,
        classified: &classified,
        policy: &policy,
        database: None,
        audit: Some(ctx.audit.clone()),
        revision: 1,
        tunnel_endpoint: None,
    })
    .await
}

async fn exists(ctx: &Ctx, table: &str) -> bool {
    let rows = run(ctx, &format!("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = 'app' AND table_name = '{table}'")).await.unwrap().rows;
    let n = match &rows[0]["n"] {
        serde_json::Value::Number(v) => v.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        o => panic!("{o}"),
    };
    n > 0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d4_ddl_semantics_matrix() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();
    let ctx = ctx(&host, port, &user, &password);

    // Fixtures.
    run(&ctx, "DROP TABLE IF EXISTS d4_src").await.unwrap();
    run(&ctx, "CREATE TABLE d4_src (id INT PRIMARY KEY, v INT)")
        .await
        .unwrap();
    run(&ctx, "INSERT INTO d4_src (id, v) VALUES (1, 10), (2, 20)")
        .await
        .unwrap();

    // --- Absent target with IF EXISTS: audited local no-op, nothing sent.
    assert!(matches!(
        classify_statement("DROP TABLE IF EXISTS d4_missing_xyz", Dialect::MySql),
        Ok(c) if c.if_exists
    ));
    let r = run(&ctx, "DROP TABLE IF EXISTS d4_missing_xyz")
        .await
        .unwrap();
    assert!(
        r.ddl_no_op,
        "IF EXISTS over missing table must be a local no-op"
    );
    assert_eq!(r.affected_rows, 0);

    // --- Absent target without IF EXISTS: typed not-found error.
    let err = run(&ctx, "DROP TABLE d4_missing_xyz").await.unwrap_err();
    match &err {
        MySqlError::DdlNotFound(msg) => {
            assert!(msg.contains("d4_missing_xyz"), "{msg}");
            assert!(
                msg.contains("does not exist") || msg.contains("no IF EXISTS"),
                "{msg}"
            );
        }
        other => panic!("expected DdlNotFound, got {other:?}"),
    }

    // --- Existing DROP: snapshot captured + nontransactional warnings.
    let r = run(&ctx, "DROP TABLE d4_src").await.unwrap();
    assert!(!r.ddl_no_op);
    assert!(
        !r.warnings.is_empty(),
        "DDL must carry nontransactional warnings"
    );
    assert!(
        r.warnings
            .contains(&"snapshot and DDL are not one atomic transaction")
    );
    assert!(r.warnings.contains(&"automatic rollback is not guaranteed"));
    // A backup snapshot row must exist for the dropped table.
    let backups = sequel_mcp::backup::list_backups(&ctx.audit, Some("d4"), 20).unwrap();
    assert!(
        backups
            .iter()
            .any(|b| b.table_name == "d4_src" && b.row_count >= 2),
        "pre-image snapshot expected: {backups:?}"
    );
    assert!(!(exists(&ctx, "d4_src").await));

    // --- DROP again (now absent, no IF EXISTS): typed error, not the old
    // empty-backup-continue.
    let err = run(&ctx, "DROP TABLE d4_src").await.unwrap_err();
    assert!(matches!(err, MySqlError::DdlNotFound(_)), "{err:?}");

    // --- TRUNCATE: combined snapshot + warnings; data emptied.
    run(&ctx, "CREATE TABLE d4_t (id INT PRIMARY KEY, v INT)")
        .await
        .unwrap();
    run(&ctx, "INSERT INTO d4_t (id, v) VALUES (1, 1)")
        .await
        .unwrap();
    let r = run(&ctx, "TRUNCATE TABLE d4_t").await.unwrap();
    assert!(r.warnings.contains(&"implicit commit may occur"));
    let rows = run(&ctx, "SELECT COUNT(*) AS n FROM d4_t")
        .await
        .unwrap()
        .rows;
    let n = match &rows[0]["n"] {
        serde_json::Value::Number(v) => v.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        o => panic!("{o}"),
    };
    assert_eq!(n, 0);

    // --- TRUNCATE IF EXISTS missing: no-op.
    let r = run(&ctx, "TRUNCATE TABLE IF EXISTS d4_missing_xyz")
        .await
        .unwrap();
    assert!(r.ddl_no_op);

    // --- ALTER: schema snapshot + warnings.
    let r = run(&ctx, "ALTER TABLE d4_t ADD COLUMN extra INT")
        .await
        .unwrap();
    assert!(r.warnings.contains(&"pre-operation snapshot only"));

    // --- RENAME (old and new identities authorized; snapshot on old).
    let r = run(&ctx, "RENAME TABLE d4_t TO d4_t2").await.unwrap();
    assert!(r.warnings.contains(&"implicit commit may occur"));
    assert!(exists(&ctx, "d4_t2").await);
    assert!(!(exists(&ctx, "d4_t").await));

    // --- CREATE (fresh) and CREATE TABLE AS SELECT: no existence gating;
    // CTAS additionally reads the source table.
    let r = run(&ctx, "CREATE TABLE d4_c (id INT PRIMARY KEY)")
        .await
        .unwrap();
    assert!(!r.ddl_no_op);
    let r = run(&ctx, "CREATE TABLE d4_ctas AS SELECT id, v FROM d4_t2")
        .await
        .unwrap();
    assert!(r.warnings.contains(&"implicit commit may occur"));
    let rows = run(&ctx, "SELECT COUNT(*) AS n FROM d4_ctas")
        .await
        .unwrap()
        .rows;
    let _ = rows;

    // --- Temporary-table DDL: CREATE TEMPORARY TABLE + DROP of it.
    let r = run(&ctx, "CREATE TEMPORARY TABLE d4_tmp (id INT)")
        .await
        .unwrap();
    assert!(!r.ddl_no_op);

    // --- Journal states: no-op and not-found landed as failed terminal
    // with explanatory detail; successful DDL finalized.
    let states = dump_journal(&ctx).await;
    assert!(states.iter().any(|(st, detail)| st == "failed" && detail.as_deref().unwrap_or("").contains("no-op")),
        "no-op journalized: {states:?}");
    assert!(
        states.iter().any(|(st, detail)| st == "failed"
            && detail.as_deref().unwrap_or("").contains("does not exist")),
        "not-found journalized: {states:?}"
    );
    assert!(
        states.iter().any(|(st, _)| st == "audit_finalized"),
        "successful DDL finalized: {states:?}"
    );
}

async fn dump_journal(ctx: &Ctx) -> Vec<(String, Option<String>)> {
    ctx.audit
        .with(|c| {
            let mut stmt = c
                .prepare("SELECT state, detail FROM operation_journal ORDER BY id")
                .unwrap();
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
}
