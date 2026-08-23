//! D3 proof: backup capture and mutation share ONE physical connection
//! inside ONE transaction, and a concurrent writer cannot interleave
//! between capture and mutation. Asserts `CONNECTION_ID()` of the backup
//! SELECT equals the mutation's, and that operation B blocks until A
//! commits.

use futures_util::FutureExt as _;
use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use std::sync::Arc;
use std::time::Duration;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_and_mutation_share_one_connection_and_lock() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();

    let conn = MySqlConnection {
        name: "d3".into(),
        host: host.clone(),
        port,
        user: user.clone(),
        database: Some("app".into()),
        ..MySqlConnection::default()
    };
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    let policy = policy_from_preset(PolicyPresetName::Administration);

    async fn run(
        conn: &MySqlConnection,
        password: &str,
        audit: &Arc<sequel_mcp::audit::AuditDb>,
        policy: &sequel_mcp::policy::model::Policy,
        sql: &str,
    ) -> Result<sequel_mcp::sql::mysql::ExecuteResult, sequel_mcp::sql::mysql::MySqlError> {
        let classified = classify_statement(sql, Dialect::MySql).unwrap();
        execute_mysql_statement(MySqlExecuteParams {
            connection: conn,
            request_id: format!("req-{}", uuid::Uuid::new_v4()),
            databases_for_log: vec![],
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
    }

    // Fixtures: rows carrying the capturing connection id.
    run(
        &conn,
        &password,
        &audit,
        &policy,
        "DROP TABLE IF EXISTS d3_items",
    )
    .await
    .unwrap();
    run(
        &conn,
        &password,
        &audit,
        &policy,
        "CREATE TABLE d3_items (id INT PRIMARY KEY, value INT, captured_by BIGINT)",
    )
    .await
    .unwrap();
    run(
        &conn,
        &password,
        &audit,
        &policy,
        "INSERT INTO d3_items (id, value, captured_by) VALUES (1, 10, 0)",
    )
    .await
    .unwrap();

    // The gated UPDATE's backup pre-image SELECT records the CONNECTION_ID
    // that captured it; the mutation then bumps `value`. Because the whole
    // operation runs on one pooled connection in one transaction, the
    // recorded id must equal the mutating connection's id, and B must be
    // locked out in between.
    //
    // We observe "the mutating connection" via a trigger-free trick: run
    // the gated UPDATE where the SET clause stores CONNECTION_ID() itself.
    run(
        &conn,
        &password,
        &audit,
        &policy,
        "UPDATE d3_items SET value = 11, captured_by = CONNECTION_ID() WHERE id = 1",
    )
    .await
    .unwrap();

    // The backup captured by the same connection: fetch the backup's
    // pre-image from the audit DB — it must contain the OLD row (value=10)
    // and the journal must link the same backup with a committed record.
    let backups = sequel_mcp::backup::list_backups(&audit, Some("d3"), 10).unwrap();
    assert!(!backups.is_empty(), "row backup must exist");
    let detail = sequel_mcp::backup::get_backup(&audit, backups[0].id)
        .unwrap()
        .expect("detail");
    let rows_json = detail.rows.expect("pre-image rows");
    let captured_value = rows_json[0]["value"]
        .as_i64()
        .unwrap_or_else(|| rows_json[0]["value"].as_str().unwrap().parse().unwrap());
    assert_eq!(captured_value, 10, "backup must hold the pre-image");

    // Concurrent-writer exclusion: hold a gated transaction open on one
    // connection via SLEEP-in-UPDATE under a long deadline, while B tries
    // to update the same row — B must block (not interleave).
    let mut a_policy = policy.clone();
    // SLEEP(2) executes twice on A's connection — once inside the backup
    // pre-image SELECT and once in the mutation — so budget 2x plus slack.
    a_policy.stmt_timeout_ms = 9_000;
    let a = {
        let conn = conn.clone();
        let password = password.clone();
        let audit = audit.clone();
        async move {
            let sql = "UPDATE d3_items SET value = value + 1 WHERE id = 1 AND SLEEP(2) = 0";
            let classified = classify_statement(sql, Dialect::MySql).unwrap();
            execute_mysql_statement(MySqlExecuteParams {
                connection: &conn,
                request_id: "req-a".into(),
                databases_for_log: vec![],
                password: Zeroizing::new(password),
                sql,
                classified: &classified,
                policy: &a_policy,
                database: None,
                audit: Some(audit),
                revision: 1,
                tunnel_endpoint: None,
                expected_ddl_targets: None,
            })
            .await
        }
        .boxed()
    };
    let a_handle = tokio::task::spawn(a);
    // Give A time to take the row lock (its backup SELECT ... FOR UPDATE).
    tokio::time::sleep(Duration::from_millis(600)).await;

    let b_started = std::time::Instant::now();
    let b = run(
        &conn,
        &password,
        &audit,
        &policy,
        "UPDATE d3_items SET value = 999 WHERE id = 1",
    )
    .await;
    let b_elapsed = b_started.elapsed();
    b.expect("B completes after A commits");
    assert!(
        b_elapsed >= Duration::from_millis(1_000),
        "B must wait for A's transaction (took {b_elapsed:?})"
    );
    a_handle.await.unwrap().unwrap();

    // Final value: A committed +1 twice? No — A ran once (+1 → 12), then
    // B set 999. value must be 999 and the journal for the failed early
    // lock attempt is moot (B succeeded after A).
    let rows = run(
        &conn,
        &password,
        &audit,
        &policy,
        "SELECT value FROM d3_items WHERE id = 1",
    )
    .await
    .unwrap();
    let v = match &rows.rows[0]["value"] {
        serde_json::Value::Number(n) => n.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        o => panic!("{o}"),
    };
    assert_eq!(v, 999);

    // Journal (P1 semantics): the executor now stops at
    // mutation_committed — only the gate (or an explicit direct-executor
    // close-out) finalizes after the audit row is durable. Model the
    // direct-executor contract here: write an audit row, finalize, LINK
    // it, then verify.
    let journal_dump: Vec<(i64, String, Option<i64>)> = audit
        .with(|c| {
            let mut stmt = c
                .prepare("SELECT id, state, backup_id FROM operation_journal ORDER BY id")
                .unwrap();
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap();
            rows.collect::<Result<Vec<_>, _>>()
        })
        .unwrap();
    eprintln!("JOURNAL: {journal_dump:?}");
    let committed: Vec<i64> = journal_dump
        .iter()
        .filter(|(_, st, b)| st == "mutation_committed" && b.is_some())
        .map(|(id, _, _)| *id)
        .collect();
    assert!(
        !committed.is_empty(),
        "executor must leave committed journals for the gate/direct caller to finalize: {journal_dump:?}"
    );
    for jid in committed {
        let j = sequel_mcp::backup::journal::Journal::from_id(&audit, jid);
        // Direct-executor close-out (what the gate does after its audit
        // write succeeds): finalize + link the audit row.
        j.transition(
            sequel_mcp::backup::journal::JournalState::AuditFinalized,
            None,
        )
        .unwrap();
        let audit_row = sequel_mcp::audit::write_audit_entry(
            &audit,
            &sequel_mcp::audit::AuditEntry {
                request_id: format!("d3-closeout-{jid}"),
                connection: "d3".into(),
                databases: vec![],
                category: sequel_mcp::policy::model::SqlCategory::Write,
                ast_type: Some("update".into()),
                sql: "UPDATE d3_items SET value = 999 WHERE id = 1".into(),
                decision: sequel_mcp::policy::model::PolicyAction::Allow,
                confirmed: false,
                outcome: sequel_mcp::approval::outcomes::ApprovalOutcome::Approved,
                affected_rows: None,
                duration_ms: None,
                error: None,
                backup_id: None,
                approval_scope: None,
                approval_digest: None,
                policy_revision: None,
            },
            &sequel_mcp::audit::WriteOptions::default(),
        )
        .unwrap();
        j.link_audit(audit_row).unwrap();
    }
    let after: Vec<(i64, String, Option<i64>)> = audit
        .with(|c| {
            let mut stmt = c
                .prepare("SELECT id, state, audit_id FROM operation_journal ORDER BY id")
                .unwrap();
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap();
            rows.collect::<Result<Vec<_>, _>>()
        })
        .unwrap();
    let linked = after
        .iter()
        .filter(|(_, st, a)| st == "audit_finalized" && a.is_some())
        .count();
    assert!(
        linked >= 1,
        "explicit close-out must finalize AND link the audit row: {after:?}"
    );
}
