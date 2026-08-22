//! D8 live-server benchmarks: first (cold-pool) and warm queries against
//! whichever server `SEQUEL_MCP_TEST_MYSQL` names, plus timeout-cancellation
//! latency. Reports median/p95/max to stderr in KEY=VALUE form.

use sequel_mcp::config::MySqlConnection;
use sequel_mcp::policy::classifier::{Dialect, classify_statement};
use sequel_mcp::policy::model::{PolicyPresetName, policy_from_preset};
use sequel_mcp::sql::mysql::pool_manager;
use sequel_mcp::sql::mysql::{MySqlExecuteParams, execute_mysql_statement};
use std::sync::Arc;
use std::time::Instant;
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

fn stats(name: &str, samples: &[f64]) {
    let mut a = samples.to_vec();
    a.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let med = a[a.len() / 2];
    let p95 = a[(a.len() as f64 * 0.95).ceil() as usize - 1];
    eprintln!(
        "{name} median={med:.2}ms p95={p95:.2}ms max={:.2}ms n={}",
        a[a.len() - 1],
        a.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d8_live_benchmarks() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();

    let conn = MySqlConnection {
        name: "d8".into(),
        host: host.to_string(),
        port,
        user: user.to_string(),
        database: Some("app".into()),
        ..MySqlConnection::default()
    };
    let dir = tempfile::TempDir::new().unwrap();
    let audit =
        Arc::new(sequel_mcp::audit::AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
    let policy = policy_from_preset(PolicyPresetName::Administration);
    let pw = Zeroizing::new(password.clone());

    async fn exec(
        conn: &MySqlConnection,
        pw: &Zeroizing<String>,
        audit: &Arc<sequel_mcp::audit::AuditDb>,
        policy: &sequel_mcp::policy::model::Policy,
        sql: &str,
    ) -> Result<sequel_mcp::sql::mysql::ExecuteResult, sequel_mcp::sql::mysql::MySqlError> {
        let classified = classify_statement(sql, Dialect::MySql).unwrap();
        execute_mysql_statement(MySqlExecuteParams {
            connection: conn,
            request_id: format!("req-{}", uuid::Uuid::new_v4()),
            databases_for_log: vec![],
            password: Zeroizing::new(pw.to_string()),
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
    macro_rules! exec {
        ($sql:expr) => {
            exec(&conn, &pw, &audit, &policy, $sql).await
        };
    }

    // --- Cold first query (pool init + handshake + health + query).
    let t = Instant::now();
    exec!("SELECT 1 AS ok").unwrap();
    eprintln!("FIRST_QUERY={:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    // --- Warm SELECT x N (physical reuse via the pool).
    let mut warm = Vec::new();
    for _ in 0..30 {
        let t = Instant::now();
        exec!("SELECT 1 AS ok").unwrap();
        warm.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    stats("WARM_SELECT", &warm);
    eprintln!("POOL_COUNT={}", pool_manager().pool_count());

    // --- Timeout-cancellation latency: 400 ms deadline, interruptible
    // read under the server-side kill; measures deadline-to-return.
    let mut tight = policy.clone();
    tight.stmt_timeout_ms = 400;
    let mut cancel = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let sql = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT COUNT(*) AS z FROM c";
        let classified = classify_statement(sql, Dialect::MySql).unwrap();
        let _ = execute_mysql_statement(MySqlExecuteParams {
            connection: &conn,
            request_id: format!("req-cancel-{}", uuid::Uuid::new_v4()),
            databases_for_log: vec![],
            password: Zeroizing::new(password.clone()),
            sql,
            classified: &classified,
            policy: &tight,
            database: None,
            audit: Some(audit.clone()),
            revision: 1,
            tunnel_endpoint: None,
            expected_ddl_targets: None,
        })
        .await;
        cancel.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    stats("CANCEL_LATENCY", &cancel);

    // --- Audit-only cost: write_audit_entry latency (temp audit db).
    let mut audit_samples = Vec::new();
    for i in 0..50 {
        let t = Instant::now();
        let _ = sequel_mcp::audit::write_audit_entry(
            &audit,
            &sequel_mcp::audit::AuditEntry {
                request_id: format!("bench-{i}"),
                connection: "d8".into(),
                databases: vec!["app".into()],
                category: sequel_mcp::policy::model::SqlCategory::Read,
                ast_type: Some("select".into()),
                sql: "SELECT 1".into(),
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
        );
        audit_samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    stats("AUDIT_WRITE", &audit_samples);
}
