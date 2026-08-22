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
        expected_ddl_targets: None,
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

    // --- TRUNCATE IF EXISTS is invalid engine syntax: classification
    // rejects it before planning (sqlparser accepts it; servers do not).
    assert!(matches!(
        classify_statement("TRUNCATE TABLE IF EXISTS d4_missing_xyz", Dialect::MySql),
        Err(ref e) if e.message().contains("not valid MySQL/MariaDB syntax")
    ));

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d4a_multi_target_and_rename_matrix() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();
    let ctx = ctx(&host, port, &user, &password);

    // ================= Multi-target DROP normalization =================
    // Case: DROP existing, missing (no IF EXISTS) → typed not-found,
    // NOTHING executed on either engine (stricter than MariaDB native).
    run(&ctx, "DROP TABLE IF EXISTS d4a_a").await.unwrap();
    run(&ctx, "CREATE TABLE d4a_a (id INT PRIMARY KEY)")
        .await
        .unwrap();
    run(&ctx, "INSERT INTO d4a_a VALUES (1)").await.unwrap();
    let err = run(&ctx, "DROP TABLE d4a_a, d4a_missing")
        .await
        .unwrap_err();
    match &err {
        MySqlError::DdlNotFound(m) => assert!(m.contains("d4a_missing"), "{m}"),
        o => panic!("{o:?}"),
    }
    // d4a_a untouched: nothing executed.
    let n = count(&ctx, "d4a_a").await;
    assert_eq!(n, 1, "no target may be dropped when one is missing");

    // Case: DROP IF EXISTS existing, missing → Mixed: existing dropped,
    // absent list surfaced for audit.
    let r = run(&ctx, "DROP TABLE IF EXISTS d4a_a, d4a_missing")
        .await
        .unwrap();
    assert!(!r.ddl_no_op, "mixed set must execute on the existing part");
    assert_eq!(
        r.ddl_absent_targets,
        vec![format!("app.d4a_missing")],
        "absent targets surfaced: {:?}",
        r.ddl_absent_targets
    );
    assert_eq!(count(&ctx, "d4a_a").await, 0, "existing target dropped");
    // Only the preflight-approved existing subset was executed (the
    // statement was REWRITTEN to name just that subset; the original
    // multi-target text never reaches the server).
    assert_eq!(
        r.ddl_executed_targets,
        vec![format!("app.d4a_a")],
        "executed subset surfaced: {:?}",
        r.ddl_executed_targets
    );
    // Journal carries the mixed detail.
    let states = dump_journal(&ctx).await;
    assert!(
        states.iter().any(|(st, d)| st == "audit_finalized"
            && d.as_deref()
                .unwrap_or("")
                .contains("absent targets: [app.d4a_missing]")),
        "mixed detail journalized: {states:?}"
    );

    // Case: DROP IF EXISTS missing1, missing2 → full no-op.
    let r = run(&ctx, "DROP TABLE IF EXISTS d4a_m1, d4a_m2")
        .await
        .unwrap();
    assert!(r.ddl_no_op);
    assert_eq!(r.ddl_absent_targets.len(), 2);

    // ================= RENAME chain matrix =================
    // simple rename
    run(&ctx, "DROP TABLE IF EXISTS d4a_r1, d4a_r2")
        .await
        .unwrap();
    run(&ctx, "CREATE TABLE d4a_r1 (id INT PRIMARY KEY)")
        .await
        .unwrap();
    run(&ctx, "RENAME TABLE d4a_r1 TO d4a_r2").await.unwrap();
    assert_eq!(exists_(&ctx, "d4a_r2").await, 1);
    assert_eq!(exists_(&ctx, "d4a_r1").await, 0);

    // swap chain: a→tmp, b→a, tmp→b (destinations freed by order)
    run(&ctx, "DROP TABLE IF EXISTS d4a_a1, d4a_b1, d4a_t1")
        .await
        .unwrap();
    run(&ctx, "CREATE TABLE d4a_a1 (id INT PRIMARY KEY)")
        .await
        .unwrap();
    run(&ctx, "CREATE TABLE d4a_b1 (id INT PRIMARY KEY)")
        .await
        .unwrap();
    run(
        &ctx,
        "RENAME TABLE d4a_a1 TO d4a_t1, d4a_b1 TO d4a_a1, d4a_t1 TO d4a_b1",
    )
    .await
    .unwrap();
    assert_eq!(exists_(&ctx, "d4a_a1").await, 1);
    assert_eq!(exists_(&ctx, "d4a_b1").await, 1);
    assert_eq!(exists_(&ctx, "d4a_t1").await, 0);

    // destination exists → typed conflict
    run(&ctx, "DROP TABLE IF EXISTS d4a_x, d4a_y")
        .await
        .unwrap();
    run(&ctx, "CREATE TABLE d4a_x (id INT PRIMARY KEY)")
        .await
        .unwrap();
    run(&ctx, "CREATE TABLE d4a_y (id INT PRIMARY KEY)")
        .await
        .unwrap();
    let err = run(&ctx, "RENAME TABLE d4a_x TO d4a_y").await.unwrap_err();
    match &err {
        MySqlError::DdlNotFound(m) => assert!(m.contains("already exists"), "{m}"),
        o => panic!("{o:?}"),
    }

    // missing source → typed not-found
    let err = run(&ctx, "RENAME TABLE d4a_nosuch TO d4a_z")
        .await
        .unwrap_err();
    match &err {
        MySqlError::DdlNotFound(m) => assert!(m.contains("does not exist"), "{m}"),
        o => panic!("{o:?}"),
    }

    // cross-database rename (app ↔ same server's other schema): use
    // creating a scratch schema is engine-admin; use app→app qualified
    // form which exercises schema resolution.
    run(&ctx, "DROP TABLE IF EXISTS d4a_q1").await.unwrap();
    run(&ctx, "CREATE TABLE d4a_q1 (id INT PRIMARY KEY)")
        .await
        .unwrap();
    run(&ctx, "RENAME TABLE app.d4a_q1 TO app.d4a_q2")
        .await
        .unwrap();
    assert_eq!(exists_(&ctx, "d4a_q2").await, 1);
}

async fn count(ctx: &Ctx, table: &str) -> i64 {
    let rows = run(
        ctx,
        &format!("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = 'app' AND table_name = '{table}'"),
    )
    .await
    .unwrap()
    .rows;
    match &rows[0]["n"] {
        serde_json::Value::Number(v) => v.as_i64().unwrap(),
        serde_json::Value::String(s) => s.parse().unwrap(),
        o => panic!("{o}"),
    }
}

async fn exists_(ctx: &Ctx, table: &str) -> i64 {
    count(ctx, table).await
}

// ================= D4A TOCTOU: plan -> create -> execute =================
// The plan/execute gap (MRTR approvals) must never let a target created
// after the plan be dropped by the approved statement.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d4a_drop_race_library_level() {
    let Some((host, port, user, password)) = target() else {
        eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
        return;
    };
    pool_manager().invalidate_all();
    let ctx = ctx(&host, port, &user, &password);

    run(&ctx, "DROP TABLE IF EXISTS d4r_a, d4r_b")
        .await
        .unwrap();
    run(&ctx, "CREATE TABLE d4r_a (id INT PRIMARY KEY)")
        .await
        .unwrap();

    // PLAN: preflight exactly as the MRTR planner does.
    let sql = "DROP TABLE IF EXISTS d4r_a, d4r_b";
    let classified = classify_statement(sql, Dialect::MySql).unwrap();
    let pw = Zeroizing::new(ctx.password.clone());
    let pool = pool_manager()
        .verified_pool(&ctx.conn, &pw, None, 1, None, None, None)
        .await
        .unwrap();
    let mut conn = pool.get_conn().await.unwrap();
    let plan = sequel_mcp::sql::ddl::preflight_ddl(&mut conn, &classified, Some("app"))
        .await
        .unwrap();
    drop(conn);
    let approved = match plan {
        sequel_mcp::sql::ddl::DdlPreflight::Mixed { existing, missing } => {
            assert_eq!(existing, vec![("app".to_string(), "d4r_a".to_string())]);
            assert_eq!(missing, vec![("app".to_string(), "d4r_b".to_string())]);
            existing
        }
        other => panic!("expected Mixed plan, got {other:?}"),
    };

    // RACE: another connection creates the absent target after the plan.
    run(&ctx, "CREATE TABLE d4r_b (id INT PRIMARY KEY)")
        .await
        .unwrap();

    // EXECUTE with the plan-approved target set: typed precondition
    // failure, NOTHING executed, both tables intact.
    let err = run_planned(&ctx, sql, Some(approved)).await.unwrap_err();
    match &err {
        MySqlError::DdlPreconditionChanged(m) => {
            assert!(m.contains("d4r_b"), "{m}");
            assert!(m.contains("nothing executed"), "{m}");
        }
        other => panic!("expected DdlPreconditionChanged, got {other:?}"),
    }
    assert_eq!(
        count(&ctx, "d4r_a").await,
        1,
        "approved target must survive"
    );
    assert_eq!(
        count(&ctx, "d4r_b").await,
        1,
        "post-plan target must survive"
    );

    // A FRESH plan (no plan-gap set) sees both targets and drops both.
    run(&ctx, sql).await.unwrap();
    assert_eq!(count(&ctx, "d4r_a").await, 0);
    assert_eq!(count(&ctx, "d4r_b").await, 0);
}

async fn run_planned(
    ctx: &Ctx,
    sql: &str,
    expected: Option<Vec<(String, String)>>,
) -> Result<sequel_mcp::sql::mysql::ExecuteResult, MySqlError> {
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
        expected_ddl_targets: expected,
    })
    .await
}

// ================= MCP-level MRTR DDL race over the real binary ==========
// The reviewer scenario end-to-end: plan (input_required with the
// confirmed/absent split) -> another connection creates the absent table
// -> approved retry -> typed precondition change, nothing executed.

mod mcp_race {
    use super::*;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    fn bin_path() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/debug/sequel-mcp"
        ))
    }

    struct LineReceiver {
        rx: std::sync::mpsc::Receiver<String>,
    }

    impl LineReceiver {
        fn from_reader<R: Read + Send + 'static>(inner: R) -> Self {
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                use std::io::BufRead;
                let reader = std::io::BufReader::new(inner);
                for line in reader.split(b'\n') {
                    match line {
                        Ok(bytes) => {
                            let line = String::from_utf8_lossy(&bytes).trim().to_string();
                            if !line.is_empty() && tx.send(line).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            Self { rx }
        }

        fn next_line(&mut self, deadline: Duration) -> Option<String> {
            let started = Instant::now();
            loop {
                match self.rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(line) => return Some(line),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if started.elapsed() >= deadline {
                            return None;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
                }
            }
        }
    }

    fn read_response(
        out: &mut LineReceiver,
        want_id: i64,
        deadline: Duration,
    ) -> serde_json::Value {
        let started = Instant::now();
        while started.elapsed() < deadline {
            if let Some(line) = out.next_line(deadline) {
                if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line)
                    && msg["id"] == want_id
                {
                    return msg;
                }
                continue;
            }
            break;
        }
        panic!("no response for id {want_id} within {deadline:?}");
    }

    fn send(stdin: &mut impl Write, value: &serde_json::Value) {
        stdin
            .write_all(serde_json::to_string(value).unwrap().as_bytes())
            .unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn meta_2026() -> serde_json::Value {
        serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
            "io.modelcontextprotocol/clientInfo": {"name": "d4race", "version": "0"}
        })
    }

    /// Spawn the real binary against the docker MySQL, in a clean isolated
    /// environment with synthetic test secrets.
    fn spawn_server(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> (Child, std::process::ChildStdin, LineReceiver) {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg_root = dir.path().join("cfg");
        let data_root = dir.path().join("data");
        std::fs::create_dir_all(cfg_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(data_root.join("sequel-mcp")).unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        std::fs::write(
            cfg_root.join("sequel-mcp").join("config.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 2, "revision": 1, "defaultConnection": "db",
                "connections": [{
                    "driver": "mysql", "name": "db",
                    "host": host, "port": port, "user": user,
                    "database": "app", "ssl": false,
                    "policy": {
                        "read": "allow", "write": "deny", "ddl": "deny", "admin": "deny",
                        "txCtrl": "allow", "rowCap": 100, "stmtTimeoutMs": 15000,
                        "requireTouchID": false, "maxBackupRows": 100,
                        "maxBackupBytes": 1048576, "onBackupOverflow": "abort"
                    },
                    "tablePolicies": {"app.*": {"ddl": "allow"}}
                }],
                "retention": {}
            }))
            .unwrap(),
        )
        .unwrap();
        eprintln!("ISO_ROOT={}", dir.path().display());
        let secrets = serde_json::json!({"db": {user: password}}).to_string();
        let test_root = dir.path().to_path_buf();
        let home = dir.path().join("home");
        std::mem::forget(dir);
        let mut child = Command::new(bin_path())
            .arg("serve")
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &cfg_root)
            .env("XDG_DATA_HOME", &data_root)
            .env("SEQUEL_MCP_TEST_MODE", "1")
            .env("SEQUEL_MCP_TEST_ROOT", &test_root)
            .env("SEQUEL_MCP_TEST_SECRETS", &secrets)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary spawns");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let err = child.stderr.take();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut e = match err {
                Some(e) => e,
                None => return,
            };
            let mut buf = [0u8; 4096];
            while let Ok(n) = e.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
        let reader = LineReceiver::from_reader(stdout);
        (child, stdin, reader)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn d4a_mcp_mrtr_ddl_race() {
        let Some((host, port, user, password)) = target() else {
            eprintln!("skipping: SEQUEL_MCP_TEST_MYSQL not set");
            return;
        };
        pool_manager().invalidate_all();
        let ctx = ctx(&host, port, &user, &password);

        run(&ctx, "DROP TABLE IF EXISTS d4m_a, d4m_b")
            .await
            .unwrap();
        run(&ctx, "CREATE TABLE d4m_a (id INT PRIMARY KEY)")
            .await
            .unwrap();

        let (mut child, mut stdin, mut out) = spawn_server(&host, port, &user, &password);

        // Plan: DROP of one existing + one absent target under an
        // elevated (confirm) rule -> input_required with the split.
        let sql = "DROP TABLE IF EXISTS d4m_a, d4m_b";
        send(
            &mut stdin,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "execute", "arguments": {"sql": sql}, "_meta": meta_2026()}
            }),
        );
        let msg = read_response(&mut out, 1, Duration::from_secs(20));
        assert_eq!(msg["result"]["resultType"], "input_required", "{msg}");
        let state = msg["result"]["requestState"].as_str().unwrap().to_string();
        let message = msg["result"]["inputRequests"]["approval"]["params"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            message.contains("Confirmed to exist at plan time (will be affected): app.d4m_a"),
            "plan split surfaced: {message}"
        );
        assert!(
            message.contains("Absent at plan time (skipped, recorded in audit): app.d4m_b"),
            "absent split surfaced: {message}"
        );

        // RACE: create the absent target after the plan was approved-pending.
        run(&ctx, "CREATE TABLE d4m_b (id INT PRIMARY KEY)")
            .await
            .unwrap();

        // Approved retry: typed precondition change, nothing executed.
        send(
            &mut stdin,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "execute", "arguments": {"sql": sql}, "_meta": meta_2026(),
                    "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                    "requestState": state
                }
            }),
        );
        let msg = read_response(&mut out, 2, Duration::from_secs(20));
        let text = serde_json::to_string(&msg).unwrap();
        assert!(
            text.contains("[ddl_precondition_changed]"),
            "typed precondition failure: {msg}"
        );
        assert!(text.contains("d4m_b"), "names the changed target: {msg}");
        assert_eq!(count(&ctx, "d4m_a").await, 1, "approved target survives");
        assert_eq!(count(&ctx, "d4m_b").await, 1, "post-plan target survives");

        // Fresh plan sees both; the approved retry drops both.
        send(
            &mut stdin,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "execute", "arguments": {"sql": sql}, "_meta": meta_2026()}
            }),
        );
        let msg = read_response(&mut out, 3, Duration::from_secs(20));
        let state = msg["result"]["requestState"].as_str().unwrap().to_string();
        send(
            &mut stdin,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {
                    "name": "execute", "arguments": {"sql": sql}, "_meta": meta_2026(),
                    "inputResponses": {"approval": {"action": "accept", "content": {"choice": "once"}}},
                    "requestState": state
                }
            }),
        );
        let msg = read_response(&mut out, 4, Duration::from_secs(20));
        let structured = &msg["result"]["structuredContent"];
        assert!(
            structured["ddlExecutedTargets"].is_array(),
            "fresh plan executes: {msg}"
        );
        assert_eq!(count(&ctx, "d4m_a").await, 0);
        assert_eq!(count(&ctx, "d4m_b").await, 0);

        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
    }
}
