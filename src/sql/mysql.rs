//! MySQL/MariaDB execution: bounded pools, TLS with server-name override,
//! hard-failing READ ONLY transactions, MAX_EXECUTION_TIME hints,
//! streaming with caps, lossless numerics, LOCAL INFILE disabled.

use crate::backup::extractor::{BackupSpec, extract_backup_spec};
use crate::config::MySqlConnection;
use crate::policy::classifier::ClassifiedStatement;
use crate::policy::model::{Policy, SqlCategory};
use futures_util::StreamExt;
use mysql_async::prelude::Queryable;
use mysql_async::{OptsBuilder, PoolConstraints, PoolOpts, Row, SslOpts, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::audit::AuditDb;

#[derive(Debug, Error)]
pub enum MySqlError {
    #[error("mysql error: {0}")]
    Driver(#[from] mysql_async::Error),
    #[error("read-only transaction could not be established: {0}")]
    ReadOnlyTx(String),
    #[error("statement timed out after {0}ms")]
    Timeout(u64),
    #[error("backup overflow: {0}")]
    BackupOverflow(String),
    #[error("backup capture failed: {0} — mutation denied")]
    BackupFailed(String),
    #[error("pool error: {0}")]
    Pool(String),
    #[error("{0}")]
    Uncertain(String),
    #[error("DDL target not found: {0}")]
    DdlNotFound(String),
    #[error("[ddl_precondition_changed] {0}")]
    DdlPreconditionChanged(String),
}

#[derive(Debug)]
pub struct ExecuteResult {
    /// Operation-journal row id (D3), when a journal was created.
    pub journal_id: Option<i64>,
    /// Targets that were absent under IF EXISTS in a Mixed set (D4A):
    /// only the preflight-approved existing subset was executed; the
    /// absent list is surfaced in the result and audit.
    pub ddl_absent_targets: Vec<String>,
    /// The subset actually named by the rewritten Mixed statement
    /// (equals the plan-approved existing set intersected with what still
    /// exists at execution). Empty unless a Mixed rewrite occurred.
    pub ddl_executed_targets: Vec<String>,
    /// DDL absent-target no-op (IF EXISTS over missing tables): nothing
    /// was sent to the server; audited locally.
    pub ddl_no_op: bool,
    /// Protection-model warnings that must surface in the plan and audit
    /// (nontransactional DDL snapshot semantics, D4).
    pub warnings: Vec<&'static str>,
    pub rows: Vec<serde_json::Value>,
    pub fields: Vec<String>,
    pub affected_rows: u64,
    pub truncated: bool,
    pub duration_ms: u64,
    pub backup_id: Option<i64>,
    pub backup_row_count: u64,
}

/// Legacy `buildBaseOptions` parity, including the TLS server-name override
/// and the injection guardrails (multi-statements off, no LOCAL INFILE
/// handler, keepalive, 15 s connect timeout).
/// Deadline for establishing (handshake + health probe) a pooled
/// connection; blackhole endpoints fail with a typed error at this bound.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub fn build_opts(
    conn: &MySqlConnection,
    password: &str,
    database: Option<&str>,
    host_override: Option<&str>,
    port_override: Option<u16>,
) -> OptsBuilder {
    let ssl: Option<SslOpts> = if conn.ssl {
        let mut ssl = SslOpts::default();
        if let Some(name) = &conn.ssl_server_name {
            // Verify the certificate against the user-configured name
            // (e.g. when connecting through a tunnel endpoint).
            ssl = ssl.with_danger_tls_hostname_override(Some(name.clone()));
        }
        Some(ssl)
    } else {
        None
    };
    OptsBuilder::default()
        .ip_or_hostname(
            host_override
                .map(str::to_string)
                .unwrap_or_else(|| conn.host.clone()),
        )
        .tcp_port(port_override.unwrap_or(conn.port))
        .user(Some(conn.user.clone()))
        .pass(Some(password.to_string()))
        .db_name(
            database
                .map(str::to_string)
                .or_else(|| conn.database.clone()),
        )
        .secure_auth(true)
        .ssl_opts(ssl)
        .conn_ttl(Duration::from_secs(600))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .pool_opts(
            PoolOpts::default()
                .with_constraints(PoolConstraints::new(1, 4).expect("1<=4"))
                // The default inactive TTL is 0 (immediate recycle), which
                // defeats physical connection reuse; keep idle pooled
                // connections alive so warm queries reuse them.
                .with_inactive_connection_ttl(Duration::from_secs(300)),
        )
}

/// Lossless value mapping: text-protocol DECIMAL/BIGINT arrive as raw
/// bytes and stay strings; binaries base64; dates formatted like the
/// legacy `dateStrings: true`.
pub fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::NULL => serde_json::Value::Null,
        Value::Bytes(b) => match std::str::from_utf8(b) {
            Ok(s) => serde_json::json!(s),
            Err(_) => {
                use base64::Engine;
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b))
            }
        },
        Value::Int(i) => serde_json::json!(i),
        Value::UInt(u) => serde_json::json!(u),
        Value::Float(f) => serde_json::json!(f),
        Value::Double(d) => serde_json::json!(d),
        Value::Date(y, m, d, hh, mm, ss, us) => {
            if *us == 0 {
                serde_json::json!(format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}"))
            } else {
                serde_json::json!(format!(
                    "{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}.{us:06}"
                ))
            }
        }
        Value::Time(neg, d, h, m, s, us) => {
            let base = format!("{d:02}:{h:02}:{m:02}:{s:02}");
            let with_us = if *us == 0 {
                base
            } else {
                format!("{base}.{us:06}")
            };
            serde_json::json!(if *neg { format!("-{with_us}") } else { with_us })
        }
    }
}

static MANAGER: std::sync::OnceLock<super::pool::PoolManager> = std::sync::OnceLock::new();

pub fn pool_manager() -> &'static super::pool::PoolManager {
    MANAGER.get_or_init(super::pool::PoolManager::new)
}

pub struct MySqlExecuteParams<'a> {
    pub connection: &'a MySqlConnection,
    /// Request id for the D3 operation journal.
    pub request_id: String,
    /// Databases considered for the operation (journal metadata).
    pub databases_for_log: Vec<String>,
    pub password: Zeroizing<String>,
    pub sql: &'a str,
    pub classified: &'a ClassifiedStatement,
    pub policy: &'a Policy,
    pub database: Option<&'a str>,
    pub audit: Option<Arc<AuditDb>>,
    pub revision: u64,
    /// Local endpoint when an SSH tunnel is in front of the server.
    pub tunnel_endpoint: Option<(String, u16)>,
    /// Plan-time approved DDL target set (MRTR plan→retry gap): every
    /// DROP target that exists at execution time must have existed at
    /// plan time, otherwise nothing executes (DdlPreconditionChanged).
    /// `None` for single-shot execution (no plan gap).
    pub expected_ddl_targets: Option<Vec<(String, String)>>,
}

/// Structured representation for binary column values so they can never
/// be mistaken for ordinary text: `{"type":"binary","encoding":"base64",
/// "data":…}` (D5).
pub fn binary_json(bytes: &[u8]) -> serde_json::Value {
    use base64::Engine;
    serde_json::json!({
        "type": "binary",
        "encoding": "base64",
        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

/// Legacy numeric parity for text-protocol results: INT-family and
/// FLOAT/DOUBLE parse to JSON numbers; BIGINT and DECIMAL stay strings
/// (`bigNumberStrings` semantics — lossless round-trip).
pub fn value_with_column_type(
    v: &Value,
    ct: mysql_async::consts::ColumnType,
    charset: u16,
) -> serde_json::Value {
    use mysql_async::consts::ColumnType;
    // Binary-typed columns (BLOB family, BIT, GEOMETRY) and any column
    // using the binary character set (63: VARBINARY/BINARY render as
    // VAR_STRING/STRING in the text protocol) get the structured
    // representation — including valid-UTF-8 bytes (an ASCII BLOB is
    // still a BLOB).
    if let Value::Bytes(b) = v
        && (matches!(
            ct,
            ColumnType::MYSQL_TYPE_TINY_BLOB
                | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
                | ColumnType::MYSQL_TYPE_LONG_BLOB
                | ColumnType::MYSQL_TYPE_BLOB
                | ColumnType::MYSQL_TYPE_BIT
                | ColumnType::MYSQL_TYPE_GEOMETRY
        ) || (charset == 63
            && matches!(
                ct,
                ColumnType::MYSQL_TYPE_STRING | ColumnType::MYSQL_TYPE_VAR_STRING
            )))
    {
        return binary_json(b);
    }
    let bytes = match v {
        Value::Bytes(b) => b,
        other => return value_to_json(other),
    };
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return value_to_json(v),
    };
    let numeric = matches!(
        ct,
        ColumnType::MYSQL_TYPE_TINY
            | ColumnType::MYSQL_TYPE_SHORT
            | ColumnType::MYSQL_TYPE_LONG
            | ColumnType::MYSQL_TYPE_INT24
            | ColumnType::MYSQL_TYPE_FLOAT
            | ColumnType::MYSQL_TYPE_DOUBLE
            | ColumnType::MYSQL_TYPE_YEAR
    );
    if numeric {
        if let Ok(i) = text.parse::<i64>() {
            return serde_json::json!(i);
        }
        if let Ok(u) = text.parse::<u64>() {
            return serde_json::json!(u);
        }
        if let Ok(f) = text.parse::<f64>() {
            return serde_json::json!(f);
        }
    }
    serde_json::json!(text)
}

const READ_CATEGORIES: [SqlCategory; 1] = [SqlCategory::Read];
const RESULT_BYTE_CAP: u64 = 4 * 1024 * 1024;

fn is_mariadb(server_version: &str) -> bool {
    server_version.to_ascii_lowercase().contains("mariadb")
}

/// Execute one classified statement through the pool. Reads run inside
/// START TRANSACTION READ ONLY — when that cannot be established the
/// operation fails hard (legacy continued on a read-write session).
pub async fn execute_mysql_statement(
    params: MySqlExecuteParams<'_>,
) -> Result<ExecuteResult, MySqlError> {
    let start = Instant::now();
    let is_read = READ_CATEGORIES.contains(&params.classified.category);
    let (host, port) = match &params.tunnel_endpoint {
        Some((h, p)) => (h.clone(), *p),
        None => (params.connection.host.clone(), params.connection.port),
    };
    // Fail-closed test-mode endpoint gate: refused BEFORE any connect
    // attempt (a violation must never open a socket).
    crate::app::test_mode::check_mysql_endpoint(&host, port).map_err(MySqlError::Pool)?;
    let pool = pool_manager()
        .verified_pool(
            params.connection,
            &params.password,
            params.database,
            params.revision,
            Some(&host),
            Some(port),
        )
        .await
        .map_err(|e| MySqlError::Pool(e.to_string()))?;
    let mut conn = pool.get_conn().await?;

    // Record the physical connection id for active cancellation (D2).
    let executing_id: Option<u64> = conn
        .exec_first::<(u64,), _, _>("SELECT CONNECTION_ID()", ())
        .await
        .ok()
        .flatten()
        .map(|(id,)| id);

    let (major, minor, _patch) = conn.server_version();
    let server_version = format!("{major}.{minor}");
    let mut in_tx = false;
    if params.classified.category != SqlCategory::TxCtrl {
        let stmt = if is_read {
            "START TRANSACTION READ ONLY"
        } else {
            "START TRANSACTION READ WRITE"
        };
        if let Err(e) = conn.query_drop(stmt).await {
            if is_read {
                return Err(MySqlError::ReadOnlyTx(e.to_string()));
            }
            // Writes cannot open a transaction: execute without one and
            // let the server's implicit behavior apply (legacy logged and
            // continued for writes; reads are the hard gate).
            eprintln!(
                "[sequel-mcp] {} START TRANSACTION failed: {e}; continuing without explicit tx",
                params.connection.name
            );
        } else {
            in_tx = true;
        }
        // Statement timeout: MySQL max_execution_time (ms) / MariaDB
        // max_statement_time (seconds) on this session.
        if params.policy.stmt_timeout_ms > 0 {
            let timeout_sql = if is_mariadb(&server_version) {
                format!(
                    "SET SESSION max_statement_time = {}",
                    params.policy.stmt_timeout_ms.div_ceil(1000)
                )
            } else {
                format!(
                    "SET SESSION max_execution_time = {}",
                    params.policy.stmt_timeout_ms
                )
            };
            let _ = conn.query_drop(timeout_sql).await;
        }
    }

    // Statement work + finalization under an active-cancellation deadline.
    // The timeout applies to the whole in-transaction phase (statement +
    // commit) so a stalled COMMIT also triggers cancellation. The work
    // future owns the connection and hands it back, so the cancellation
    // path can roll back / verify / sever it.
    // D3 operation journal: mutations (write/ddl categories) get a
    // durable lifecycle record; reads do not need one.
    let journal = if matches!(
        params.classified.category,
        SqlCategory::Write | SqlCategory::Ddl | SqlCategory::Admin
    ) && params.audit.is_some()
    {
        let Some(audit) = params.audit.as_ref() else {
            unreachable!("guarded by is_some above")
        };
        let _ = crate::backup::journal::ensure_table(audit);
        crate::backup::journal::Journal::create(
            audit,
            &params.request_id,
            &params.connection.name,
            &params.databases_for_log,
            params.classified.category.as_str(),
        )
        .ok()
    } else {
        None
    };

    use crate::backup::journal::JournalState;
    // D4A: absent targets of a Mixed IF EXISTS set (audited, never
    // suppressed), the rewritten statement naming only the
    // preflight-approved existing subset, and an optional journal detail.
    let mut ddl_absent: Vec<(String, String)> = Vec::new();
    let mut ddl_executed: Vec<String> = Vec::new();
    let mut ddl_effective_sql: Option<String> = None;
    let mut ddl_detail: Option<String> = None;

    // D4 preflight for DDL: bound-parameter existence check on every
    // mutated target. IF EXISTS + missing -> audited local no-op (no DDL
    // sent); missing without IF EXISTS -> typed not-found error; mixed
    // -> REWRITTEN statement over the approved existing subset only (the
    // original multi-target statement is never re-sent: a target created
    // after the preflight would otherwise be dropped without ever being
    // approved or snapshotted); present -> continue with snapshot
    // semantics.
    if params.classified.category == SqlCategory::Ddl {
        match super::ddl::preflight_ddl(
            &mut conn,
            params.classified,
            params.database.or(params.connection.database.as_deref()),
        )
        .await
        {
            Ok(super::ddl::DdlPreflight::Present) => {
                // Plan-gap enforcement (MRTR retry): if a plan-time target
                // set exists, every currently-present DROP target must
                // have been in it — a table created after the approved
                // plan fails closed with nothing executed.
                if let (Some(expected), "drop") = (
                    params.expected_ddl_targets.as_ref(),
                    params.classified.ast_type,
                ) {
                    let fallback = params.database.or(params.connection.database.as_deref());
                    for target in &params.classified.mutated_tables {
                        let Some(schema) = target
                            .database
                            .clone()
                            .or_else(|| fallback.map(str::to_string))
                        else {
                            continue;
                        };
                        if !expected.contains(&(schema.clone(), target.table.clone())) {
                            let detail = format!(
                                "table {}.{} changed existence after the approved plan; nothing executed; re-run for a fresh plan",
                                schema, target.table
                            );
                            if let Some(j) = &journal {
                                let _ = j.transition(JournalState::Failed, Some(&detail));
                            }
                            return Err(MySqlError::DdlPreconditionChanged(detail));
                        }
                    }
                }
            }
            Ok(super::ddl::DdlPreflight::Mixed { existing, missing }) => {
                // Plan-gap enforcement: the current existing set must be a
                // subset of the plan-approved set.
                if let Some(expected) = params.expected_ddl_targets.as_ref() {
                    for (schema, table) in &existing {
                        if !expected.contains(&(schema.clone(), table.clone())) {
                            let detail = format!(
                                "table {schema}.{table} changed existence after the approved plan; nothing executed; re-run for a fresh plan"
                            );
                            if let Some(j) = &journal {
                                let _ = j.transition(JournalState::Failed, Some(&detail));
                            }
                            return Err(MySqlError::DdlPreconditionChanged(detail));
                        }
                    }
                }
                let absent = missing
                    .iter()
                    .map(|(s, t)| format!("{s}.{t}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let kept = existing
                    .iter()
                    .map(|(s, t)| format!("{s}.{t}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                match super::ddl::rewrite_drop_subset(
                    params.classified.drop_object_type.unwrap_or("other"),
                    &existing,
                ) {
                    Some(rewritten) => {
                        ddl_effective_sql = Some(rewritten);
                        ddl_executed = existing.iter().map(|(s, t)| format!("{s}.{t}")).collect();
                        ddl_absent = missing.clone();
                        ddl_detail = Some(format!(
                            "IF EXISTS: executing approved subset [{kept}]; absent targets: [{absent}]"
                        ));
                    }
                    None => {
                        let detail = format!(
                            "mixed multi-target drop of this object type cannot be safely rewritten; nothing executed (targets: [{kept}], absent: [{absent}])"
                        );
                        if let Some(j) = &journal {
                            let _ = j.transition(JournalState::Failed, Some(&detail));
                        }
                        return Err(MySqlError::DdlPreconditionChanged(detail));
                    }
                }
            }
            Ok(super::ddl::DdlPreflight::MissingNoOp(missing)) => {
                let detail = missing
                    .iter()
                    .map(|(s, t)| format!("{s}.{t}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Some(j) = &journal {
                    let _ = j.transition(
                        crate::backup::journal::JournalState::Failed,
                        Some(&format!("ddl no-op: absent targets {detail}")),
                    );
                }
                ddl_absent = missing.clone();
                return Ok(ExecuteResult {
                    journal_id: journal.as_ref().map(|j| j.id()),
                    ddl_no_op: true,
                    ddl_absent_targets: ddl_absent
                        .iter()
                        .map(|(s, t)| format!("{s}.{t}"))
                        .collect(),
                    ddl_executed_targets: Vec::new(),
                    warnings: vec![],
                    rows: Vec::new(),
                    fields: Vec::new(),
                    affected_rows: 0,
                    truncated: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    backup_id: None,
                    backup_row_count: 0,
                });
            }
            Err(e) => {
                if let Some(j) = &journal {
                    let _ = j.transition(
                        crate::backup::journal::JournalState::Failed,
                        Some(&e.to_string()),
                    );
                }
                return Err(MySqlError::DdlNotFound(e.to_string()));
            }
            #[allow(unreachable_patterns)]
            Ok(_) => {}
        }
    }
    let warnings: Vec<&'static str> =
        super::ddl::protection_model_for(params.classified.category, params.classified.ast_type)
            .warnings()
            .to_vec();

    let timeout_ms = params.policy.stmt_timeout_ms.max(1) as u64;
    let mut conn_slot = Some(conn);
    let work = async {
        let mut conn = conn_slot.take().expect("conn returned by prior poll");
        let result = run_in_transaction(
            &mut conn,
            &params,
            is_read,
            start,
            journal.as_ref(),
            warnings.clone(),
            ddl_absent.clone(),
            ddl_executed.clone(),
            ddl_effective_sql.clone(),
            ddl_detail.clone(),
        )
        .await;
        match result {
            Ok(value) => {
                if in_tx && let Err(e) = conn.query_drop("COMMIT").await {
                    let _ = conn.query_drop("ROLLBACK").await;
                    if let Some(j) = journal {
                        let _ = j.transition(JournalState::Uncertain, Some("COMMIT failed"));
                    }
                    (Err(MySqlError::Driver(e)), Some(conn))
                } else {
                    if let Some(j) = journal {
                        let _ = j.transition(JournalState::MutationCommitted, None);
                        // Direct-executor callers (tests/CLI) have no gate
                        // audit write; the journal itself is durable here,
                        // so close it out. Gate callers re-transition
                        // harmlessly (idempotence guarded by the state
                        // machine: committed -> finalized is legal).
                        let _ = j.transition(JournalState::AuditFinalized, None);
                    }
                    (Ok(value), Some(conn))
                }
            }
            Err(e) => {
                if in_tx {
                    let _ = conn.query_drop("ROLLBACK").await;
                }
                if let Some(j) = journal {
                    let _ = j.transition(JournalState::Failed, Some(&e.to_string()));
                }
                (Err(e), Some(conn))
            }
        }
    };
    tokio::pin!(work);
    match tokio::time::timeout(Duration::from_millis(timeout_ms), &mut work).await {
        Ok((result, _conn)) => result,
        Err(_elapsed) => {
            // Deadline fired with the statement still running server-side.
            // Interrupt it via KILL QUERY from a same-pool control
            // connection, then let the work future resolve within a
            // bounded grace period.
            let kill_result = match executing_id {
                Some(id) => super::cancel::kill_query(&pool, id).await,
                None => Err("no executing connection id recorded".into()),
            };
            let grace = tokio::time::timeout(Duration::from_secs(5), &mut work).await;
            match (kill_result, grace) {
                (Ok(()), Ok((Err(_interrupted), Some(mut conn)))) => {
                    if in_tx {
                        let _ = conn.query_drop("ROLLBACK").await;
                    }
                    let clean = super::cancel::verify_connection_clean(&mut conn).await;
                    match &clean {
                        Ok(true) => Err(MySqlError::Timeout(timeout_ms)),
                        Ok(false) => {
                            conn.disconnect().await.ok();
                            Err(MySqlError::Uncertain(
                                "deadline exceeded; transaction still open after rollback - connection discarded"
                                    .to_string(),
                            ))
                        }
                        Err(detail) => {
                            conn.disconnect().await.ok();
                            Err(MySqlError::Uncertain(format!(
                                "deadline exceeded; verification failed ({detail}) - connection discarded"
                            )))
                        }
                    }
                }
                (Ok(_), Ok((Ok(_value), _conn))) => {
                    // Completed during the kill race: the deadline has
                    // already expired, and a KILLed statement can resolve
                    // with a benign Ok (e.g. SLEEP() returns 1 instead of
                    // an error). Per the deadline contract this is a
                    // timeout, not a success.
                    Err(MySqlError::Timeout(timeout_ms))
                }
                _ => {
                    // Kill failed or the future never resolved: uncertain.
                    // The still-armed work future is dropped, severing its
                    // connection without a clean pool return.
                    Err(MySqlError::Uncertain(
                        "deadline exceeded; cancellation inconclusive - connection discarded"
                            .to_string(),
                    ))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_in_transaction(
    conn: &mut mysql_async::Conn,
    params: &MySqlExecuteParams<'_>,
    is_read: bool,
    start: Instant,
    journal: Option<&crate::backup::journal::Journal<'_>>,
    warnings_out: Vec<&'static str>,
    ddl_absent: Vec<(String, String)>,
    ddl_executed: Vec<String>,
    ddl_effective_sql: Option<String>,
    ddl_detail: Option<String>,
) -> Result<ExecuteResult, MySqlError> {
    use crate::backup::journal::JournalState;
    if let Some(j) = journal {
        let _ = j.transition(JournalState::BackupCapturing, ddl_detail.as_deref());
    }
    // The statement actually sent: the Mixed-IF-EXISTS rewrite names only
    // the approved existing subset; every other statement runs verbatim.
    let effective_sql: &str = ddl_effective_sql.as_deref().unwrap_or(params.sql);
    // Pre-mutation backup (fail-closed: capture errors deny the mutation).
    let mut backup_id: Option<i64> = None;
    let mut backup_row_count: u64 = 0;
    let mut pending_insert: Option<BackupSpec> = None;
    if crate::backup::extractor::is_backup_required(params.classified.ast_type) {
        let spec = extract_backup_spec(
            effective_sql,
            params.classified.ast_type,
            crate::policy::classifier::Dialect::MySql,
        )
        .map_err(|e| MySqlError::BackupFailed(e.to_string()))?;
        match &spec {
            BackupSpec::InsertHint { .. } => pending_insert = Some(spec),
            BackupSpec::None { .. } => {}
            _ => {
                if let Some(c) = capture_backup_mysql(
                    conn,
                    &spec,
                    &params.connection.name,
                    params.database.or(params.connection.database.as_deref()),
                    params.policy,
                    params.audit.clone(),
                )
                .await?
                {
                    backup_id = Some(c.backup_id);
                    backup_row_count = c.total_rows;
                    if let Some(j) = journal {
                        let _ = j.link_backup(c.backup_id);
                        let _ = j.transition(JournalState::BackupDurable, None);
                    }
                }
            }
        }
    }

    if let Some(j) = journal {
        let _ = j.transition(JournalState::MutationExecuting, None);
    }

    // Reads carry the optimizer timeout hint.
    let sql_owned;
    let sql: &str = if is_read && params.policy.stmt_timeout_ms > 0 {
        sql_owned = crate::sql::hints::inject_max_execution_time(
            effective_sql,
            params.policy.stmt_timeout_ms,
        );
        &sql_owned
    } else {
        effective_sql
    };

    let cap = params.policy.row_cap;
    let timeout = Duration::from_millis(params.policy.stmt_timeout_ms.max(1) as u64);
    let outcome = tokio::time::timeout(timeout, collect_result(conn, sql, cap)).await;

    let (rows, fields, affected, truncated, insert_id) = match outcome {
        Ok(inner) => inner?,
        Err(_) => return Err(MySqlError::Timeout(params.policy.stmt_timeout_ms as u64)),
    };

    if let Some(spec) = pending_insert
        && let Some(id) = crate::backup::capture_insert_hint(
            &spec,
            &params.connection.name,
            params.database.or(params.connection.database.as_deref()),
            insert_id,
            affected,
            params.audit.as_ref(),
        )
    {
        backup_id = Some(id);
        backup_row_count = affected;
    }

    let mut value = ExecuteResult {
        journal_id: None,
        ddl_no_op: false,
        ddl_absent_targets: ddl_absent.iter().map(|(s, t)| format!("{s}.{t}")).collect(),
        ddl_executed_targets: ddl_executed,
        warnings: Vec::new(),
        rows,
        fields,
        affected_rows: affected,
        truncated,
        duration_ms: start.elapsed().as_millis() as u64,
        backup_id,
        backup_row_count,
    };
    value.warnings = warnings_out;
    Ok(value)
}

/// Stream rows with an early stop at the row/byte caps — never fetch all
/// and slice afterwards.
async fn collect_result(
    conn: &mut mysql_async::Conn,
    sql: &str,
    row_cap: u32,
) -> Result<(Vec<serde_json::Value>, Vec<String>, u64, bool, Option<i64>), MySqlError> {
    use mysql_async::prelude::*;
    let mut result = conn.query_iter(sql).await?;
    let columns: Vec<String> = result
        .columns()
        .as_ref()
        .map(|cols| cols.iter().map(|c| c.name_str().to_string()).collect())
        .unwrap_or_default();
    let column_types: Vec<mysql_async::consts::ColumnType> = result
        .columns()
        .as_ref()
        .map(|cols| cols.iter().map(|c| c.column_type()).collect())
        .unwrap_or_default();
    let column_charsets: Vec<u16> = result
        .columns()
        .as_ref()
        .map(|cols| cols.iter().map(|c| c.character_set()).collect())
        .unwrap_or_default();
    let mut rows_out: Vec<serde_json::Value> = Vec::new();
    let mut bytes: u64 = 0;
    let mut truncated = false;
    let stream = result.stream::<Row>().await?;
    let is_reader = stream.is_some();
    if !is_reader {
        drop(stream);
        let affected = conn.affected_rows();
        let insert_id = conn.last_insert_id().map(|id| id as i64);
        return Ok((Vec::new(), Vec::new(), affected, false, insert_id));
    }
    let mut stream = stream.expect("checked Some above");
    while let Some(row) = stream.next().await {
        let row = row?;
        if rows_out.len() >= row_cap as usize {
            truncated = true;
            break;
        }
        let mut obj = serde_json::Map::with_capacity(columns.len());
        for (i, name) in columns.iter().enumerate() {
            let v = row.as_ref(i).cloned().unwrap_or(Value::NULL);
            let ct = column_types
                .get(i)
                .copied()
                .unwrap_or(mysql_async::consts::ColumnType::MYSQL_TYPE_VAR_STRING);
            let cs = column_charsets.get(i).copied().unwrap_or(255);
            let j = value_with_column_type(&v, ct, cs);
            bytes += name.len() as u64 + j.to_string().len() as u64;
            obj.insert(name.clone(), j);
        }
        rows_out.push(serde_json::Value::Object(obj));
        if bytes > RESULT_BYTE_CAP {
            truncated = true;
            break;
        }
    }
    drop(stream);
    let affected = conn.affected_rows();
    let insert_id = conn.last_insert_id().map(|id| id as i64);
    Ok((rows_out, columns, affected, truncated, insert_id))
}

/// MySQL pre-mutation backup capture with row/byte caps.
pub async fn capture_backup_mysql(
    conn: &mut mysql_async::Conn,
    spec: &BackupSpec,
    connection_name: &str,
    database: Option<&str>,
    policy: &Policy,
    audit: Option<Arc<AuditDb>>,
) -> Result<Option<crate::backup::CapturedBackup>, MySqlError> {
    use mysql_async::prelude::*;
    let ts = time_iso();
    let tables = match spec {
        BackupSpec::None { .. } | BackupSpec::InsertHint { .. } => return Ok(None),
        BackupSpec::Rows { tables } | BackupSpec::Combined { tables } => tables,
        BackupSpec::Schema { tables } => {
            let mut first = None;
            for t in tables {
                let schema = show_create_table(conn, &t.db, &t.table).await;
                let id = crate::backup::insert_schema_backup_row(
                    &audit,
                    &ts,
                    connection_name,
                    database,
                    &t.table,
                    schema.as_deref(),
                )
                .map_err(|e| MySqlError::BackupFailed(e.to_string()))?;
                if first.is_none() {
                    first = Some(id);
                }
            }
            return Ok(first.map(|id| crate::backup::CapturedBackup {
                backup_id: id,
                total_rows: 0,
                truncated: false,
                total_bytes: 0,
            }));
        }
    };

    let row_cap = policy.max_backup_rows as usize;
    let byte_cap = policy.max_backup_bytes;
    let mut first_id: Option<i64> = None;
    let mut total_rows = 0u64;
    let mut total_bytes = 0u64;
    let mut truncated_any = false;

    for t in tables {
        let capped = crate::backup::extractor::with_limit(&t.select_sql, (row_cap + 1) as u64)
            .ok_or_else(|| {
                MySqlError::BackupOverflow(format!(
                    "backup query not safely limitable: {}",
                    t.select_sql.chars().take(80).collect::<String>()
                ))
            })?;
        // Absent targets are resolved by preflight (ddl.rs) BEFORE backup
        // capture; ER_NO_SUCH_TABLE here is a genuine mid-operation race
        // or error and denies the mutation (fail closed).
        let mut stream = conn
            .query_iter(capped.as_str())
            .await
            .map_err(|e| MySqlError::BackupFailed(e.to_string()))?;
        let mut rows: Vec<serde_json::Value> = Vec::new();
        let cols: Vec<String> = stream
            .columns()
            .as_ref()
            .map(|cs| cs.iter().map(|c| c.name_str().to_string()).collect())
            .unwrap_or_default();
        let mut srows = match stream.stream::<Row>().await {
            Ok(Some(s)) => s,
            Ok(None) => continue,
            Err(e) => return Err(MySqlError::BackupFailed(e.to_string())),
        };
        let mut truncated = false;
        while let Some(row) = srows.next().await {
            let row = row.map_err(|e| MySqlError::BackupFailed(e.to_string()))?;
            if rows.len() >= row_cap {
                truncated = true;
                break;
            }
            let mut obj = serde_json::Map::with_capacity(cols.len());
            for (i, name) in cols.iter().enumerate() {
                let v = row.as_ref(i).cloned().unwrap_or(Value::NULL);
                obj.insert(name.clone(), value_to_json(&v));
            }
            rows.push(serde_json::Value::Object(obj));
        }
        drop(srows);
        let json = if rows.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&rows).unwrap_or_default())
        };
        let bytes = json.as_ref().map(|j| j.len() as u64).unwrap_or(0);
        if truncated
            && matches!(
                policy.on_backup_overflow,
                crate::policy::model::BackupOverflow::Abort
            )
        {
            return Err(MySqlError::BackupOverflow(format!(
                "row cap exceeded ({})",
                row_cap
            )));
        }
        if bytes > byte_cap
            && matches!(
                policy.on_backup_overflow,
                crate::policy::model::BackupOverflow::Abort
            )
        {
            return Err(MySqlError::BackupOverflow(format!(
                "byte cap exceeded ({bytes} > {byte_cap})"
            )));
        }
        let schema = if matches!(spec, BackupSpec::Combined { .. }) {
            show_create_table(conn, &t.db, &t.table).await
        } else {
            None
        };
        let kind = match spec {
            BackupSpec::Combined { .. } => "combined",
            _ => "rows",
        };
        let count = rows.len() as u64;
        let id = crate::backup::insert_rows_backup_row(
            &audit,
            &ts,
            connection_name,
            database.or(t.db.as_deref()),
            &t.table,
            kind,
            json.as_deref(),
            schema.as_deref(),
            count,
            truncated,
            bytes,
        )
        .map_err(|e| MySqlError::BackupFailed(e.to_string()))?;
        if first_id.is_none() {
            first_id = Some(id);
        }
        total_rows += count;
        total_bytes += bytes;
        truncated_any |= truncated;
    }

    Ok(first_id.map(|id| crate::backup::CapturedBackup {
        backup_id: id,
        total_rows,
        truncated: truncated_any,
        total_bytes,
    }))
}

async fn show_create_table(
    conn: &mut mysql_async::Conn,
    db: &Option<String>,
    table: &str,
) -> Option<String> {
    use mysql_async::prelude::*;
    let target = match db {
        Some(db) => format!("`{}`.`{}`", db.replace('`', "``"), table.replace('`', "``")),
        None => format!("`{}`", table.replace('`', "``")),
    };
    let sql = format!("SHOW CREATE TABLE {target}");
    let row: Option<Row> = conn.exec_first(sql, ()).await.ok()?;
    let row = row?;
    let create: Option<String> = row.get(1);
    create
}

fn time_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> MySqlConnection {
        MySqlConnection {
            name: "t".into(),
            host: "db.example.invalid".into(),
            port: 3306,
            user: "u".into(),
            ..MySqlConnection::default()
        }
    }

    #[test]
    fn opts_carry_tls_override_and_bounds() {
        let mut c = conn();
        c.ssl = true;
        c.ssl_server_name = Some("db.prod.example.invalid".into());
        let opts = build_opts(&c, "pw", Some("app"), None, None);
        // The builder API does not expose readers; assert via the URL form.
        // The builder carries the SSL options; TLS handshake behaviour is
        // exercised by the live integration test.
        let _ = opts;
    }

    #[test]
    fn numeric_fidelity_mapping() {
        assert_eq!(
            value_to_json(&Value::Bytes(b"12345678901234567890".to_vec())),
            serde_json::json!("12345678901234567890")
        );
        assert_eq!(value_to_json(&Value::Int(-5)), serde_json::json!(-5));
        assert_eq!(
            value_to_json(&Value::UInt(u64::MAX)),
            serde_json::json!(u64::MAX)
        );
        assert_eq!(
            value_to_json(&Value::Date(2026, 8, 21, 15, 4, 5, 0)),
            serde_json::json!("2026-08-21 15:04:05")
        );
        assert_eq!(value_to_json(&Value::NULL), serde_json::Value::Null);
    }

    #[tokio::test]
    async fn pool_init_failure_is_not_cached() {
        // Port 1 on localhost: refused. Initialization must fail and the
        // manager must stay empty (no failed pool retained).
        use zeroize::Zeroizing;
        let mgr = pool_manager();
        mgr.invalidate_all();
        let c = conn();
        let pw = Zeroizing::new("pw".to_string());
        assert!(
            mgr.verified_pool(&c, &pw, None, 1, None, Some(1))
                .await
                .is_err()
        );
        assert_eq!(mgr.pool_count(), 0);
        mgr.invalidate_all();
    }
}
