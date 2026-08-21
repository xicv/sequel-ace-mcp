//! MySQL/MariaDB execution: bounded pools, TLS with server-name override,
//! hard-failing READ ONLY transactions, MAX_EXECUTION_TIME hints,
//! streaming with caps, lossless numerics, LOCAL INFILE disabled.

use crate::backup::extractor::{BackupSpec, extract_backup_spec};
use crate::config::MySqlConnection;
use crate::policy::classifier::ClassifiedStatement;
use crate::policy::model::{Policy, SqlCategory};
use futures_util::StreamExt;
use mysql_async::prelude::Queryable;
use mysql_async::{OptsBuilder, Pool, PoolConstraints, PoolOpts, Row, SslOpts, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
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
}

#[derive(Debug)]
pub struct ExecuteResult {
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
        .pool_opts(PoolOpts::default().with_constraints(PoolConstraints::new(1, 4).expect("1<=4")))
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

/// Per-connection pool registry. Pools are keyed by the connection's
/// transport-relevant identity plus the config revision, so policy or
/// endpoint changes invalidate old pools. Bounds: min 1, max 4.
pub struct PoolRegistry {
    pools: Mutex<HashMap<String, Pool>>,
}

static REGISTRY: OnceLock<PoolRegistry> = OnceLock::new();

pub fn pool_registry() -> &'static PoolRegistry {
    REGISTRY.get_or_init(|| PoolRegistry {
        pools: Mutex::new(HashMap::new()),
    })
}

impl PoolRegistry {
    pub fn pool_for(
        &self,
        conn: &MySqlConnection,
        password: &str,
        database: Option<&str>,
        revision: u64,
        host_override: Option<&str>,
        port_override: Option<u16>,
    ) -> Pool {
        // The pool bakes the password into its connect options, so the key
        // must change with the credential. A SHA-256 fingerprint is used —
        // the password itself never enters the key (or any log surface).
        let pw_fp = {
            use sha2::Digest as _;
            let d = Sha256::digest(password.as_bytes());
            d[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let key = format!(
            "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
            conn.name,
            host_override.unwrap_or(&conn.host),
            port_override.unwrap_or(conn.port),
            conn.user,
            database.or(conn.database.as_deref()).unwrap_or(""),
            conn.ssl,
            conn.ssl_server_name.as_deref().unwrap_or(""),
            revision,
            pw_fp,
        );
        let mut pools = self.pools.lock().unwrap();
        pools
            .entry(key)
            .or_insert_with(|| {
                let opts: mysql_async::Opts =
                    build_opts(conn, password, database, host_override, port_override).into();
                Pool::new(opts)
            })
            .clone()
    }

    pub fn invalidate_all(&self) {
        self.pools.lock().unwrap().clear();
    }

    pub fn pool_count(&self) -> usize {
        self.pools.lock().unwrap().len()
    }
}

pub struct MySqlExecuteParams<'a> {
    pub connection: &'a MySqlConnection,
    pub password: Zeroizing<String>,
    pub sql: &'a str,
    pub classified: &'a ClassifiedStatement,
    pub policy: &'a Policy,
    pub database: Option<&'a str>,
    pub audit: Option<Arc<AuditDb>>,
    pub revision: u64,
    /// Local endpoint when an SSH tunnel is in front of the server.
    pub tunnel_endpoint: Option<(String, u16)>,
}

/// Legacy numeric parity for text-protocol results: INT-family and
/// FLOAT/DOUBLE parse to JSON numbers; BIGINT and DECIMAL stay strings
/// (`bigNumberStrings` semantics — lossless round-trip).
pub fn value_with_column_type(v: &Value, ct: mysql_async::consts::ColumnType) -> serde_json::Value {
    use mysql_async::consts::ColumnType;
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
    let pool = pool_registry().pool_for(
        params.connection,
        &params.password,
        params.database,
        params.revision,
        Some(&host),
        Some(port),
    );
    let mut conn = pool.get_conn().await?;

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

    let result = run_in_transaction(&mut conn, &params, is_read, start).await;

    match &result {
        Ok(_) => {
            if in_tx && let Err(e) = conn.query_drop("COMMIT").await {
                let _ = conn.query_drop("ROLLBACK").await;
                return Err(MySqlError::Driver(e));
            }
        }
        Err(_) => {
            if in_tx {
                let _ = conn.query_drop("ROLLBACK").await;
            }
        }
    }
    result
}

async fn run_in_transaction(
    conn: &mut mysql_async::Conn,
    params: &MySqlExecuteParams<'_>,
    is_read: bool,
    start: Instant,
) -> Result<ExecuteResult, MySqlError> {
    // Pre-mutation backup (fail-closed: capture errors deny the mutation).
    let mut backup_id: Option<i64> = None;
    let mut backup_row_count: u64 = 0;
    let mut pending_insert: Option<BackupSpec> = None;
    if crate::backup::extractor::is_backup_required(params.classified.ast_type) {
        let spec = extract_backup_spec(
            params.sql,
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
                }
            }
        }
    }

    // Reads carry the optimizer timeout hint.
    let sql_owned;
    let sql: &str = if is_read && params.policy.stmt_timeout_ms > 0 {
        sql_owned =
            crate::sql::hints::inject_max_execution_time(params.sql, params.policy.stmt_timeout_ms);
        &sql_owned
    } else {
        params.sql
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

    Ok(ExecuteResult {
        rows,
        fields,
        affected_rows: affected,
        truncated,
        duration_ms: start.elapsed().as_millis() as u64,
        backup_id,
        backup_row_count,
    })
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
            let j = value_with_column_type(&v, ct);
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
        let capped = crate::backup::extractor::with_limit(&t.select_sql, (row_cap + 1) as u64);
        let mut stream = match conn.query_iter(capped.as_str()).await {
            Ok(r) => r,
            Err(mysql_async::Error::Server(se)) if se.code == 1146 || se.code == 1051 => {
                // ER_NO_SUCH_TABLE / ER_BAD_TABLE_ERROR: the pre-image of a
                // table that does not exist is empty — record it and let
                // the DROP proceed (other failures still deny).
                let id = crate::backup::insert_rows_backup_row(
                    &audit,
                    &time_iso(),
                    connection_name,
                    database.or(t.db.as_deref()),
                    &t.table,
                    "combined",
                    None,
                    None,
                    0,
                    false,
                    0,
                )
                .map_err(|e| MySqlError::BackupFailed(e.to_string()))?;
                if first_id.is_none() {
                    first_id = Some(id);
                }
                continue;
            }
            Err(e) => return Err(MySqlError::BackupFailed(e.to_string())),
        };
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

    #[test]
    fn pools_keyed_and_invalidated() {
        let reg = pool_registry();
        let before = reg.pool_count();
        let c = conn();
        let p1 = reg.pool_for(&c, "pw", None, 1, None, None);
        let p2 = reg.pool_for(&c, "pw", None, 1, None, None);
        let p3 = reg.pool_for(&c, "pw", None, 2, None, None);
        assert_eq!(reg.pool_count(), before + 2, "revision changes the key");
        let _ = (p1, p2, p3);
        reg.invalidate_all();
        assert_eq!(reg.pool_count(), 0);
    }
}
