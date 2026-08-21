//! SQLite execution: read-only handles for reads, BEGIN IMMEDIATE for
//! writes, interrupt-handle cancellation, streaming with caps, symlink
//! checks, and the shared backup pipeline.

use crate::backup::capture::{capture_backup_sqlite, capture_insert_hint};
use crate::backup::extractor::{BackupSpec, extract_backup_spec};
use crate::config::SqliteConnection;
use crate::policy::classifier::{ClassifiedStatement, ClassifyError, Dialect, classify_statement};
use crate::policy::model::{Policy, SqlCategory};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Rows, Statement};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::audit::AuditDb;

#[derive(Debug, Error)]
pub enum SqliteError {
    #[error("{0}")]
    Db(#[from] rusqlite::Error),
    #[error("cannot classify statement: {0}")]
    Classify(String),
    #[error("read-only connection: database file {0} not found")]
    NotFound(String),
    #[error("read-only connection: path {0} is a symlink — refusing")]
    Symlink(String),
    #[error("statement timed out after {0}ms")]
    Timeout(u64),
    #[error("backup overflow: {0}")]
    BackupOverflow(String),
    #[error("backup capture failed: {0} — mutation denied")]
    BackupFailed(String),
}

#[derive(Debug)]
pub struct ExecuteResult {
    /// Operation-journal row id (D3); MySQL mutations create journals,
    /// SQLite ones currently do not (single-file local transactions).
    pub journal_id: Option<i64>,
    pub rows: Vec<serde_json::Value>,
    pub fields: Vec<String>,
    pub affected_rows: u64,
    pub truncated: bool,
    pub duration_ms: u64,
    pub backup_id: Option<i64>,
    pub backup_row_count: u64,
}

const READ_CATEGORIES: [SqlCategory; 1] = [SqlCategory::Read];

/// Open a SQLite database with the legacy semantics: reads use a read-only
/// handle that must already exist; writes create if needed.
pub fn open_sqlite_database(
    conn: &SqliteConnection,
    readonly: bool,
    timeout_ms: u32,
) -> Result<Connection, SqliteError> {
    let filename = crate::app::paths::expand_tilde(&conn.path);
    if readonly {
        let canonical = std::fs::canonicalize(&filename)
            .map_err(|_| SqliteError::NotFound(filename.display().to_string()))?;
        verify_no_symlink_escape(&canonical)?;
        let db = Connection::open_with_flags(
            &canonical,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(timeout_ms.max(1) as u64))?;
        Ok(db)
    } else {
        let db = Connection::open_with_flags(
            &filename,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(timeout_ms.max(1) as u64))?;
        db.pragma_update(None, "foreign_keys", true)?;
        Ok(db)
    }
}

/// Reads must not follow a substituted symlink outside the resolved tree.
fn verify_no_symlink_escape(canonical: &Path) -> Result<(), SqliteError> {
    // canonicalize already resolved symlinks; refuse when the final
    // component itself is a link (raced) by checking the parent chain.
    let mut dir = canonical.parent().map(PathBuf::from);
    while let Some(d) = dir {
        let meta = std::fs::symlink_metadata(&d);
        if matches!(meta, Ok(m) if m.file_type().is_symlink()) {
            return Err(SqliteError::Symlink(d.display().to_string()));
        }
        dir = d.parent().map(PathBuf::from);
    }
    Ok(())
}

fn value_to_json(vr: ValueRef<'_>) -> serde_json::Value {
    match vr {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(i) => serde_json::json!(i),
        ValueRef::Real(f) => serde_json::json!(f),
        ValueRef::Text(t) => serde_json::json!(String::from_utf8_lossy(t)),
        ValueRef::Blob(b) => {
            use base64::Engine;
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b))
        }
    }
}

struct StreamStats {
    rows: Vec<serde_json::Value>,
    fields: Vec<String>,
    affected_rows: u64,
    truncated: bool,
    insert_id: Option<i64>,
}

/// Stream rows with an early stop at the row cap (never materialize then
/// slice). The byte cap stops iteration once accumulated JSON size
/// exceeds it.
fn run_streaming(
    db: &Connection,
    sql: &str,
    row_cap: u32,
    byte_cap: u64,
) -> Result<StreamStats, SqliteError> {
    let interrupt = db.get_interrupt_handle();
    let mut stmt: Statement = db.prepare(sql)?;
    let fields: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    // A statement exposing columns returns rows (SELECT/PRAGMA/RETURNING);
    // otherwise it is a mutation: execute it and read change stats.
    let is_reader = stmt.column_count() > 0;
    if !is_reader {
        stmt.execute([])?;
        drop(stmt);
        let _ = interrupt;
        let stats = get_change_stats(db)?;
        return Ok(StreamStats {
            rows: Vec::new(),
            fields: Vec::new(),
            affected_rows: stats.0,
            truncated: false,
            insert_id: stats.1,
        });
    }
    let mut rows: Rows = stmt.query([])?;
    let mut out = Vec::new();
    let mut truncated = false;
    let mut bytes: u64 = 0;
    while let Some(row) = rows.next()? {
        if out.len() >= row_cap as usize {
            truncated = true;
            break;
        }
        let mut obj = serde_json::Map::with_capacity(fields.len());
        for (i, name) in fields.iter().enumerate() {
            let v = value_to_json(row.get_ref(i)?);
            obj.insert(name.clone(), v);
        }
        let val = serde_json::Value::Object(obj);
        bytes += val.encoded_len() as u64;
        out.push(val);
        if bytes > byte_cap {
            truncated = true;
            break;
        }
    }
    drop(rows);
    drop(stmt);
    let _ = interrupt;
    let stats = get_change_stats(db)?;
    Ok(StreamStats {
        rows: out,
        fields,
        affected_rows: stats.0,
        truncated,
        insert_id: stats.1,
    })
}

trait JsonLen {
    fn encoded_len(&self) -> usize;
}

impl JsonLen for serde_json::Value {
    fn encoded_len(&self) -> usize {
        serde_json::to_string(self).map(|s| s.len()).unwrap_or(0)
    }
}

fn get_change_stats(db: &Connection) -> Result<(u64, Option<i64>), SqliteError> {
    let affected: i64 = db.query_row("SELECT changes()", [], |r| r.get(0))?;
    let insert_id: i64 = db.query_row("SELECT last_insert_rowid()", [], |r| r.get(0))?;
    Ok((
        affected.max(0) as u64,
        if insert_id > 0 { Some(insert_id) } else { None },
    ))
}

pub struct SqliteExecuteParams<'a> {
    pub connection: &'a SqliteConnection,
    pub sql: &'a str,
    pub classified: &'a ClassifiedStatement,
    pub policy: &'a Policy,
    pub database: Option<&'a str>,
    pub audit: Option<Arc<AuditDb>>,
}

/// Execute one classified statement against a SQLite database, using the
/// shared backup pipeline. Backup capture failure denies the mutation.
/// A wall-clock timer armed on this connection interrupts runaway
/// statements at `policy.stmt_timeout_ms`.
pub fn execute_sqlite_statement(
    params: SqliteExecuteParams<'_>,
) -> Result<ExecuteResult, SqliteError> {
    let start = Instant::now();
    let is_read = READ_CATEGORIES.contains(&params.classified.category);
    let db = open_sqlite_database(params.connection, is_read, params.policy.stmt_timeout_ms)?;
    let interrupt = db.get_interrupt_handle();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_flag = done.clone();
    let timeout_ms = params.policy.stmt_timeout_ms;
    let timer = std::thread::spawn(move || {
        for _ in 0..(timeout_ms.max(1)) {
            if done_flag.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if !done_flag.load(std::sync::atomic::Ordering::SeqCst) {
            interrupt.interrupt();
        }
    });

    let result = execute_on_connection(&db, &params, start);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = timer.join();
    match result {
        Err(SqliteError::Db(rusqlite::Error::SqliteFailure(ffi, _)))
            if ffi.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            Err(SqliteError::Timeout(timeout_ms as u64))
        }
        other => other,
    }
}

fn execute_on_connection(
    db: &Connection,
    params: &SqliteExecuteParams<'_>,
    start: Instant,
) -> Result<ExecuteResult, SqliteError> {
    let is_read = READ_CATEGORIES.contains(&params.classified.category);
    let mut in_txn = false;
    if !is_read && params.classified.category != SqlCategory::TxCtrl {
        db.execute_batch("BEGIN IMMEDIATE")?;
        in_txn = true;
    }

    let result = (|| -> Result<ExecuteResult, SqliteError> {
        let mut backup_id: Option<i64> = None;
        let mut backup_row_count: u64 = 0;
        let mut pending_insert_spec: Option<BackupSpec> = None;

        if crate::backup::extractor::is_backup_required(params.classified.ast_type) {
            let spec = extract_backup_spec(params.sql, params.classified.ast_type, Dialect::SQLite)
                .map_err(|e| SqliteError::BackupFailed(e.to_string()))?;
            match &spec {
                BackupSpec::InsertHint { .. } => pending_insert_spec = Some(spec),
                BackupSpec::None { .. } => {}
                _ => {
                    match capture_backup_sqlite(
                        db,
                        &spec,
                        &params.connection.name,
                        params
                            .database
                            .or(Some(params.connection.database.as_str())),
                        params.policy,
                        params.audit.as_ref(),
                    ) {
                        Ok(Some(captured)) => {
                            backup_id = Some(captured.backup_id);
                            backup_row_count = captured.total_rows;
                        }
                        Ok(None) => {}
                        Err(e) => return Err(SqliteError::BackupFailed(e.to_string())),
                    }
                }
            }
        }

        let stats = run_streaming(db, params.sql, params.policy.row_cap, 4 * 1024 * 1024)?;

        if let Some(spec) = pending_insert_spec
            && let Some(id) = capture_insert_hint(
                &spec,
                &params.connection.name,
                params
                    .database
                    .or(Some(params.connection.database.as_str())),
                stats.insert_id,
                stats.affected_rows,
                params.audit.as_ref(),
            )
        {
            backup_id = Some(id);
            backup_row_count = stats.affected_rows;
        }

        if in_txn {
            db.execute_batch("COMMIT")?;
            in_txn = false;
        }

        Ok(ExecuteResult {
            journal_id: None,
            rows: stats.rows,
            fields: stats.fields,
            affected_rows: stats.affected_rows,
            truncated: stats.truncated,
            duration_ms: start.elapsed().as_millis() as u64,
            backup_id,
            backup_row_count,
        })
    })();

    if result.is_err() && in_txn {
        let _ = db.execute_batch("ROLLBACK");
    }
    result
}

/// Convenience classifier wrapper matching the legacy entry point.
pub fn classify_for_sqlite(sql: &str) -> Result<ClassifiedStatement, ClassifyError> {
    classify_statement(sql, Dialect::SQLite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::{PolicyPresetName, policy_from_preset};

    fn sqlite_conn(path: &std::path::Path) -> SqliteConnection {
        SqliteConnection {
            name: "local-sqlite".into(),
            path: path.display().to_string(),
            ..SqliteConnection::default()
        }
    }

    fn classify(sql: &str) -> ClassifiedStatement {
        classify_for_sqlite(sql).unwrap()
    }

    #[test]
    fn ddl_write_read_roundtrip_with_backups() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.sqlite");
        let conn = sqlite_conn(&file);
        let policy = policy_from_preset(PolicyPresetName::Development);
        let audit = Arc::new(AuditDb::at_path(&dir.path().join("audit.sqlite")).unwrap());

        // DDL
        let ddl = classify("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
        let r = execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)",
            classified: &ddl,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        assert_eq!(r.affected_rows, 0);

        // INSERT with backup hint
        let ins = classify("INSERT INTO users (id, name) VALUES (1, 'a'), (2, 'b')");
        let r = execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "INSERT INTO users (id, name) VALUES (1, 'a'), (2, 'b')",
            classified: &ins,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        assert_eq!(r.affected_rows, 2);
        assert!(r.backup_id.is_some(), "insert-hint backup expected");

        // UPDATE with row backup
        let upd = classify("UPDATE users SET name = 'x' WHERE id = 1");
        let r = execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "UPDATE users SET name = 'x' WHERE id = 1",
            classified: &upd,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        assert_eq!(r.affected_rows, 1);
        assert!(r.backup_id.is_some());

        // Read via read-only handle
        let read = classify("SELECT id, name FROM users");
        let r = execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "SELECT id, name FROM users",
            classified: &read,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.fields, vec!["id", "name"]);
        assert_eq!(r.rows[0]["name"], serde_json::json!("x"));
    }

    #[test]
    fn row_cap_truncates_without_materializing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.sqlite");
        let conn = sqlite_conn(&file);
        let mut policy = policy_from_preset(PolicyPresetName::Development);
        policy.row_cap = 5;
        let audit = Arc::new(AuditDb::at_path(&dir.path().join("audit.sqlite")).unwrap());
        let ddl = classify("CREATE TABLE t (n INTEGER)");
        execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "CREATE TABLE t (n INTEGER)",
            classified: &ddl,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        let ins = classify("INSERT INTO t (n) VALUES (1),(2),(3),(4),(5),(6),(7),(8)");
        execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "INSERT INTO t (n) VALUES (1),(2),(3),(4),(5),(6),(7),(8)",
            classified: &ins,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        let read = classify("SELECT n FROM t");
        let r = execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "SELECT n FROM t",
            classified: &read,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        assert_eq!(r.rows.len(), 5);
        assert!(r.truncated);
    }

    #[test]
    fn readonly_missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let conn = sqlite_conn(&dir.path().join("missing.sqlite"));
        let err = open_sqlite_database(&conn, true, 5000).unwrap_err();
        assert!(matches!(err, SqliteError::NotFound(_)));
    }

    #[test]
    fn statement_timeout_interrupts() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.sqlite");
        let conn = sqlite_conn(&file);
        let mut policy = policy_from_preset(PolicyPresetName::Development);
        policy.stmt_timeout_ms = 150;
        let audit = Arc::new(AuditDb::at_path(&dir.path().join("audit.sqlite")).unwrap());
        let ddl = classify("CREATE TABLE t (n INTEGER)");
        execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "CREATE TABLE t (n INTEGER)",
            classified: &ddl,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap();
        let read = classify(
            "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT count(*) FROM c",
        );
        let err = execute_sqlite_statement(SqliteExecuteParams {
            connection: &conn,
            sql: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT count(*) FROM c",
            classified: &read,
            policy: &policy,
            database: None,
            audit: Some(audit.clone()),
        })
        .unwrap_err();
        assert!(matches!(err, SqliteError::Timeout(_)), "{err:?}");
    }
}
