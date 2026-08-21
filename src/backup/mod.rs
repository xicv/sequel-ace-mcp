//! Backup capture and restore planning over the audit database.

pub mod extractor;

use crate::audit::AuditDb;
use crate::policy::model::Policy;
use extractor::{BackupSpec, BackupTable};
use rusqlite::params;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup row cap exceeded ({observed} > {cap})")]
    RowOverflow { observed: u64, cap: u64 },
    #[error("backup byte cap exceeded ({observed} > {cap})")]
    ByteOverflow { observed: u64, cap: u64 },
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

#[derive(Debug, Clone)]
pub struct CapturedBackup {
    pub backup_id: i64,
    pub total_rows: u64,
    pub truncated: bool,
    pub total_bytes: u64,
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[allow(clippy::too_many_arguments)]
fn insert_backup_row(
    audit: &Option<Arc<AuditDb>>,
    ts: &str,
    connection: &str,
    database: Option<&str>,
    table: &str,
    kind: &str,
    rows_json: Option<&str>,
    schema_sql: Option<&str>,
    primary_key: Option<&str>,
    row_count: u64,
    truncated: bool,
    bytes: u64,
) -> rusqlite::Result<i64> {
    let db = match audit {
        Some(a) => a.clone(),
        None => AuditDb::shared(),
    };
    db.with_tx(|c| {
        c.execute(
            "INSERT INTO backup
               (ts, connection, database, table_name, backup_kind, rows_json,
                schema_sql, primary_key, row_count, truncated, size_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                ts,
                connection,
                database,
                table,
                kind,
                rows_json,
                schema_sql,
                primary_key,
                row_count as i64,
                truncated as i64,
                bytes as i64,
            ],
        )?;
        Ok(c.last_insert_rowid())
    })
}

fn show_create_table_sqlite(
    db: &rusqlite::Connection,
    database: Option<&str>,
    table: &str,
) -> Option<String> {
    let schema_table = match database {
        Some(d) => format!("{}.sqlite_schema", extractor::quote_ident(d)),
        None => "sqlite_schema".to_string(),
    };
    db.query_row(
        &format!(
            "SELECT sql FROM {schema_table}
              WHERE name = ?1 AND type IN ('table', 'view')
              ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END LIMIT 1"
        ),
        params![table],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
}

pub mod capture {
    //! Re-exports used by the executors.
    pub use super::{
        BackupError, CapturedBackup, capture_backup_sqlite, capture_insert_hint,
        insert_rows_backup_row, insert_schema_backup_row,
    };
}

/// Insert a schema-only backup row (used by the MySQL and SQLite paths).
pub fn insert_schema_backup_row(
    audit: &Option<Arc<AuditDb>>,
    ts: &str,
    connection_name: &str,
    database: Option<&str>,
    table: &str,
    schema_sql: Option<&str>,
) -> rusqlite::Result<i64> {
    insert_backup_row(
        audit,
        ts,
        connection_name,
        database,
        table,
        "schema",
        None,
        schema_sql,
        None,
        0,
        false,
        0,
    )
}

/// Insert a rows/combined backup row (used by the MySQL path).
#[allow(clippy::too_many_arguments)]
pub fn insert_rows_backup_row(
    audit: &Option<Arc<AuditDb>>,
    ts: &str,
    connection_name: &str,
    database: Option<&str>,
    table: &str,
    kind: &str,
    rows_json: Option<&str>,
    schema_sql: Option<&str>,
    row_count: u64,
    truncated: bool,
    bytes: u64,
) -> rusqlite::Result<i64> {
    insert_backup_row(
        audit,
        ts,
        connection_name,
        database,
        table,
        kind,
        rows_json,
        schema_sql,
        None,
        row_count,
        truncated,
        bytes,
    )
}

/// Capture a pre-mutation backup from a SQLite handle, enforcing the row
/// and byte caps with the policy's overflow behaviour.
pub fn capture_backup_sqlite(
    db: &rusqlite::Connection,
    spec: &BackupSpec,
    connection_name: &str,
    database: Option<&str>,
    policy: &Policy,
    audit: Option<&Arc<AuditDb>>,
) -> Result<Option<CapturedBackup>, BackupError> {
    let ts = iso_now();
    let row_cap = policy.max_backup_rows as u64;
    let byte_cap = policy.max_backup_bytes;

    let tables = match spec {
        BackupSpec::None { .. } | BackupSpec::InsertHint { .. } => return Ok(None),
        BackupSpec::Rows { tables } | BackupSpec::Combined { tables } => tables,
        BackupSpec::Schema { tables } => {
            let mut first_id = None;
            let mut total = 0u64;
            for t in tables {
                let schema_sql = show_create_table_sqlite(db, database, &t.table);
                let id = insert_backup_row(
                    &audit.map(Arc::clone),
                    &ts,
                    connection_name,
                    database,
                    &t.table,
                    "schema",
                    None,
                    schema_sql.as_deref(),
                    None,
                    0,
                    false,
                    0,
                )?;
                if first_id.is_none() {
                    first_id = Some(id);
                }
                total += 1;
            }
            return Ok(first_id.map(|id| CapturedBackup {
                backup_id: id,
                total_rows: 0,
                truncated: false,
                total_bytes: total,
            }));
        }
    };

    let mut first_id: Option<i64> = None;
    let mut total_rows = 0u64;
    let mut total_bytes = 0u64;
    let mut truncated_any = false;

    for t in tables {
        let (rows_json, schema_sql, row_count, truncated, bytes) =
            fetch_rows_sqlite(db, t, row_cap, database)?;
        if truncated
            && matches!(
                policy.on_backup_overflow,
                crate::policy::model::BackupOverflow::Abort
            )
        {
            return Err(BackupError::RowOverflow {
                observed: row_cap + 1,
                cap: row_cap,
            });
        }
        if bytes > byte_cap
            && matches!(
                policy.on_backup_overflow,
                crate::policy::model::BackupOverflow::Abort
            )
        {
            return Err(BackupError::ByteOverflow {
                observed: bytes,
                cap: byte_cap,
            });
        }
        let kind = match spec {
            BackupSpec::Combined { .. } => "combined",
            _ => "rows",
        };
        let schema_sql = if matches!(spec, BackupSpec::Combined { .. }) {
            schema_sql.or_else(|| show_create_table_sqlite(db, database, &t.table))
        } else {
            schema_sql
        };
        let id = insert_backup_row(
            &audit.map(Arc::clone),
            &ts,
            connection_name,
            database,
            &t.table,
            kind,
            rows_json.as_deref(),
            schema_sql.as_deref(),
            None,
            row_count,
            truncated,
            bytes,
        )?;
        if first_id.is_none() {
            first_id = Some(id);
        }
        total_rows += row_count;
        total_bytes += bytes;
        truncated_any |= truncated;
    }

    Ok(first_id.map(|id| CapturedBackup {
        backup_id: id,
        total_rows,
        truncated: truncated_any,
        total_bytes,
    }))
}

/// Row payload fetched for a backup.
type RowsFetch = (Option<String>, Option<String>, u64, bool, u64);

fn fetch_rows_sqlite(
    db: &rusqlite::Connection,
    t: &BackupTable,
    row_cap: u64,
    _database: Option<&str>,
) -> Result<RowsFetch, BackupError> {
    let capped = crate::backup::extractor::with_limit(&t.select_sql, row_cap + 1);
    let mut stmt = db.prepare(&capped)?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt.query([])?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut truncated = false;
    while let Some(row) = rows.next()? {
        if out.len() as u64 >= row_cap {
            truncated = true;
            break;
        }
        let mut obj = serde_json::Map::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            let v = match row.get_ref(i)? {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(n) => serde_json::json!(n),
                rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                rusqlite::types::ValueRef::Text(s) => {
                    serde_json::json!(String::from_utf8_lossy(s))
                }
                rusqlite::types::ValueRef::Blob(b) => {
                    use base64::Engine;
                    serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b))
                }
            };
            obj.insert(name.clone(), v);
        }
        out.push(serde_json::Value::Object(obj));
    }
    let bytes = serde_json::to_string(&out)
        .map(|s| s.len() as u64)
        .unwrap_or(0);
    let count = out.len() as u64;
    let json = if count > 0 {
        Some(serde_json::to_string(&out).unwrap_or_default())
    } else {
        None
    };
    Ok((json, None, count, truncated, bytes))
}

/// Record an insert rollback hint (explicit PK values or autoincrement
/// range) after a successful INSERT.
pub fn capture_insert_hint(
    spec: &BackupSpec,
    connection_name: &str,
    database: Option<&str>,
    insert_id: Option<i64>,
    affected_rows: u64,
    audit: Option<&Arc<AuditDb>>,
) -> Option<i64> {
    let BackupSpec::InsertHint {
        table,
        explicit_pk_values,
        ..
    } = spec
    else {
        return None;
    };
    let (primary_key, rows_json, row_count) = if let Some(values) = explicit_pk_values {
        if values.is_empty() {
            return None;
        }
        let pk = serde_json::json!({
            "kind": "explicit",
            "columns": ["id"],
            "values": values,
        })
        .to_string();
        let rows = serde_json::to_string(values).ok()?;
        (pk, Some(rows), values.len() as u64)
    } else if let (Some(start), true) = (insert_id, affected_rows > 0) {
        let end = start + affected_rows as i64 - 1;
        let pk = serde_json::json!({
            "kind": "range",
            "column": "id",
            "start": start,
            "end": end,
        })
        .to_string();
        (pk, None, affected_rows)
    } else {
        return None;
    };
    let bytes = rows_json.as_ref().map(|r| r.len() as u64).unwrap_or(0);
    insert_backup_row(
        &audit.map(Arc::clone),
        &iso_now(),
        connection_name,
        database.or(table.db.as_deref()),
        &table.table,
        "insert-hint",
        rows_json.as_deref(),
        None,
        Some(&primary_key),
        row_count,
        false,
        bytes,
    )
    .ok()
}

/// Backup listing row (legacy shape).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackupRow {
    pub id: i64,
    pub ts: String,
    pub connection: String,
    pub database: Option<String>,
    pub table_name: String,
    pub backup_kind: String,
    pub row_count: u64,
    pub truncated: bool,
    pub size_bytes: u64,
}

pub fn list_backups(
    audit: &Arc<AuditDb>,
    connection: Option<&str>,
    limit: u32,
) -> rusqlite::Result<Vec<BackupRow>> {
    let limit = limit.min(1000);
    audit.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, ts, connection, database, table_name, backup_kind, row_count, truncated, size_bytes
               FROM backup
              WHERE (?1 IS NULL OR connection = ?1)
              ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![connection, limit], |r| {
            Ok(BackupRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                connection: r.get(2)?,
                database: r.get(3)?,
                table_name: r.get(4)?,
                backup_kind: r.get(5)?,
                row_count: r.get::<_, i64>(6)?.max(0) as u64,
                truncated: r.get::<_, i64>(7)? != 0,
                size_bytes: r.get::<_, i64>(8)?.max(0) as u64,
            })
        })?;
        rows.collect()
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BackupDetail {
    pub id: i64,
    pub ts: String,
    pub connection: String,
    pub database: Option<String>,
    pub table_name: String,
    pub backup_kind: String,
    pub row_count: u64,
    pub truncated: bool,
    pub size_bytes: u64,
    pub rows: Option<serde_json::Value>,
    pub schema_sql: Option<String>,
    pub primary_key: Option<String>,
}

pub fn get_backup(audit: &Arc<AuditDb>, id: i64) -> rusqlite::Result<Option<BackupDetail>> {
    audit.with(|c| {
        c.query_row(
            "SELECT id, ts, connection, database, table_name, backup_kind, rows_json,
                    schema_sql, primary_key, row_count, truncated, size_bytes
               FROM backup WHERE id = ?1",
            params![id],
            |r| {
                let rows_json: Option<String> = r.get(6)?;
                Ok(BackupDetail {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    connection: r.get(2)?,
                    database: r.get(3)?,
                    table_name: r.get(4)?,
                    backup_kind: r.get(5)?,
                    row_count: r.get::<_, i64>(9)?.max(0) as u64,
                    truncated: r.get::<_, i64>(10)? != 0,
                    size_bytes: r.get::<_, i64>(11)?.max(0) as u64,
                    rows: rows_json.and_then(|j| serde_json::from_str(&j).ok()),
                    schema_sql: r.get(7)?,
                    primary_key: r.get(8)?,
                })
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
    })
}
