//! Backup restore (legacy `backup/restore.ts` port): build a
//! dialect-specific replay plan from a stored backup row, then execute
//! it inside one transaction. Row backups replay as upserts, schema
//! backups as their captured `CREATE TABLE`, and insert-hint backups as
//! the DELETE of exactly the rows the original INSERT created. The
//! restore always goes through the normal gate when invoked as a tool
//! (it counts as a write).

use crate::audit::AuditDb;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreDialect {
    MySql,
    SQLite,
}

#[derive(Debug, Error)]
pub enum RestoreError {
    #[error("backup #{0} not found")]
    NotFound(i64),
    #[error("restore planning failed: {0}")]
    Plan(String),
    #[error("restore execution failed: {0}")]
    Execution(String),
}

#[derive(Debug, Clone)]
pub struct RestorePlan {
    pub backup_id: i64,
    pub statements: Vec<String>,
    pub row_count: u64,
    pub warnings: Vec<String>,
    /// Set for insert-hint plans (the dangerous DELETE case).
    pub is_insert_hint_delete: bool,
}

/// The stored detail of one backup row.
#[derive(Debug, Clone)]
pub struct BackupDetail {
    pub id: i64,
    pub ts: String,
    pub connection: String,
    pub database: Option<String>,
    pub table_name: String,
    pub backup_kind: String,
    pub rows_json: Option<String>,
    pub schema_sql: Option<String>,
    pub primary_key: Option<String>,
    pub row_count: u64,
    pub truncated: bool,
}

pub fn get_backup(audit: &Arc<AuditDb>, id: i64) -> Option<BackupDetail> {
    audit
        .with(|c| {
            c.query_row(
                "SELECT id, ts, connection, database, table_name, backup_kind,
                        rows_json, schema_sql, primary_key, row_count, truncated
                   FROM backup WHERE id = ?1",
                [id],
                |r| {
                    Ok(BackupDetail {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        connection: r.get(2)?,
                        database: r.get(3)?,
                        table_name: r.get(4)?,
                        backup_kind: r.get(5)?,
                        rows_json: r.get(6)?,
                        schema_sql: r.get(7)?,
                        primary_key: r.get(8)?,
                        row_count: r.get::<_, i64>(9)?.max(0) as u64,
                        truncated: r.get::<_, i64>(10)? != 0,
                    })
                },
            )
        })
        .ok()
}

fn quote_id(id: &str) -> String {
    format!("`{}`", id.replace('`', "``"))
}

fn table_ref_sql(db: Option<&str>, table: &str) -> String {
    match db {
        Some(db) => format!("{}.{}", quote_id(db), quote_id(table)),
        None => quote_id(table),
    }
}

fn escape_value(v: &serde_json::Value, dialect: RestoreDialect) -> String {
    match v {
        serde_json::Value::Null => "NULL".into(),
        serde_json::Value::Bool(b) => u8::from(*b).to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            let escaped = s.replace('\\', "\\\\").replace('\'', "''");
            format!("'{escaped}'")
        }
        // Structured binary values come back as
        // {"type":"binary","encoding":"base64","data":…} — restore them
        // as SQL blob literals.
        serde_json::Value::Object(o)
            if o.get("type").and_then(|t| t.as_str()) == Some("binary")
                && o.get("encoding").and_then(|e| e.as_str()) == Some("base64") =>
        {
            use base64::Engine;
            let data = o.get("data").and_then(|d| d.as_str()).unwrap_or("");
            match base64::engine::general_purpose::STANDARD.decode(data) {
                Ok(bytes) => {
                    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    match dialect {
                        RestoreDialect::SQLite => format!("X'{hex}'"),
                        RestoreDialect::MySql => format!("0x{hex}"),
                    }
                }
                Err(_) => "NULL".into(),
            }
        }
        // Other objects/arrays (legacy stored JSON text) round-trip as
        // escaped JSON strings.
        other => {
            let text = other.to_string();
            let escaped = text.replace('\\', "\\\\").replace('\'', "''");
            format!("'{escaped}'")
        }
    }
}

/// Build the replay plan for backup `id` in the given dialect.
pub fn plan_restore(
    audit: &Arc<AuditDb>,
    id: i64,
    dialect: RestoreDialect,
) -> Result<RestorePlan, RestoreError> {
    let backup = get_backup(audit, id).ok_or(RestoreError::NotFound(id))?;
    let mut statements: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut is_insert_hint_delete = false;

    if backup.truncated {
        warnings.push("backup was truncated; restore will not be complete".into());
    }

    if backup.backup_kind == "schema" {
        if let Some(schema_sql) = &backup.schema_sql {
            warnings.push(
                "schema-only backup; running this will fail unless the table was dropped first"
                    .into(),
            );
            statements.push(format!("{schema_sql};"));
        }
        return Ok(RestorePlan {
            backup_id: id,
            statements,
            row_count: 0,
            warnings,
            is_insert_hint_delete,
        });
    }

    if backup.backup_kind == "combined"
        && let Some(schema_sql) = &backup.schema_sql
    {
        statements.push(format!("{schema_sql};"));
    }

    if backup.backup_kind == "insert-hint" {
        let Some(pk_json) = &backup.primary_key else {
            warnings.push(
                "insert-hint backup has no recoverable PK metadata; nothing to restore".into(),
            );
            return Ok(RestorePlan {
                backup_id: id,
                statements,
                row_count: 0,
                warnings,
                is_insert_hint_delete,
            });
        };
        let tref = table_ref_sql(backup.database.as_deref(), &backup.table_name);
        let pk: serde_json::Value = serde_json::from_str(pk_json)
            .map_err(|e| RestoreError::Plan(format!("bad PK metadata: {e}")))?;
        match pk["kind"].as_str() {
            Some("range") => {
                let column = pk["column"].as_str().unwrap_or_default();
                let start = pk["start"].clone();
                let end = pk["end"].clone();
                statements.push(format!(
                    "DELETE FROM {tref} WHERE {} BETWEEN {} AND {};",
                    quote_id(column),
                    escape_value(&start, dialect),
                    escape_value(&end, dialect),
                ));
            }
            Some("explicit") => {
                let columns: Vec<String> = pk["columns"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|c| c.as_str().map(quote_id)).collect())
                    .unwrap_or_default();
                let rows = pk["values"].as_array().map(|a| {
                    a.iter()
                        .map(|row| {
                            let vals: Vec<String> = row
                                .as_array()
                                .map(|r| r.iter().map(|v| escape_value(v, dialect)).collect())
                                .unwrap_or_default();
                            format!("({})", vals.join(", "))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                });
                if !columns.is_empty()
                    && let Some(rows) = rows
                    && !rows.is_empty()
                {
                    statements.push(format!(
                        "DELETE FROM {tref} WHERE ({}) IN ({rows});",
                        columns.join(", ")
                    ));
                }
            }
            _ => {}
        }
        warnings.push(
            "insert-hint restore deletes the rows the INSERT created — verify before running"
                .into(),
        );
        is_insert_hint_delete = true;
        return Ok(RestorePlan {
            backup_id: id,
            statements,
            row_count: backup.row_count,
            warnings,
            is_insert_hint_delete,
        });
    }

    // Row backup: per-row upserts with dialect-specific conflict arms.
    if let Some(rows_json) = &backup.rows_json {
        let rows: Vec<serde_json::Value> = serde_json::from_str(rows_json)
            .map_err(|e| RestoreError::Plan(format!("bad rows payload: {e}")))?;
        if let Some(first) = rows.first().and_then(|r| r.as_object()) {
            let cols: Vec<String> = first.keys().cloned().collect();
            let col_list = cols
                .iter()
                .map(|c| quote_id(c))
                .collect::<Vec<_>>()
                .join(", ");
            let update_clause = cols
                .iter()
                .map(|c| match dialect {
                    RestoreDialect::SQLite => format!("{} = excluded.{}", quote_id(c), quote_id(c)),
                    RestoreDialect::MySql => format!("{} = VALUES({})", quote_id(c), quote_id(c)),
                })
                .collect::<Vec<_>>()
                .join(", ");
            let tref = table_ref_sql(backup.database.as_deref(), &backup.table_name);
            for row in &rows {
                let Some(obj) = row.as_object() else { continue };
                let values = cols
                    .iter()
                    .map(|c| escape_value(obj.get(c).unwrap_or(&serde_json::Value::Null), dialect))
                    .collect::<Vec<_>>()
                    .join(", ");
                statements.push(match dialect {
                    RestoreDialect::SQLite => format!(
                        "INSERT INTO {tref} ({col_list}) VALUES ({values}) ON CONFLICT DO UPDATE SET {update_clause};"
                    ),
                    RestoreDialect::MySql => format!(
                        "INSERT INTO {tref} ({col_list}) VALUES ({values}) ON DUPLICATE KEY UPDATE {update_clause};"
                    ),
                });
            }
        }
    }

    Ok(RestorePlan {
        backup_id: id,
        statements,
        row_count: backup.row_count,
        warnings,
        is_insert_hint_delete,
    })
}

#[derive(Debug)]
pub struct RestoreOutcome {
    pub statements_run: usize,
    pub affected: u64,
}

/// Execute a plan against an open SQLite handle inside the caller's
/// transaction.
pub fn execute_restore_sqlite(
    db: &rusqlite::Connection,
    plan: &RestorePlan,
) -> Result<RestoreOutcome, RestoreError> {
    let mut affected: u64 = 0;
    for stmt_raw in &plan.statements {
        let stmt_text = stmt_raw.trim_end_matches(|c: char| c == ';' || c.is_whitespace());
        let mut stmt = db
            .prepare(stmt_text)
            .map_err(|e| RestoreError::Execution(e.to_string()))?;
        if stmt.column_count() > 0 {
            // Reader statements (rare in plans) are drained.
            let rows = stmt
                .query(())
                .map_err(|e| RestoreError::Execution(e.to_string()))?;
            drop(rows);
        } else {
            stmt.execute(())
                .map_err(|e| RestoreError::Execution(e.to_string()))?;
            affected += db.changes();
        }
    }
    Ok(RestoreOutcome {
        statements_run: plan.statements.len(),
        affected,
    })
}
