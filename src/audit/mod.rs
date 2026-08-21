//! Audit logging with redaction, hash chaining and epoch bookkeeping.

pub mod db;
pub mod redactor;

use crate::approval::outcomes::ApprovalOutcome;
use crate::policy::model::{PolicyAction, SqlCategory};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub use db::AuditDb;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub request_id: String,
    pub connection: String,
    pub databases: Vec<String>,
    pub category: SqlCategory,
    pub ast_type: Option<String>,
    pub sql: String,
    pub decision: PolicyAction,
    pub confirmed: bool,
    pub outcome: ApprovalOutcome,
    pub affected_rows: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub backup_id: Option<i64>,
    /// v2 linkage: approval scope + digest + policy revision.
    pub approval_scope: Option<String>,
    pub approval_digest: Option<[u8; 32]>,
    pub policy_revision: Option<u64>,
}

#[derive(Default)]
pub struct WriteOptions {
    pub redact_sql_in_log: bool,
    pub tamper_evident_chain: bool,
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn hash_row(prev: Option<&[u8]>, payload: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    if let Some(p) = prev {
        h.update(p);
    }
    h.update(payload.as_bytes());
    h.finalize().into()
}

/// Write one audit entry. When `tamper_evident_chain` is set, the row hash
/// chains from the previous row's hash inside the same IMMEDIATE
/// transaction, so concurrent writers cannot interleave.
pub fn write_audit_entry(
    db: &Arc<AuditDb>,
    entry: &AuditEntry,
    opts: &WriteOptions,
) -> rusqlite::Result<i64> {
    let ts = iso_now();
    // Redaction is dialect-agnostic (tokenizer-level); MySQL dialect
    // tokenization covers the shared syntax.
    let dialect = crate::policy::classifier::Dialect::MySql;
    let sql_redacted = redactor::redact_sql(&entry.sql, dialect);
    let sql_raw = if opts.redact_sql_in_log {
        sql_redacted.clone()
    } else {
        entry.sql.clone()
    };
    let databases = serde_json::to_string(&entry.databases).unwrap_or_else(|_| "[]".into());

    db.with_tx(|c| {
        let (prev_hash, row_hash): (Option<Vec<u8>>, Option<[u8; 32]>) = if opts.tamper_evident_chain {
            let prev: Option<Vec<u8>> = c
                .query_row(
                    "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(None);
            let canonical = serde_json::json!({
                "ts": ts,
                "requestId": entry.request_id,
                "connection": entry.connection,
                "databases": databases,
                "category": entry.category.as_str(),
                "astType": entry.ast_type,
                "sqlRedacted": sql_redacted,
                "decision": entry.decision.as_str(),
                "confirmed": entry.confirmed,
                "outcome": entry.outcome.as_str(),
                "affectedRows": entry.affected_rows,
                "durationMs": entry.duration_ms,
                "error": entry.error,
                "backupId": entry.backup_id,
            })
            .to_string();
            let rh = hash_row(prev.as_deref(), &canonical);
            (prev, Some(rh))
        } else {
            (None, None)
        };

        c.execute(
            "INSERT INTO audit_log
               (ts, request_id, connection, databases, category, ast_type,
                sql_raw, sql_redacted, decision, confirmed, outcome,
                affected_rows, duration_ms, error_msg, backup_id,
                prev_hash, row_hash, approval_scope, approval_digest, policy_revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                ts,
                entry.request_id,
                entry.connection,
                databases,
                entry.category.as_str(),
                entry.ast_type,
                sql_raw,
                sql_redacted,
                entry.decision.as_str(),
                entry.confirmed,
                entry.outcome.as_str(),
                entry.affected_rows,
                entry.duration_ms,
                entry.error,
                entry.backup_id,
                prev_hash,
                row_hash,
                entry.approval_scope,
                entry.approval_digest.map(|d| d.to_vec()),
                entry.policy_revision.map(|r| r as i64),
            ],
        )?;
        Ok(c.last_insert_rowid())
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub ts: String,
    pub request_id: String,
    pub connection: String,
    pub databases: Vec<String>,
    pub category: String,
    pub ast_type: Option<String>,
    pub sql_redacted: String,
    pub decision: String,
    pub confirmed: bool,
    pub outcome: String,
    pub affected_rows: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error_msg: Option<String>,
    pub backup_id: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditSearchFilters {
    pub since: Option<String>,
    pub until: Option<String>,
    pub connection: Option<String>,
    pub category: Option<SqlCategory>,
    pub outcome: Option<String>,
    pub limit: u32,
}

pub fn search_audit_log(
    db: &Arc<AuditDb>,
    f: &AuditSearchFilters,
) -> rusqlite::Result<Vec<AuditRow>> {
    let mut conds: Vec<String> = Vec::new();
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(s) = &f.since {
        params_vec.push(Box::new(s.clone()));
        conds.push(format!("ts >= ?{}", params_vec.len()));
    }
    if let Some(u) = &f.until {
        params_vec.push(Box::new(u.clone()));
        conds.push(format!("ts < ?{}", params_vec.len()));
    }
    if let Some(conn) = &f.connection {
        params_vec.push(Box::new(conn.clone()));
        conds.push(format!("connection = ?{}", params_vec.len()));
    }
    if let Some(cat) = &f.category {
        params_vec.push(Box::new(cat.as_str().to_string()));
        conds.push(format!("category = ?{}", params_vec.len()));
    }
    if let Some(out) = &f.outcome {
        params_vec.push(Box::new(out.clone()));
        conds.push(format!("outcome = ?{}", params_vec.len()));
    }
    let where_clause = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };
    let limit = f.limit.min(5000);
    params_vec.push(Box::new(limit));
    let limit_idx = params_vec.len();

    let sql = format!(
        "SELECT id, ts, request_id, connection, databases, category, ast_type,
                sql_redacted, decision, confirmed, outcome, affected_rows,
                duration_ms, error_msg, backup_id
           FROM audit_log {where_clause} ORDER BY id DESC LIMIT ?{limit_idx}"
    );
    let params_ref: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(|p| p.as_ref()).collect();
    db.with(|c| {
        let mut stmt = c.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| {
            let databases_raw: String = r.get(4)?;
            Ok(AuditRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                request_id: r.get(2)?,
                connection: r.get(3)?,
                databases: serde_json::from_str(&databases_raw).unwrap_or_default(),
                category: r.get(5)?,
                ast_type: r.get(6)?,
                sql_redacted: r.get(7)?,
                decision: r.get(8)?,
                confirmed: r.get::<_, i64>(9)? != 0,
                outcome: r.get(10)?,
                affected_rows: r.get(11)?,
                duration_ms: r.get(12)?,
                error_msg: r.get(13)?,
                backup_id: r.get(14)?,
            })
        })?;
        rows.collect()
    })
}

/// Verify the tamper-evident chain. Retention deletions create chain
/// epochs; verification restarts at each epoch boundary row.
#[derive(Debug)]
pub struct ChainVerification {
    pub ok: bool,
    pub rows_checked: u64,
    pub broken_at: Option<i64>,
    pub epoch: u64,
}

pub fn verify_chain(db: &Arc<AuditDb>) -> rusqlite::Result<ChainVerification> {
    #[derive(Debug)]
    struct ChainRow {
        id: i64,
        canonical: String,
        prev_hash: Option<Vec<u8>>,
        row_hash: Option<Vec<u8>>,
    }
    #[allow(clippy::type_complexity)]
    fn get_chain(r: &rusqlite::Row<'_>) -> rusqlite::Result<ChainRow> {
        let confirmed: i64 = r.get(9)?;
        let canonical = serde_json::json!({
            "ts": r.get::<_, String>(1)?,
            "requestId": r.get::<_, String>(2)?,
            "connection": r.get::<_, String>(3)?,
            "databases": r.get::<_, String>(4)?,
            "category": r.get::<_, String>(5)?,
            "astType": r.get::<_, Option<String>>(6)?,
            "sqlRedacted": r.get::<_, String>(7)?,
            "decision": r.get::<_, String>(8)?,
            "confirmed": confirmed != 0,
            "outcome": r.get::<_, String>(10)?,
            "affectedRows": r.get::<_, Option<i64>>(11)?,
            "durationMs": r.get::<_, Option<i64>>(12)?,
            "error": r.get::<_, Option<String>>(13)?,
            "backupId": r.get::<_, Option<i64>>(14)?,
        })
        .to_string();
        Ok(ChainRow {
            id: r.get(0)?,
            canonical,
            prev_hash: r.get(15)?,
            row_hash: r.get(16)?,
        })
    }

    let mut checked: u64 = 0;
    let mut epoch: u64 = 0;
    let mut prev: Option<Vec<u8>> = None;
    let mut broken_at: Option<i64> = None;

    db.with(|c| {
        let mut stmt = c.prepare("SELECT id, ts, request_id, connection, databases, category, ast_type, sql_redacted, decision, confirmed, outcome, affected_rows, duration_ms, error_msg, backup_id, prev_hash, row_hash FROM audit_log ORDER BY id ASC")?;
        let rows = stmt.query_map([], get_chain)?;
        for row in rows {
            let ChainRow { id, canonical, prev_hash, row_hash } = row?;
            let Some(rh) = row_hash else {
                // Chaining was off for this row: restart from here.
                if prev_hash.is_none() {
                    epoch += 1;
                    prev = None;
                }
                continue;
            };
            // Content integrity: the row hash must cover its stored prev and
            // the canonical payload. This detects any content tampering.
            let expected = hash_row(prev_hash.as_deref(), &canonical);
            if expected != rh.as_slice() {
                broken_at = Some(id);
                return Ok(());
            }
            // Chain linkage: when a predecessor is known in this scan, the
            // stored prev must be that predecessor's hash. A dangling prev
            // at a chain start is an epoch boundary (retention deleted the
            // predecessor), recorded rather than reported as tampering.
            match (&prev, &prev_hash) {
                (Some(last), Some(stored)) if last != stored => {
                    broken_at = Some(id);
                    return Ok(());
                }
                (None, Some(_)) => {
                    epoch += 1;
                }
                _ => {}
            }
            prev = Some(rh);
            checked += 1;
        }
        Ok(())
    })?;

    Ok(ChainVerification {
        ok: broken_at.is_none(),
        rows_checked: checked,
        broken_at,
        epoch,
    })
}

/// Record a chain epoch after retention deletes chained rows, so
/// verification stays meaningful instead of silently seeing a broken link.
pub fn write_chain_epoch(db: &Arc<AuditDb>, deleted: u64) -> rusqlite::Result<()> {
    db.with_tx(|c| {
        c.execute(
            "INSERT INTO meta (key, value) VALUES ('chain_epoch', '0')
             ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + ?1 AS TEXT)",
            params![deleted as i64],
        )?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Arc<AuditDb>) {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
        (dir, d)
    }

    fn entry(sql: &str, outcome: ApprovalOutcome) -> AuditEntry {
        AuditEntry {
            request_id: uuid::Uuid::new_v4().to_string(),
            connection: "c1".into(),
            databases: vec!["app".into()],
            category: SqlCategory::Write,
            ast_type: Some("update".into()),
            sql: sql.into(),
            decision: PolicyAction::Confirm,
            confirmed: false,
            outcome,
            affected_rows: None,
            duration_ms: None,
            error: None,
            backup_id: None,
            approval_scope: None,
            approval_digest: None,
            policy_revision: None,
        }
    }

    #[test]
    fn writes_and_reads_back_redacted() {
        let (_dir, db) = db();
        let id = write_audit_entry(
            &db,
            &entry(
                "UPDATE users SET name = 'secret' WHERE id = 1",
                ApprovalOutcome::Approved,
            ),
            &WriteOptions::default(),
        )
        .unwrap();
        assert!(id > 0);
        let rows = search_audit_log(
            &db,
            &AuditSearchFilters {
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert!(!rows[0].sql_redacted.contains("secret"));
        assert_eq!(rows[0].outcome, "approved");
    }

    #[test]
    fn raw_sql_hidden_when_redact_sql_in_log() {
        let (_dir, db) = db();
        write_audit_entry(
            &db,
            &entry(
                "UPDATE users SET name = 'secret'",
                ApprovalOutcome::Approved,
            ),
            &WriteOptions {
                redact_sql_in_log: true,
                ..Default::default()
            },
        )
        .unwrap();
        let raw: String = db
            .with(|c| c.query_row("SELECT sql_raw FROM audit_log LIMIT 1", [], |r| r.get(0)))
            .unwrap();
        assert!(
            !raw.contains("secret"),
            "raw must be redacted when configured"
        );
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let (_dir, db) = db();
        for i in 0..5 {
            write_audit_entry(
                &db,
                &entry(&format!("UPDATE t SET n = {i}"), ApprovalOutcome::Approved),
                &WriteOptions {
                    tamper_evident_chain: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let v = verify_chain(&db).unwrap();
        assert!(v.ok);
        assert_eq!(v.rows_checked, 5);

        // Tamper directly.
        db.with(|c| {
            c.execute(
                "UPDATE audit_log SET sql_redacted = 'tampered' WHERE id = 3",
                [],
            )
        })
        .unwrap();
        let v2 = verify_chain(&db).unwrap();
        assert!(!v2.ok);
        assert_eq!(v2.broken_at, Some(3));
    }

    #[test]
    fn epoch_rows_restart_chain() {
        let (_dir, db) = db();
        write_audit_entry(
            &db,
            &entry("UPDATE t SET n = 1", ApprovalOutcome::Approved),
            &WriteOptions {
                tamper_evident_chain: true,
                ..Default::default()
            },
        )
        .unwrap();
        // Simulate retention deletion: rows 2.. with chain on but no
        // predecessor.
        write_audit_entry(
            &db,
            &entry("UPDATE t SET n = 2", ApprovalOutcome::Approved),
            &WriteOptions {
                tamper_evident_chain: true,
                ..Default::default()
            },
        )
        .unwrap();
        db.with(|c| c.execute("DELETE FROM audit_log WHERE id = 1", []))
            .unwrap();
        write_chain_epoch(&db, 1).unwrap();
        let v = verify_chain(&db).unwrap();
        assert!(v.ok, "epoch boundary must not read as tampering: {v:?}");
        assert!(v.epoch >= 1);
    }
}
