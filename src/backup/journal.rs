//! Operation journal (D3): durable, crash-recoverable records linking
//! backups, mutations, and audit across the local/remote database
//! boundary. Because the audit DB and the target server cannot share a
//! distributed transaction, every gated mutation writes journal
//! transitions; a crash between remote commit and local finalization
//! leaves a visibly ambiguous record rather than silent success/failure.

use crate::audit::AuditDb;
use rusqlite::params;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalState {
    Planned,
    BackupCapturing,
    BackupDurable,
    MutationExecuting,
    MutationCommitted,
    AuditFinalized,
    Failed,
    Uncertain,
}

impl JournalState {
    fn as_str(&self) -> &'static str {
        match self {
            JournalState::Planned => "planned",
            JournalState::BackupCapturing => "backup_capturing",
            JournalState::BackupDurable => "backup_durable",
            JournalState::MutationExecuting => "mutation_executing",
            JournalState::MutationCommitted => "mutation_committed",
            JournalState::AuditFinalized => "audit_finalized",
            JournalState::Failed => "failed",
            JournalState::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal write failed: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("transition {from} -> {to} is not allowed")]
    IllegalTransition { from: String, to: String },
}

/// Allowed forward transitions; `failed`/`uncertain` are terminal for
/// recovery purposes, `uncertain` additionally reachable from any
/// executing-or-later state (crash/timeout ambiguity).
const TRANSITIONS: &[(&str, &[&str])] = &[
    ("planned", &["backup_capturing", "failed"]),
    (
        "backup_capturing",
        &["backup_durable", "mutation_executing", "failed"],
    ),
    ("backup_durable", &["mutation_executing", "failed"]),
    (
        "mutation_executing",
        &["mutation_committed", "failed", "uncertain"],
    ),
    ("mutation_committed", &["audit_finalized", "uncertain"]),
    ("audit_finalized", &[]),
    ("failed", &[]),
    ("uncertain", &[]),
];

pub struct Journal<'a> {
    db: &'a Arc<AuditDb>,
    id: i64,
}

pub fn ensure_table(db: &Arc<AuditDb>) -> rusqlite::Result<()> {
    db.with(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS operation_journal (
               id           INTEGER PRIMARY KEY AUTOINCREMENT,
               ts           TEXT    NOT NULL,
               request_id   TEXT    NOT NULL,
               connection   TEXT    NOT NULL,
               databases    TEXT    NOT NULL,
               category     TEXT    NOT NULL,
               state        TEXT    NOT NULL,
               detail       TEXT,
               backup_id    INTEGER,
               audit_id     INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_journal_state ON operation_journal(state, ts);",
        )
    })
}

impl<'a> Journal<'a> {
    pub fn create(
        db: &'a Arc<AuditDb>,
        request_id: &str,
        connection: &str,
        databases: &[String],
        category: &str,
    ) -> Result<Journal<'a>, JournalError> {
        let ts = now_iso();
        let databases = serde_json::to_string(databases).unwrap_or_else(|_| "[]".into());
        let id = db.with_tx(|c| {
            c.execute(
                "INSERT INTO operation_journal
                   (ts, request_id, connection, databases, category, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'planned')",
                params![ts, request_id, connection, databases, category],
            )?;
            Ok(c.last_insert_rowid())
        })?;
        Ok(Journal { db, id })
    }

    pub fn id(&self) -> i64 {
        self.id
    }

    /// Re-open an existing journal row by id (for finalization by the
    /// caller that performed the audit write).
    pub fn from_id(db: &'a Arc<AuditDb>, id: i64) -> Journal<'a> {
        Journal { db, id }
    }

    pub fn transition(&self, to: JournalState, detail: Option<&str>) -> Result<(), JournalError> {
        self.db.with_tx(|c| {
            let from: String = c.query_row(
                "SELECT state FROM operation_journal WHERE id = ?1",
                params![self.id],
                |r| r.get(0),
            )?;
            let allowed = TRANSITIONS
                .iter()
                .find(|(f, _)| *f == from.as_str())
                .map(|(_, ts)| ts.contains(&to.as_str()))
                .unwrap_or(false);
            if !allowed {
                return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                    std::io::Error::other(format!("illegal transition {from} -> {}", to.as_str())),
                )));
            }
            c.execute(
                "UPDATE operation_journal
                    SET state = ?2, detail = COALESCE(?3, detail), ts = ?4
                  WHERE id = ?1",
                params![self.id, to.as_str(), detail, now_iso()],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn link_backup(&self, backup_id: i64) -> rusqlite::Result<()> {
        self.db.with(|c| {
            c.execute(
                "UPDATE operation_journal SET backup_id = ?2 WHERE id = ?1",
                params![self.id, backup_id],
            )
        })?;
        Ok(())
    }

    pub fn link_audit(&self, audit_id: i64) -> rusqlite::Result<()> {
        self.db.with(|c| {
            c.execute(
                "UPDATE operation_journal SET audit_id = ?2 WHERE id = ?1",
                params![self.id, audit_id],
            )
        })?;
        Ok(())
    }

    /// Rows left in a non-terminal or ambiguous state — the crash-recovery
    /// surface. `mutation_committed` without `audit_finalized` is the
    /// visibly-ambiguous case: the remote commit may have landed.
    pub fn recoverable(db: &Arc<AuditDb>) -> rusqlite::Result<Vec<(i64, String, String)>> {
        db.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, state, COALESCE(request_id, '') FROM operation_journal
                  WHERE state NOT IN ('audit_finalized', 'failed', 'uncertain')
                     OR (state = 'mutation_committed' AND audit_id IS NULL)",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })
    }
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Arc<AuditDb>) {
        let dir = tempfile::TempDir::new().unwrap();
        let d = Arc::new(AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
        ensure_table(&d).unwrap();
        (dir, d)
    }

    #[test]
    fn happy_path_transitions() {
        let (_dir, db) = db();
        let j = Journal::create(&db, "req-1", "c1", &["app".into()], "write").unwrap();
        j.transition(JournalState::BackupCapturing, None).unwrap();
        j.transition(JournalState::BackupDurable, None).unwrap();
        j.transition(JournalState::MutationExecuting, None).unwrap();
        j.transition(JournalState::MutationCommitted, None).unwrap();
        j.transition(JournalState::AuditFinalized, None).unwrap();
        assert!(Journal::recoverable(&db).unwrap().is_empty());
    }

    #[test]
    fn illegal_transitions_rejected() {
        let (_dir, db) = db();
        let j = Journal::create(&db, "req-2", "c1", &[], "ddl").unwrap();
        assert!(j.transition(JournalState::MutationCommitted, None).is_err());
        j.transition(JournalState::BackupCapturing, None).unwrap();
        // backup_capturing -> mutation_executing is legal for backup-less
        // operations; the illegal jump is straight to committed.
        assert!(j.transition(JournalState::MutationCommitted, None).is_err());
    }

    #[test]
    fn crash_before_audit_finalization_is_recoverable() {
        let (_dir, db) = db();
        let j = Journal::create(&db, "req-3", "c1", &[], "write").unwrap();
        for s in [
            JournalState::BackupCapturing,
            JournalState::BackupDurable,
            JournalState::MutationExecuting,
            JournalState::MutationCommitted,
        ] {
            j.transition(s, None).unwrap();
        }
        // Crash here: committed remotely, audit not finalized.
        let r = Journal::recoverable(&db).unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].1, "mutation_committed");
    }

    #[test]
    fn uncertain_is_terminal_and_not_recoverable() {
        let (_dir, db) = db();
        let j = Journal::create(&db, "req-4", "c1", &[], "write").unwrap();
        j.transition(JournalState::BackupCapturing, None).unwrap();
        j.transition(JournalState::BackupDurable, None).unwrap();
        j.transition(JournalState::MutationExecuting, None).unwrap();
        j.transition(JournalState::Uncertain, Some("cancellation inconclusive"))
            .unwrap();
        assert!(Journal::recoverable(&db).unwrap().is_empty());
    }

    #[test]
    fn backup_failure_leads_to_failed_not_mutation() {
        let (_dir, db) = db();
        let j = Journal::create(&db, "req-5", "c1", &[], "write").unwrap();
        j.transition(JournalState::BackupCapturing, None).unwrap();
        j.transition(JournalState::Failed, Some("backup overflow"))
            .unwrap();
        assert!(Journal::recoverable(&db).unwrap().is_empty());
    }
}
