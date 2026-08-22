//! Audit retention and cleanup (legacy `audit/retention.ts` port):
//! prune audit entries per category cutoff, backups by age, hard size
//! caps trigger an additional 20% trim, then VACUUM. Auto-cleanup on
//! boot runs only when the configured interval has elapsed since the
//! last run (recorded in the audit DB meta table).

use crate::audit::AuditDb;
use crate::policy::model::{RetentionConfig, SqlCategory};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct CleanupResult {
    pub audit_deleted: u64,
    pub audit_deleted_by_category: BTreeMap<&'static str, u64>,
    pub backup_deleted: u64,
    pub bytes_reclaimed: u64,
    pub ran_at: String,
}

const CATEGORIES: [SqlCategory; 5] = [
    SqlCategory::Read,
    SqlCategory::Write,
    SqlCategory::Ddl,
    SqlCategory::Admin,
    SqlCategory::TxCtrl,
];

fn day_cutoff(days: u32) -> String {
    let now = time::OffsetDateTime::now_utc();
    let cutoff = now - time::Duration::seconds(i64::from(days) * 24 * 60 * 60);
    cutoff
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn page_bytes(c: &rusqlite::Connection) -> u64 {
    let count: i64 = c
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap_or(0);
    let size: i64 = c
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap_or(0);
    (count.max(0) as u64) * (size.max(0) as u64)
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Prune per the retention config. `dry_run` counts what WOULD be
/// deleted without touching anything.
pub fn cleanup_audit(
    audit: &Arc<AuditDb>,
    config: &RetentionConfig,
    dry_run: bool,
) -> CleanupResult {
    let ran_at = iso_now();
    let mut by_category: BTreeMap<&'static str, u64> =
        CATEGORIES.iter().map(|c| (c.as_str(), 0)).collect();

    let dry_shape = if dry_run {
        let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
        audit
            .with(|c| {
                for cat in &CATEGORIES {
                    let cutoff = day_cutoff(config.retention_days_by_category.get(*cat));
                    let n: i64 = c.query_row(
                        "SELECT COUNT(*) FROM audit_log WHERE category = ?1 AND ts < ?2",
                        [cat.as_str(), cutoff.as_str()],
                        |r| r.get(0),
                    )?;
                    counts.insert(cat.as_str(), n.max(0) as u64);
                }
                let backup_cutoff = day_cutoff(config.backup_days);
                let b: i64 = c.query_row(
                    "SELECT COUNT(*) FROM backup WHERE ts < ?1",
                    [&backup_cutoff],
                    |r| r.get(0),
                )?;
                Ok::<_, rusqlite::Error>(b.max(0) as u64)
            })
            .ok()
            .map(|b| {
                let total: u64 = counts.values().sum();
                (counts, total, b)
            })
    } else {
        None
    };

    let result = audit.with_tx(|c| {
        let before = page_bytes(c);

        if dry_run {
            let Some((counts, total, b)) = dry_shape else {
                unreachable!("dry_run set means dry_shape is Some");
            };
            return Ok::<_, rusqlite::Error>(CleanupResult {
                audit_deleted: total,
                audit_deleted_by_category: counts,
                backup_deleted: b,
                bytes_reclaimed: 0,
                ran_at: ran_at.clone(),
            });
        }

        let mut audit_deleted: u64 = 0;
        let tx = c;
        for cat in &CATEGORIES {
            let cutoff = day_cutoff(config.retention_days_by_category.get(*cat));
            let n = tx.execute(
                "DELETE FROM audit_log WHERE category = ?1 AND ts < ?2",
                [cat.as_str(), cutoff.as_str()],
            )? as u64;
            by_category.insert(cat.as_str(), n);
            audit_deleted += n;
        }
        let backup_cutoff = day_cutoff(config.backup_days);
        let mut backup_deleted =
            tx.execute("DELETE FROM backup WHERE ts < ?1", [&backup_cutoff])? as u64;

        // Hard size caps: trim the oldest 20% of both tables.
        let audit_max = u64::from(config.audit_max_mb) * 1024 * 1024;
        let backup_max = u64::from(config.backup_max_mb) * 1024 * 1024;
        let cur = page_bytes(tx);
        if cur > audit_max + backup_max {
            backup_deleted += tx.execute(
                "DELETE FROM backup WHERE id IN (
                   SELECT id FROM backup ORDER BY id ASC LIMIT
                     (SELECT COUNT(*) FROM backup) / 5
                 )",
                [],
            )? as u64;
            audit_deleted += tx.execute(
                "DELETE FROM audit_log WHERE id IN (
                   SELECT id FROM audit_log ORDER BY id ASC LIMIT
                     (SELECT COUNT(*) FROM audit_log) / 5
                 )",
                [],
            )? as u64;
        }

        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('last_cleanup_at', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&ran_at],
        )?;

        let after = page_bytes(c);
        Ok(CleanupResult {
            audit_deleted,
            audit_deleted_by_category: by_category.clone(),
            backup_deleted,
            bytes_reclaimed: before.saturating_sub(after),
            ran_at: ran_at.clone(),
        })
    });

    // VACUUM outside the counted transaction (dry_run never reaches here).
    if !dry_run {
        let _ = audit.with(|c| c.execute("VACUUM", []));
    }

    result.unwrap_or(CleanupResult {
        audit_deleted: 0,
        audit_deleted_by_category: by_category.clone(),
        backup_deleted: 0,
        bytes_reclaimed: 0,
        ran_at,
    })
}

/// Run cleanup on boot iff the configured interval elapsed since the
/// last run. `None` = not due (or disabled).
pub fn maybe_auto_cleanup(audit: &Arc<AuditDb>, config: &RetentionConfig) -> Option<CleanupResult> {
    if config.auto_cleanup_hours == 0 {
        return None;
    }
    let last: Option<String> = audit
        .with(|c| {
            c.query_row(
                "SELECT value FROM meta WHERE key = 'last_cleanup_at'",
                [],
                |r| r.get(0),
            )
        })
        .ok();
    if let Some(last) = last
        && let Ok(ts) =
            time::OffsetDateTime::parse(&last, &time::format_description::well_known::Rfc3339)
    {
        let age = time::OffsetDateTime::now_utc() - ts;
        if age.whole_hours() < i64::from(config.auto_cleanup_hours) {
            return None;
        }
    }
    Some(cleanup_audit(audit, config, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn tmp_audit() -> (tempfile::TempDir, Arc<AuditDb>) {
        let dir = tempfile::TempDir::new().unwrap();
        let audit = Arc::new(AuditDb::at_path(&dir.path().join("a.sqlite")).unwrap());
        (dir, audit)
    }

    #[test]
    fn dry_run_counts_and_cleanup_deletes_by_category() {
        let (_dir, audit) = tmp_audit();
        let old = "2020-01-01T00:00:00Z";
        for cat in &CATEGORIES {
            insert_raw(&audit, cat.as_str(), old);
            insert_raw(&audit, cat.as_str(), &iso_now());
        }

        let cfg = RetentionConfig::default();
        let dry = cleanup_audit(&audit, &cfg, true);
        assert_eq!(dry.audit_deleted, 5, "one old row per category");
        assert_eq!(dry.audit_deleted_by_category["read"], 1);
        // Dry run must not modify anything.
        let count: i64 = audit
            .with(|c| c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(count, 10);

        let run = cleanup_audit(&audit, &cfg, false);
        assert_eq!(run.audit_deleted, 5);
        let count: i64 = audit
            .with(|c| c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(count, 5, "recent rows survive");
        // meta recorded
        let last: String = audit
            .with(|c| {
                c.query_row(
                    "SELECT value FROM meta WHERE key = 'last_cleanup_at'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(last.starts_with("20"));
    }

    fn insert_raw(audit: &Arc<AuditDb>, category: &str, ts: &str) {
        audit
            .with(|c| {
                c.execute(
                    "INSERT INTO audit_log
                       (ts, request_id, connection, databases, category, ast_type,
                        sql_raw, sql_redacted, decision, confirmed, outcome)
                     VALUES (?1, ?2, 'c', '[]', ?3, NULL, 'SELECT 1', 'SELECT 1',
                             'allow', 0, 'approved')",
                    params![ts, uuid::Uuid::new_v4().to_string(), category],
                )
            })
            .unwrap();
    }

    #[test]
    fn auto_cleanup_respects_interval() {
        let (_dir, audit) = tmp_audit();
        let cfg = RetentionConfig {
            auto_cleanup_hours: 24,
            ..RetentionConfig::default()
        };
        // No meta yet -> runs.
        assert!(maybe_auto_cleanup(&audit, &cfg).is_some());
        // Just ran -> not due.
        assert!(maybe_auto_cleanup(&audit, &cfg).is_none());
        // Disabled -> never.
        let off = RetentionConfig {
            auto_cleanup_hours: 0,
            ..RetentionConfig::default()
        };
        assert!(maybe_auto_cleanup(&audit, &off).is_none());
    }
}
