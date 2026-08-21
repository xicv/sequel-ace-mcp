//! Audit database: schema-compatible with the legacy SQLite file
//! (`audit_log`, `backup`, `meta`), opened with WAL and 0700/0600 modes.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::app::paths;

const SCHEMA_V1_SQL: &str = "
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT    NOT NULL,
  request_id    TEXT    NOT NULL,
  connection    TEXT    NOT NULL,
  databases     TEXT    NOT NULL,
  category      TEXT    NOT NULL,
  ast_type      TEXT,
  sql_raw       TEXT    NOT NULL,
  sql_redacted  TEXT    NOT NULL,
  decision      TEXT    NOT NULL,
  confirmed     INTEGER NOT NULL DEFAULT 0,
  outcome       TEXT    NOT NULL,
  affected_rows INTEGER,
  duration_ms   INTEGER,
  error_msg     TEXT,
  backup_id     INTEGER REFERENCES backup(id) ON DELETE SET NULL,
  prev_hash     BLOB,
  row_hash      BLOB
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_connection ON audit_log(connection, ts);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_log(outcome, ts);

CREATE TABLE IF NOT EXISTS backup (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT    NOT NULL,
  connection    TEXT    NOT NULL,
  database      TEXT,
  table_name    TEXT    NOT NULL,
  backup_kind   TEXT    NOT NULL,
  rows_json     TEXT,
  schema_sql    TEXT,
  primary_key   TEXT,
  row_count     INTEGER NOT NULL DEFAULT 0,
  truncated     INTEGER NOT NULL DEFAULT 0,
  size_bytes    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_backup_ts ON backup(ts);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
";

/// v2 additions: approval linkage + chain epoch bookkeeping.
const SCHEMA_V2_SQL: &str = "
ALTER TABLE audit_log ADD COLUMN approval_scope TEXT;
ALTER TABLE audit_log ADD COLUMN approval_digest BLOB;
ALTER TABLE audit_log ADD COLUMN policy_revision INTEGER;
INSERT INTO meta (key, value) VALUES ('schema_version', '2')
  ON CONFLICT(key) DO UPDATE SET value = '2';
INSERT OR IGNORE INTO meta (key, value) VALUES ('chain_epoch', '0');
";

fn apply_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "mmap_size", 268_435_456i64)?;
    conn.pragma_update(None, "cache_size", -20_000i64)?;
    conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
    conn.pragma_update(None, "journal_size_limit", 67_108_864i64)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

fn migrate_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA_V1_SQL)?;
    let version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "1".to_string());
    if version == "1" {
        let have_scope = conn
            .prepare("SELECT approval_scope FROM audit_log LIMIT 0")
            .is_ok();
        if !have_scope {
            conn.execute_batch(SCHEMA_V2_SQL)?;
        }
    }
    Ok(())
}

/// A process-wide cached handle (default path only). Connections are
/// serialized behind a mutex: audit writes are short and rare.
pub struct AuditDb {
    conn: Arc<Mutex<Connection>>,
    #[allow(dead_code)]
    path: PathBuf,
}

static CACHED: OnceLock<Arc<AuditDb>> = OnceLock::new();

fn set_file_mode_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn open_at(path: &Path, ensure_parent_with_mode: bool) -> rusqlite::Result<Connection> {
    if ensure_parent_with_mode && let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    migrate_schema(&conn)?;
    set_file_mode_0600(path);
    Ok(conn)
}

impl AuditDb {
    /// Open (or return the cached) default audit database.
    pub fn shared() -> Arc<AuditDb> {
        CACHED
            .get_or_init(|| {
                let path = paths::audit_db_path();
                let conn = open_at(&path, true).expect("audit db opens");
                Arc::new(AuditDb {
                    conn: Arc::new(Mutex::new(conn)),
                    path,
                })
            })
            .clone()
    }

    /// Open an isolated database (tests / overrides).
    pub fn at_path(path: &Path) -> rusqlite::Result<AuditDb> {
        let conn = open_at(path, true)?;
        Ok(AuditDb {
            conn: Arc::new(Mutex::new(conn)),
            path: path.to_path_buf(),
        })
    }

    /// Run a closure with the connection under the write lock.
    pub fn with<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let guard = self.conn.lock().unwrap();
        f(&guard)
    }

    /// Run a closure inside an IMMEDIATE transaction.
    pub fn with_tx<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let guard = self.conn.lock().unwrap();
        guard.execute_batch("BEGIN IMMEDIATE")?;
        match f(&guard) {
            Ok(v) => {
                guard.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn checkpoint(&self) {
        let _ = self.with(|c| c.pragma_update(None, "wal_checkpoint", "TRUNCATE"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_created_and_versioned() {
        let dir = tempfile::tempdir().unwrap();
        let db = AuditDb::at_path(&dir.path().join("audit.sqlite")).unwrap();
        let v: String = db
            .with(|c| {
                c.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(v, "2");
        // Legacy tables exist.
        let n: i64 = db
            .with(|c| c.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(n, 0);
        let _ = dir;
    }

    #[test]
    fn reopen_upgrades_v1_to_v2() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("audit.sqlite");
        {
            let raw = Connection::open(&file).unwrap();
            raw.execute_batch(SCHEMA_V1_SQL).unwrap();
            raw.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '1')",
                [],
            )
            .unwrap();
        }
        let db = AuditDb::at_path(&file).unwrap();
        let v: String = db
            .with(|c| {
                c.query_row(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(v, "2");
    }
}
