//! Read-only access to Sequel Ace's queryHistory.db (legacy
//! `importer/sequelAceHistory.ts` port). The GUI dedupes by query text
//! and keeps the latest createdTime per distinct query.

use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct SequelAceHistoryEntry {
    pub id: i64,
    pub query: String,
    pub created_time: i64,
    pub created_at_iso: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SequelAceHistoryStat {
    pub exists: bool,
    pub path: PathBuf,
    pub entry_count: u64,
    pub size_bytes: u64,
}

fn open_read_only(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

fn iso_from_unix(seconds: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(t) => t
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
        Err(_) => "1970-01-01T00:00:00Z".into(),
    }
}

/// Test-mode gate: the Sequel Ace sandbox is REAL user data — in
/// SEQUEL_MCP_TEST_MODE reads must stay below the isolated root.
fn guard_test_mode(path: &Path) -> Result<(), String> {
    if crate::app::test_mode::is_active() {
        return crate::app::test_mode::check_sqlite_path(path)
            .map_err(|e| format!("sequel-ace history: {e}"));
    }
    Ok(())
}

pub fn stat_sequel_ace_history(path_override: Option<&Path>) -> SequelAceHistoryStat {
    let path = path_override
        .map(PathBuf::from)
        .unwrap_or_else(crate::app::paths::sequel_ace_query_history_db_path);
    let meta = match std::fs::metadata(&path) {
        Ok(m) if m.is_file() => m,
        _ => {
            return SequelAceHistoryStat {
                exists: false,
                path,
                entry_count: 0,
                size_bytes: 0,
            };
        }
    };
    let size = meta.len();
    if guard_test_mode(&path).is_err() {
        return SequelAceHistoryStat {
            exists: false,
            path,
            entry_count: 0,
            size_bytes: 0,
        };
    }
    let count = open_read_only(&path)
        .and_then(|db| {
            db.query_row("SELECT COUNT(*) FROM QueryHistory", [], |r| {
                r.get::<_, i64>(0)
            })
            .ok()
            .map(|n| n.max(0) as u64)
        })
        .unwrap_or(0);
    SequelAceHistoryStat {
        exists: true,
        path,
        entry_count: count,
        size_bytes: size,
    }
}

pub fn read_sequel_ace_history(
    filters: &SequelAceHistoryFilters<'_>,
    path_override: Option<&Path>,
) -> Vec<SequelAceHistoryEntry> {
    let path = path_override
        .map(PathBuf::from)
        .unwrap_or_else(crate::app::paths::sequel_ace_query_history_db_path);
    if guard_test_mode(&path).is_err() {
        return Vec::new();
    }
    let Some(db) = open_read_only(&path) else {
        return Vec::new();
    };
    let mut conds: Vec<String> = Vec::new();
    let mut like: Option<String> = None;
    let mut since_secs: Option<i64> = None;
    if let Some(since_iso) = filters.since_iso
        && let Ok(t) =
            time::OffsetDateTime::parse(since_iso, &time::format_description::well_known::Rfc3339)
    {
        since_secs = Some(t.unix_timestamp());
        conds.push("createdTime >= ?".into());
    }
    if let Some(search) = filters.search {
        conds.push("query LIKE ?".into());
        like = Some(format!("%{search}%"));
    }
    let where_clause = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };
    let limit = filters.limit.unwrap_or(200).min(5000);
    let sql = format!(
        "SELECT id, query, createdTime FROM QueryHistory {where_clause}
          ORDER BY createdTime DESC LIMIT ?"
    );
    let mut stmt = match db.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    // Bind positionally: since?, like?, limit.
    let bound: Vec<String> = [
        since_secs.map(|v| v.to_string()),
        like.clone(),
        Some(limit.to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let rows = stmt.query_map(rusqlite::params_from_iter(bound), |r| {
        Ok(SequelAceHistoryEntry {
            id: r.get(0)?,
            query: r.get(1)?,
            created_time: r.get(2)?,
            created_at_iso: String::new(),
        })
    });
    match rows {
        Ok(iter) => iter
            .filter_map(Result::ok)
            .map(|mut e| {
                e.created_at_iso = iso_from_unix(e.created_time);
                e
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Default)]
pub struct SequelAceHistoryFilters<'a> {
    pub since_iso: Option<&'a str>,
    pub search: Option<&'a str>,
    pub limit: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_history_db(path: &Path) {
        let db = Connection::open(path).unwrap();
        db.execute_batch(
            "CREATE TABLE QueryHistory (id INTEGER PRIMARY KEY, query TEXT, createdTime INTEGER);
             INSERT INTO QueryHistory (query, createdTime) VALUES
               ('SELECT 1', 1700000000),
               ('SELECT 2', 1700003600),
               ('UPDATE t SET x = 1', 1700007200);",
        )
        .unwrap();
    }

    #[test]
    fn reads_filters_and_stats() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("queryHistory.db");
        build_history_db(&db_path);

        let stat = stat_sequel_ace_history(Some(&db_path));
        assert!(stat.exists);
        assert_eq!(stat.entry_count, 3);
        assert!(stat.size_bytes > 0);

        let all = read_sequel_ace_history(
            &SequelAceHistoryFilters {
                limit: Some(10),
                ..Default::default()
            },
            Some(&db_path),
        );
        assert_eq!(all.len(), 3);
        // DESC order
        assert_eq!(all[0].query, "UPDATE t SET x = 1");
        assert!(all[0].created_at_iso.starts_with("2023-11-1"));

        let searched = read_sequel_ace_history(
            &SequelAceHistoryFilters {
                search: Some("SELECT"),
                limit: Some(10),
                ..Default::default()
            },
            Some(&db_path),
        );
        assert_eq!(searched.len(), 2);

        let since = read_sequel_ace_history(
            &SequelAceHistoryFilters {
                since_iso: Some("2023-11-14T23:30:00Z"),
                limit: Some(10),
                ..Default::default()
            },
            Some(&db_path),
        );
        assert_eq!(since.len(), 1, "only the newest passes the cutoff");
    }

    #[test]
    fn missing_db_is_empty_stat() {
        let stat = stat_sequel_ace_history(Some(Path::new("/nonexistent/qh.db")));
        assert!(!stat.exists);
        assert_eq!(stat.entry_count, 0);
    }
}
