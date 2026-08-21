//! MAX_EXECUTION_TIME hint injection (legacy `sql/hints.ts` port).

/// Inject `/*+ MAX_EXECUTION_TIME(ms) */` after the leading `select`
/// keyword when not already present. Case-insensitive, first-statement only.
pub fn inject_max_execution_time(sql: &str, ms: u32) -> String {
    let trimmed = sql.trim_start();
    let leading = sql.len() - trimmed.len();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("select") {
        return sql.to_string();
    }
    if lower.contains("/*+ max_execution_time") {
        return sql.to_string();
    }
    let after = leading + "select".len();
    format!(
        "{}{} /*+ MAX_EXECUTION_TIME({ms}) */{}",
        &sql[..leading],
        &sql[leading..after],
        &sql[after..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_after_select() {
        assert_eq!(
            inject_max_execution_time("SELECT * FROM users", 5000),
            "SELECT /*+ MAX_EXECUTION_TIME(5000) */ * FROM users"
        );
    }

    #[test]
    fn lowercase_and_leading_whitespace() {
        assert_eq!(
            inject_max_execution_time("  select 1", 50),
            "  select /*+ MAX_EXECUTION_TIME(50) */ 1"
        );
    }

    /// Differential check against the generated legacy fixtures.
    #[test]
    fn matches_legacy_fixtures() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy/hints.json"
        );
        let data = std::fs::read_to_string(path).expect("fixtures present");
        let cases: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let sql = case["sql"].as_str().unwrap();
            let ms = case["ms"].as_u64().unwrap() as u32;
            let expected = case["result"].as_str().unwrap();
            assert_eq!(inject_max_execution_time(sql, ms), expected, "sql: {sql:?}");
        }
    }

    #[test]
    fn existing_hint_left_alone() {
        let sql = "SELECT /*+ MAX_EXECUTION_TIME(1000) */ * FROM users";
        assert_eq!(inject_max_execution_time(sql, 2000), sql);
    }

    #[test]
    fn non_select_untouched() {
        assert_eq!(
            inject_max_execution_time("UPDATE users SET x = 1", 5),
            "UPDATE users SET x = 1"
        );
    }
}
