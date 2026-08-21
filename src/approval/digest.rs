//! Canonical operation digests. A one-time approval is bound to the digest
//! of everything material about the operation; changing any field
//! invalidates the approval.

use crate::policy::model::SqlCategory;
use sha2::{Digest, Sha256};

/// Fields folded into the operation digest.
#[derive(Debug, Clone)]
pub struct OperationDigestInput<'a> {
    pub connection: &'a str,
    pub driver: &'a str,
    pub database: Option<&'a str>,
    pub read_tables: &'a [crate::policy::classifier::TableRef],
    pub mutated_tables: &'a [crate::policy::classifier::TableRef],
    pub category: SqlCategory,
    pub canonical_sql: &'a str,
    /// Hashes of bound parameters, never raw values. The MCP surface has no
    /// separate parameters today; kept for the executor's internal binds.
    pub parameter_hashes: &'a [[u8; 32]],
    pub backup_plan_identity: Option<&'a str>,
    pub policy_revision: u64,
    pub metadata_revision: u64,
    pub nonce: [u8; 32],
}

fn sorted_tables(tables: &[crate::policy::classifier::TableRef]) -> Vec<String> {
    let mut out: Vec<String> = tables
        .iter()
        .map(|t| format!("{}.{}", t.database.as_deref().unwrap_or("\u{0}"), t.table))
        .collect();
    out.sort();
    out
}

/// Compute the canonical digest over every material field.
pub fn operation_digest(input: &OperationDigestInput<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sequel-mcp/operation/v1\n");
    h.update(input.connection.as_bytes());
    h.update(b"\n");
    h.update(input.driver.as_bytes());
    h.update(b"\n");
    h.update(input.database.unwrap_or("\u{0}").as_bytes());
    h.update(b"\n");
    for t in sorted_tables(input.read_tables) {
        h.update(t.as_bytes());
        h.update(b"\x1e");
    }
    h.update(b"\n");
    for t in sorted_tables(input.mutated_tables) {
        h.update(t.as_bytes());
        h.update(b"\x1e");
    }
    h.update(b"\n");
    h.update(input.category.as_str().as_bytes());
    h.update(b"\n");
    h.update(input.canonical_sql.as_bytes());
    h.update(b"\n");
    for p in input.parameter_hashes {
        h.update(p);
    }
    h.update(b"\n");
    h.update(
        input
            .backup_plan_identity
            .map(str::as_bytes)
            .unwrap_or(&[0]),
    );
    h.update(b"\n");
    h.update(input.policy_revision.to_le_bytes());
    h.update(input.metadata_revision.to_le_bytes());
    h.update(b"\n");
    h.update(input.nonce);
    h.finalize().into()
}

/// Canonical SQL: re-printed from the AST when parseable, otherwise the
/// whitespace-normalized statement. Literals are NOT redacted here (the
/// digest must change when literals change); redaction happens in audit.
pub fn canonical_sql(statement: &str, dialect: crate::policy::classifier::Dialect) -> String {
    use sqlparser::parser::Parser;
    let parsed = match dialect {
        crate::policy::classifier::Dialect::MySql => {
            Parser::parse_sql(&sqlparser::dialect::MySqlDialect {}, statement)
        }
        crate::policy::classifier::Dialect::SQLite => {
            Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, statement)
        }
    };
    match parsed {
        Ok(stmts) if stmts.len() == 1 => normalize_ws(&stmts[0].to_string()),
        _ => normalize_ws(statement),
    }
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::classifier::{ClassifiedStatement, Dialect, TableRef, classify_statement};

    fn input_for(sql: &str) -> (String, ClassifiedStatement) {
        let c = classify_statement(sql, Dialect::MySql).unwrap();
        (canonical_sql(sql, Dialect::MySql), c)
    }

    fn digest_of(sql: &str, nonce: [u8; 32]) -> [u8; 32] {
        let (canon, c) = input_for(sql);
        operation_digest(&OperationDigestInput {
            connection: "c1",
            driver: "mysql",
            database: Some("app"),
            read_tables: &c.read_tables,
            mutated_tables: &c.mutated_tables,
            category: c.category,
            canonical_sql: &canon,
            parameter_hashes: &[],
            backup_plan_identity: None,
            policy_revision: 1,
            metadata_revision: 0,
            nonce,
        })
    }

    #[test]
    fn different_sql_different_digest() {
        let n = [0u8; 32];
        assert_ne!(
            digest_of("UPDATE app.jobs SET a = 1 WHERE id = 1", n),
            digest_of("UPDATE app.jobs SET a = 2 WHERE id = 1", n)
        );
    }

    #[test]
    fn different_tables_different_digest() {
        let n = [0u8; 32];
        assert_ne!(
            digest_of("UPDATE app.jobs SET a = 1", n),
            digest_of("UPDATE app.users SET a = 1", n)
        );
    }

    #[test]
    fn same_operation_same_digest() {
        let n = [5u8; 32];
        assert_eq!(
            digest_of("UPDATE app.jobs SET a = 1", n),
            digest_of("UPDATE app.jobs SET a = 1", n)
        );
    }

    #[test]
    fn nonce_changes_digest() {
        assert_ne!(
            digest_of("UPDATE app.jobs SET a = 1", [0u8; 32]),
            digest_of("UPDATE app.jobs SET a = 1", [1u8; 32])
        );
    }

    #[test]
    fn policy_revision_changes_digest() {
        let (canon, c) = input_for("UPDATE app.jobs SET a = 1");
        let base = operation_digest(&OperationDigestInput {
            connection: "c1",
            driver: "mysql",
            database: Some("app"),
            read_tables: &c.read_tables,
            mutated_tables: &c.mutated_tables,
            category: c.category,
            canonical_sql: &canon,
            parameter_hashes: &[],
            backup_plan_identity: None,
            policy_revision: 1,
            metadata_revision: 0,
            nonce: [0u8; 32],
        });
        let bumped = operation_digest(&OperationDigestInput {
            connection: "c1",
            driver: "mysql",
            database: Some("app"),
            read_tables: &c.read_tables,
            mutated_tables: &c.mutated_tables,
            category: c.category,
            canonical_sql: &canon,
            parameter_hashes: &[],
            backup_plan_identity: None,
            policy_revision: 2,
            metadata_revision: 0,
            nonce: [0u8; 32],
        });
        assert_ne!(base, bumped);
        let _ = TableRef {
            database: None,
            table: String::new(),
        };
    }

    #[test]
    fn canonical_sql_is_stable_across_formatting() {
        assert_eq!(
            canonical_sql("SELECT 1", Dialect::MySql),
            canonical_sql("SELECT    1", Dialect::MySql)
        );
    }
}
