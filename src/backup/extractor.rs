//! Backup spec extraction (`backup/extractor.ts` port): what to capture
//! before a mutation so it can be undone.

use crate::policy::classifier::Dialect;
use sqlparser::ast::{Expr, Statement};
use sqlparser::parser::Parser;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BackupTable {
    pub db: Option<String>,
    pub table: String,
    pub select_sql: String,
    pub locking: &'static str, // "FOR UPDATE" | "NONE"
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BackupSpec {
    None {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Rows {
        tables: Vec<BackupTable>,
    },
    Schema {
        tables: Vec<SchemaTable>,
    },
    Combined {
        tables: Vec<BackupTable>,
    },
    InsertHint {
        table: SchemaTable,
        columns: Vec<String>,
        explicit_pk_values: Option<Vec<Vec<serde_json::Value>>>,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SchemaTable {
    pub db: Option<String>,
    pub table: String,
}

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("parse error: {0}")]
    Parse(String),
}

pub fn quote_ident(id: &str) -> String {
    format!("`{}`", id.replace('`', "``"))
}

pub fn table_ref_sql(db: &Option<String>, table: &str) -> String {
    match db {
        Some(db) => format!("{}.{}", quote_ident(db), quote_ident(table)),
        None => quote_ident(table),
    }
}

fn object_parts(name: &sqlparser::ast::ObjectName) -> (Option<String>, String) {
    let mut parts = Vec::new();
    for p in &name.0 {
        if let sqlparser::ast::ObjectNamePart::Identifier(i) = p {
            parts.push(i.value.clone());
        }
    }
    match parts.len() {
        0 => (None, String::new()),
        1 => (None, parts.remove(0)),
        _ => {
            let table = parts.pop().unwrap_or_default();
            (parts.pop(), table)
        }
    }
}

fn expr_sql(e: &Expr) -> String {
    e.to_string()
}

fn lock_suffix(dialect: Dialect) -> &'static str {
    if dialect == Dialect::MySql {
        " FOR UPDATE"
    } else {
        ""
    }
}

/// Render the FROM-side of the statement (tables + joins) exactly as
/// written, so backup SELECTs keep join semantics.
fn from_sql(twj: &sqlparser::ast::TableWithJoins) -> String {
    twj.to_string()
}

pub fn is_backup_required(ast_type: &str) -> bool {
    matches!(
        ast_type,
        "update" | "delete" | "replace" | "insert" | "truncate" | "drop" | "alter" | "rename"
    )
}

/// Lock suffixes recognised after stripping; each must move *after* the
/// appended LIMIT to stay valid MySQL.
const TRAILING_LOCK_SUFFIXES: [&str; 5] = [
    " FOR UPDATE NOWAIT",
    " FOR UPDATE SKIP LOCKED",
    " FOR UPDATE",
    " FOR SHARE",
    " LOCK IN SHARE MODE",
];

/// Append `LIMIT n` to a backup SELECT, preserving any trailing lock
/// clause. Returns `None` when the query cannot be safely rewritten
/// (existing LIMIT/OFFSET, set operations, CTE, trailing semicolon or
/// comment, parenthesized tail, or an unmatched lock clause) — callers
/// must DENY in that case rather than execute the unbounded original.
pub fn with_limit(select_sql: &str, n: u64) -> Option<String> {
    if select_sql.contains(';') {
        return None; // trailing semicolon or statement separator: refuse
    }
    let lower = select_sql.to_ascii_lowercase();
    if lower.contains(" limit ") || lower.ends_with(" limit") {
        return None; // existing LIMIT: composing another is invalid
    }
    if lower.contains(" offset ") {
        return None;
    }
    if lower.starts_with("with ") || lower.contains(" union ") {
        return None; // set operations/CTEs: not safely suffix-rewritable
    }
    if select_sql.contains("--") || select_sql.contains("/*") {
        return None; // comments could hide a tail we fail to see
    }
    if select_sql.ends_with(')') {
        return None; // parenthesized query expression: refuse
    }
    for suffix in TRAILING_LOCK_SUFFIXES {
        if let Some(base) = select_sql.strip_suffix(suffix) {
            return Some(format!("{base} LIMIT {n}{suffix}"));
        }
    }
    if lower.contains(" for update")
        || lower.contains(" for share")
        || lower.contains(" for key share")
        || lower.contains(" lock in share mode")
    {
        return None; // a lock clause we failed to match exactly: refuse
    }
    Some(format!("{select_sql} LIMIT {n}"))
}

const PK_GUESS_NAMES: [&str; 3] = ["id", "uuid", "pk"];

fn guess_pk_column(columns: &[String]) -> Option<usize> {
    for guess in PK_GUESS_NAMES {
        if let Some(i) = columns.iter().position(|c| c.eq_ignore_ascii_case(guess)) {
            return Some(i);
        }
    }
    None
}

fn literal_json(v: &Expr) -> serde_json::Value {
    match v {
        Expr::Value(val) => match &val.value {
            sqlparser::ast::Value::Number(n, _) => {
                serde_json::from_str(n).unwrap_or_else(|_| serde_json::json!(n))
            }
            sqlparser::ast::Value::SingleQuotedString(s)
            | sqlparser::ast::Value::DoubleQuotedString(s) => serde_json::json!(s),
            sqlparser::ast::Value::NationalStringLiteral(s) => serde_json::json!(s),
            sqlparser::ast::Value::HexStringLiteral(s) => serde_json::json!(s),
            sqlparser::ast::Value::Null => serde_json::Value::Null,
            sqlparser::ast::Value::Placeholder(p) => serde_json::json!(p),
            sqlparser::ast::Value::EscapedStringLiteral(s) => serde_json::json!(s),
            sqlparser::ast::Value::SingleQuotedByteStringLiteral(s)
            | sqlparser::ast::Value::DoubleQuotedByteStringLiteral(s) => serde_json::json!(s),
            _ => serde_json::Value::Null,
        },
        _ => serde_json::Value::Null,
    }
}

/// Build the backup spec for a statement. `ast_type` is the legacy name
/// from the classifier.
pub fn extract_backup_spec(
    sql: &str,
    ast_type: &str,
    dialect: Dialect,
) -> Result<BackupSpec, ExtractError> {
    let stmts = Parser::parse_sql(
        match dialect {
            Dialect::MySql => {
                &sqlparser::dialect::MySqlDialect {} as &dyn sqlparser::dialect::Dialect
            }
            Dialect::SQLite => {
                &sqlparser::dialect::SQLiteDialect {} as &dyn sqlparser::dialect::Dialect
            }
        },
        sql,
    )
    .map_err(|e| ExtractError::Parse(e.to_string()))?;
    let Some(stmt) = stmts.into_iter().next() else {
        return Ok(BackupSpec::None {
            reason: Some("no statement".into()),
        });
    };

    match ast_type {
        "update" => update_spec(&stmt, dialect),
        "delete" => delete_spec(&stmt, dialect),
        "replace" => replace_spec(&stmt, dialect),
        "insert" => insert_spec(&stmt),
        "truncate" => truncate_spec(&stmt),
        "drop" => drop_spec(&stmt),
        "alter" | "rename" => schema_spec(&stmt),
        _ => Ok(BackupSpec::None {
            reason: Some(format!("no backup strategy for AST type \"{ast_type}\"")),
        }),
    }
}

fn where_suffix(where_expr: Option<&Expr>) -> String {
    where_expr
        .map(|w| format!(" WHERE {}", expr_sql(w)))
        .unwrap_or_default()
}

fn update_spec(stmt: &Statement, dialect: Dialect) -> Result<BackupSpec, ExtractError> {
    let Statement::Update(u) = stmt else {
        return Ok(none("not an UPDATE"));
    };
    let from = &u.table;
    let where_sql = where_suffix(u.selection.as_ref());
    let lock = lock_suffix(dialect);

    // SET-target qualification decides which joined tables get row backups
    // (legacy `inferMutatedTables`); unqualified SET falls back to the
    // first table.
    let mut qualified: Vec<String> = Vec::new();
    for a in &u.assignments {
        if let sqlparser::ast::AssignmentTarget::ColumnName(id) = &a.target {
            let parts = &id.0;
            if parts.len() == 2
                && let sqlparser::ast::ObjectNamePart::Identifier(tbl) = &parts[0]
                && !qualified.contains(&tbl.value)
            {
                qualified.push(tbl.value.clone());
            }
        }
    }

    let all_tables = collect_tables_with_aliases(from);
    let targets: Vec<(Option<String>, String, String)> = if qualified.is_empty() {
        let (db, table, rendered) = all_tables.first().cloned().unwrap_or_default();
        vec![(db, table, rendered)]
    } else {
        all_tables
            .iter()
            .filter(|(_, table, _)| qualified.iter().any(|q| table.eq_ignore_ascii_case(q)))
            .cloned()
            .collect()
    };

    let full_from = from_sql(from);
    let mut tables = Vec::new();
    for (db, table, _rendered) in targets {
        let select = if all_tables.len() == 1 && where_sql.is_empty() {
            format!("SELECT * FROM {}{}", table_ref_sql(&db, &table), lock)
        } else {
            let alias_col = format!("{}.*", quote_ident(&table));
            format!(
                "SELECT {} FROM {}{}{}",
                alias_col, full_from, where_sql, lock
            )
        };
        tables.push(BackupTable {
            db,
            table,
            select_sql: select,
            locking: if lock.is_empty() {
                "NONE"
            } else {
                "FOR UPDATE"
            },
        });
    }
    if tables.is_empty() {
        return Ok(none("no mutated tables identified in multi-table UPDATE"));
    }
    Ok(BackupSpec::Rows { tables })
}

/// (db, table, rendered-alias-or-name) for every table factor in FROM.
fn collect_tables_with_aliases(
    twj: &sqlparser::ast::TableWithJoins,
) -> Vec<(Option<String>, String, String)> {
    let mut out = Vec::new();
    let mut visit = |f: &sqlparser::ast::TableFactor| {
        if let sqlparser::ast::TableFactor::Table { name, alias, .. } = f {
            let (db, table) = object_parts(name);
            let rendered = alias
                .as_ref()
                .map(|a| a.name.value.clone())
                .unwrap_or_else(|| table.clone());
            out.push((db, table, rendered));
        }
    };
    visit(&twj.relation);
    for j in &twj.joins {
        visit(&j.relation);
    }
    out
}

fn delete_spec(stmt: &Statement, dialect: Dialect) -> Result<BackupSpec, ExtractError> {
    let Statement::Delete(d) = stmt else {
        return Ok(none("not a DELETE"));
    };
    let where_sql = where_suffix(d.selection.as_ref());
    let lock = lock_suffix(dialect);

    let mut from_tables: Vec<(Option<String>, String, String)> = Vec::new();
    let collect = |twjs: &Vec<sqlparser::ast::TableWithJoins>, out: &mut Vec<_>| {
        for twj in twjs {
            out.extend(collect_tables_with_aliases(twj));
        }
    };
    match &d.from {
        sqlparser::ast::FromTable::WithFromKeyword(t) => collect(t, &mut from_tables),
        sqlparser::ast::FromTable::WithoutKeyword(t) => collect(t, &mut from_tables),
    }
    if let Some(using) = &d.using {
        collect(using, &mut from_tables);
    }

    // DELETE targets: `DELETE a, b FROM …` names them explicitly.
    let explicit: Vec<(Option<String>, String)> = d.tables.iter().map(object_parts).collect();

    let targets: Vec<(Option<String>, String)> = if !explicit.is_empty() {
        explicit
            .into_iter()
            .map(|(db, table)| {
                let resolved = from_tables
                    .iter()
                    .find(|(_, t, _)| t.eq_ignore_ascii_case(&table))
                    .map(|(fdb, _, _)| fdb.clone())
                    .unwrap_or(db);
                (resolved, table)
            })
            .collect()
    } else {
        from_tables
            .iter()
            .map(|(db, t, _)| (db.clone(), t.clone()))
            .collect()
    };

    if from_tables.is_empty() {
        return Ok(none("DELETE has no source table"));
    }

    let mut tables = Vec::new();
    for (db, table) in targets {
        let select = if from_tables.len() == 1 && where_sql.is_empty() {
            format!("SELECT * FROM {}{}", table_ref_sql(&db, &table), lock)
        } else {
            let rendered = from_tables
                .iter()
                .find(|(_, t, _)| t.eq_ignore_ascii_case(&table))
                .map(|(_, _, r)| r.clone())
                .unwrap_or_else(|| table.clone());
            format!(
                "SELECT {}.* FROM {}{}{}",
                quote_ident(&rendered),
                from_tables
                    .iter()
                    .map(|(db, t, _)| table_ref_sql(db, t))
                    .collect::<Vec<_>>()
                    .join(", "),
                where_sql,
                lock
            )
        };
        tables.push(BackupTable {
            db,
            table,
            select_sql: select,
            locking: if lock.is_empty() {
                "NONE"
            } else {
                "FOR UPDATE"
            },
        });
    }
    Ok(BackupSpec::Rows { tables })
}

fn replace_spec(stmt: &Statement, dialect: Dialect) -> Result<BackupSpec, ExtractError> {
    let Statement::Insert(ins) = stmt else {
        return Ok(none("not a REPLACE"));
    };
    if !ins.replace_into {
        return Ok(none("not a REPLACE"));
    }
    let Some((db, table)) = table_of(ins) else {
        return Ok(none("REPLACE target unclear"));
    };
    let columns: Vec<String> = ins
        .columns
        .iter()
        .map(|c| {
            c.0.iter()
                .filter_map(|p| match p {
                    sqlparser::ast::ObjectNamePart::Identifier(i) => Some(i.value.clone()),
                    _ => None,
                })
                .next()
                .unwrap_or_default()
        })
        .collect();
    let rows = literal_rows(ins);
    if let (Some(pk_idx), Some(all_rows)) = (guess_pk_column(&columns), rows)
        && !all_rows.is_empty()
    {
        let values: Vec<String> = all_rows
            .iter()
            .map(|row| sql_literal(&row[pk_idx]))
            .collect();
        let lock = lock_suffix(dialect);
        let select = format!(
            "SELECT * FROM {} WHERE {} IN ({}){}",
            table_ref_sql(&db, &table),
            quote_ident(&columns[pk_idx]),
            values.join(", "),
            lock
        );
        return Ok(BackupSpec::Rows {
            tables: vec![BackupTable {
                db,
                table,
                select_sql: select,
                locking: if lock.is_empty() {
                    "NONE"
                } else {
                    "FOR UPDATE"
                },
            }],
        });
    }
    Ok(none(
        "REPLACE without identifiable PK column; no backup taken",
    ))
}

fn insert_spec(stmt: &Statement) -> Result<BackupSpec, ExtractError> {
    let Statement::Insert(ins) = stmt else {
        return Ok(none("not an INSERT"));
    };
    let Some((db, table)) = table_of(ins) else {
        return Ok(none("INSERT target unclear"));
    };
    let columns: Vec<String> = ins
        .columns
        .iter()
        .map(|c| {
            c.0.iter()
                .filter_map(|p| match p {
                    sqlparser::ast::ObjectNamePart::Identifier(i) => Some(i.value.clone()),
                    _ => None,
                })
                .next()
                .unwrap_or_default()
        })
        .collect();
    let rows = literal_rows(ins);
    let explicit = match (guess_pk_column(&columns), rows) {
        (Some(idx), Some(all)) if !all.is_empty() => {
            Some(all.iter().map(|r| vec![r[idx].clone()]).collect())
        }
        _ => None,
    };
    Ok(BackupSpec::InsertHint {
        table: SchemaTable { db, table },
        columns,
        explicit_pk_values: explicit,
    })
}

fn table_of(ins: &sqlparser::ast::Insert) -> Option<(Option<String>, String)> {
    match &ins.table {
        sqlparser::ast::TableObject::TableName(name) => Some(object_parts(name)),
        _ => None,
    }
}

fn literal_rows(ins: &sqlparser::ast::Insert) -> Option<Vec<Vec<serde_json::Value>>> {
    let source = ins.source.as_ref()?;
    match source.body.as_ref() {
        sqlparser::ast::SetExpr::Values(values) => Some(
            values
                .rows
                .iter()
                .map(|row| row.iter().map(literal_json).collect())
                .collect(),
        ),
        _ => None,
    }
}

fn sql_literal(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "NULL".into(),
        serde_json::Value::Bool(b) => if *b { "1" } else { "0" }.into(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        other => format!("'{}'", other.to_string().replace('\'', "''")),
    }
}

fn truncate_spec(stmt: &Statement) -> Result<BackupSpec, ExtractError> {
    let Statement::Truncate(t) = stmt else {
        return Ok(none("not a TRUNCATE"));
    };
    let Some(target) = t.table_names.first() else {
        return Ok(none("TRUNCATE target unclear"));
    };
    let (db, table) = object_parts(&target.name);
    let select_sql = format!("SELECT * FROM {}", table_ref_sql(&db, &table));
    Ok(BackupSpec::Combined {
        tables: vec![BackupTable {
            db,
            table,
            select_sql,
            locking: "NONE",
        }],
    })
}

fn drop_spec(stmt: &Statement) -> Result<BackupSpec, ExtractError> {
    let Statement::Drop { names, .. } = stmt else {
        return Ok(none("not a DROP"));
    };
    let Some(name) = names.first() else {
        return Ok(none("DROP target unclear"));
    };
    let (db, table) = object_parts(name);
    let select_sql = format!("SELECT * FROM {}", table_ref_sql(&db, &table));
    Ok(BackupSpec::Combined {
        tables: vec![BackupTable {
            db,
            table,
            select_sql,
            locking: "NONE",
        }],
    })
}

fn schema_spec(stmt: &Statement) -> Result<BackupSpec, ExtractError> {
    match stmt {
        Statement::AlterTable(a) => {
            let (db, table) = object_parts(&a.name);
            Ok(BackupSpec::Schema {
                tables: vec![SchemaTable { db, table }],
            })
        }
        Statement::RenameTable(renames) => {
            let mut tables = Vec::new();
            for rn in renames {
                let (odb, otable) = object_parts(&rn.old_name);
                let (ndb, ntable) = object_parts(&rn.new_name);
                tables.push(SchemaTable {
                    db: odb,
                    table: otable,
                });
                let _ = (ndb, ntable);
            }
            Ok(BackupSpec::Schema { tables })
        }
        _ => Ok(none("not ALTER/RENAME")),
    }
}

fn none(reason: &str) -> BackupSpec {
    BackupSpec::None {
        reason: Some(reason.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(sql: &str, ast_type: &str) -> BackupSpec {
        extract_backup_spec(sql, ast_type, Dialect::MySql).unwrap()
    }

    #[test]
    fn update_with_where_selects_for_update() {
        let s = spec("UPDATE users SET name = 'x' WHERE id = 1", "update");
        match s {
            BackupSpec::Rows { tables } => {
                assert_eq!(tables.len(), 1);
                assert_eq!(tables[0].table, "users");
                assert!(tables[0].select_sql.contains("FOR UPDATE"));
                assert!(
                    tables[0].select_sql.contains("WHERE"),
                    "select keeps the WHERE: {}",
                    tables[0].select_sql
                );
                assert!(tables[0].select_sql.contains("id"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn update_without_where_backs_up_all_rows() {
        let s = spec("UPDATE users SET name = 'x'", "update");
        match s {
            BackupSpec::Rows { tables } => {
                assert!(tables[0].select_sql.starts_with("SELECT * FROM `users`"));
                assert!(!tables[0].select_sql.contains("WHERE"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn multi_table_update_backs_up_set_targets() {
        let s = spec(
            "UPDATE a JOIN b ON a.id = b.id SET a.x = 1, b.y = 2",
            "update",
        );
        match s {
            BackupSpec::Rows { tables } => assert_eq!(tables.len(), 2),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn delete_multi_target() {
        let s = spec(
            "DELETE a FROM a JOIN b ON a.id = b.id WHERE b.flag = 1",
            "delete",
        );
        match s {
            BackupSpec::Rows { tables } => {
                assert_eq!(tables.len(), 1);
                assert_eq!(tables[0].table, "a");
                assert!(tables[0].select_sql.contains("WHERE"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replace_with_pk_preselects() {
        let s = spec("REPLACE INTO users (id, name) VALUES (1, 'a')", "replace");
        match s {
            BackupSpec::Rows { tables } => {
                assert!(tables[0].select_sql.contains("`id` IN (1)"));
                assert!(tables[0].select_sql.contains("FOR UPDATE"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replace_without_pk_is_none() {
        let s = spec("REPLACE INTO users (name) VALUES ('a')", "replace");
        assert!(matches!(s, BackupSpec::None { .. }));
    }

    #[test]
    fn insert_hint_explicit_pk() {
        let s = spec("INSERT INTO users (id, name) VALUES (5, 'a')", "insert");
        match s {
            BackupSpec::InsertHint {
                explicit_pk_values: Some(v),
                ..
            } => assert_eq!(v, vec![vec![serde_json::json!(5)]]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn insert_hint_without_pk() {
        let s = spec("INSERT INTO users (name) VALUES ('a')", "insert");
        match s {
            BackupSpec::InsertHint {
                explicit_pk_values: None,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn truncate_and_drop_are_combined() {
        assert!(matches!(
            spec("TRUNCATE TABLE users", "truncate"),
            BackupSpec::Combined { .. }
        ));
        assert!(matches!(
            spec("DROP TABLE users", "drop"),
            BackupSpec::Combined { .. }
        ));
    }

    #[test]
    fn alter_is_schema_only() {
        assert!(matches!(
            spec("ALTER TABLE users ADD COLUMN email TEXT", "alter"),
            BackupSpec::Schema { .. }
        ));
    }

    #[test]
    fn d6_limit_forms() {
        use super::with_limit as wl;
        // Rewritable forms.
        assert_eq!(
            wl("SELECT * FROM t WHERE id = 1 FOR UPDATE", 11).unwrap(),
            "SELECT * FROM t WHERE id = 1 LIMIT 11 FOR UPDATE"
        );
        assert_eq!(
            wl("SELECT * FROM t FOR UPDATE NOWAIT", 11).unwrap(),
            "SELECT * FROM t LIMIT 11 FOR UPDATE NOWAIT"
        );
        assert_eq!(
            wl("SELECT * FROM t FOR UPDATE SKIP LOCKED", 11).unwrap(),
            "SELECT * FROM t LIMIT 11 FOR UPDATE SKIP LOCKED"
        );
        assert_eq!(
            wl("SELECT * FROM t FOR SHARE", 11).unwrap(),
            "SELECT * FROM t LIMIT 11 FOR SHARE"
        );
        assert_eq!(
            wl("SELECT * FROM t LOCK IN SHARE MODE", 11).unwrap(),
            "SELECT * FROM t LIMIT 11 LOCK IN SHARE MODE"
        );
        // Optimizer hints are comment-delimited; a suffix rewriter cannot
        // distinguish them from tail-hiding comments, so they are denied.
        assert!(
            wl("SELECT /*+ hint */ * FROM t", 11).is_none(),
            "optimizer hints denied (comment-shaped)"
        );
        assert_eq!(
            wl("SELECT * FROM t", 11).unwrap(),
            "SELECT * FROM t LIMIT 11"
        );
        // Unrewritable forms must return None (deny), never a bad rewrite.
        assert!(
            wl("SELECT * FROM t LIMIT 5", 11).is_none(),
            "existing LIMIT"
        );
        assert!(
            wl("SELECT * FROM t LIMIT 5 OFFSET 2", 11).is_none(),
            "offset"
        );
        assert!(
            wl("SELECT * FROM a UNION SELECT * FROM b", 11).is_none(),
            "union"
        );
        assert!(
            wl("WITH x AS (SELECT 1) SELECT * FROM x", 11).is_none(),
            "cte"
        );
        assert!(wl("SELECT * FROM t;", 11).is_none(), "semicolon");
        assert!(
            wl("SELECT * FROM t -- comment", 11).is_none(),
            "line comment"
        );
        assert!(wl("SELECT * FROM /* c */ t", 11).is_none(), "block comment");
        assert!(wl("(SELECT * FROM t)", 11).is_none(), "parenthesized");
        assert!(
            wl("SELECT * FROM t FOR KEY SHARE", 11).is_none(),
            "unknown lock"
        );
    }

    #[test]
    fn create_is_none() {
        assert!(matches!(
            spec("CREATE TABLE t (id INT)", "create"),
            BackupSpec::None { .. }
        ));
    }
}
