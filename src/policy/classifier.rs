//! SQL classification and object extraction (`policy/classifier.ts` port).
//!
//! Preserves the legacy contract (categories, ast names, fast paths,
//! multi-statement rejection, target database collection) and adds the v2
//! object graph: distinct read vs mutated tables, locking-read and file-io
//! flags, and executing-semantics for `EXPLAIN ANALYZE`.

use crate::policy::model::SqlCategory;
use sqlparser::ast::{Expr, ObjectName, Query, SetExpr, Statement, TableFactor};
use sqlparser::dialect::{MySqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TableRef {
    /// `None` for unqualified references; resolved (or denied) later.
    pub database: Option<String>,
    pub table: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassifiedStatement {
    pub category: SqlCategory,
    /// Legacy-compatible AST type name (`select`, `insert`, `update`,
    /// `delete`, `replace`, `create`, `drop`, `alter`, `truncate`, `rename`,
    /// `grant`, `set`, `show`, `describe`, `explain`, `pragma`,
    /// `transaction`, `admin-keyword`).
    pub ast_type: &'static str,
    /// Distinct database qualifiers across all table references, sorted
    /// (legacy `targetDatabases`).
    pub target_databases: Vec<String>,
    /// Tables the statement reads.
    pub read_tables: Vec<TableRef>,
    /// Tables the statement can mutate. For UPDATE/DELETE every
    /// from/using table counts: MySQL may mutate any joined table.
    pub mutated_tables: Vec<TableRef>,
    /// `FOR UPDATE` / `LOCK IN SHARE MODE` present — not an ordinary read.
    pub locking_read: bool,
    /// Statement reads or writes server-side files (`INTO OUTFILE`,
    /// `LOAD DATA [LOCAL] INFILE`) — denied by policy regardless of
    /// category grants.
    pub file_io: bool,
    /// `EXPLAIN ANALYZE` — executes the wrapped statement.
    pub executes_wrapped: bool,
    /// `IF EXISTS` present on DROP/TRUNCATE DDL (absent-target handling:
    /// preflight turns a missing target into an audited local no-op).
    pub if_exists: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClassifyError {
    Empty,
    CommentOnly,
    MultipleStatements,
    Parse(String),
    Unknown(String),
}

impl ClassifyError {
    /// Message shapes mirror the legacy classifier error strings.
    pub fn message(&self) -> String {
        match self {
            ClassifyError::Empty => "empty input".into(),
            ClassifyError::CommentOnly => "input contains only comments".into(),
            ClassifyError::MultipleStatements => {
                "multiple statements not allowed (single statement only)".into()
            }
            ClassifyError::Parse(m) => format!("parser error: {m}"),
            ClassifyError::Unknown(t) => format!("unknown statement type \"{t}\""),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    MySql,
    SQLite,
}

impl Dialect {
    fn as_dyn(&self) -> &'static dyn sqlparser::dialect::Dialect {
        match self {
            Dialect::MySql => &MySqlDialect {},
            Dialect::SQLite => &SQLiteDialect {},
        }
    }
}

/// Strip `/* */`, `-- ` and MySQL `#` comments (legacy `stripComments`).
pub fn strip_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let bytes: Vec<char> = sql.chars().collect();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let c = bytes[i];
        if c == '/' && i + 1 < n && bytes[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(n);
            out.push(' ');
        } else if (c == '-' && i + 1 < n && bytes[i + 1] == '-') || c == '#' {
            // `-- ` line comment or MySQL `#` comment: skip to end of line.
            while i < n && bytes[i] != '\n' {
                i += 1;
            }
            out.push(' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Quote/paren-aware semicolon scan (legacy `looksLikeMultipleStatements`):
/// a `;` at depth 0 outside any quoted region means multiple statements.
pub fn looks_like_multiple_statements(sql: &str) -> bool {
    let stripped = strip_comments(sql);
    let trimmed = stripped.trim_end();
    let trimmed = trimmed.strip_suffix(';').unwrap_or(trimmed).trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut quote: Option<char> = None;
    let mut depth: i32 = 0;
    let chars: Vec<char> = trimmed.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if let Some(q) = quote {
            if c == q && (i == 0 || chars[i - 1] != '\\') {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' => depth += 1,
            ')' => depth -= 1,
            ';' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

fn is_tx_keyword(stripped: &str) -> bool {
    let t = stripped.trim_start();
    let lower = t.to_ascii_lowercase();
    let starts = [
        "begin",
        "commit",
        "rollback",
        "start transaction",
        "savepoint",
        "release savepoint",
    ];
    let Some(first) = lower.split_whitespace().next() else {
        return false;
    };
    if !starts
        .iter()
        .any(|s| lower.starts_with(s) && word_bounded(&lower, s))
    {
        return false;
    }
    first == "begin"
        || first == "commit"
        || first == "rollback"
        || lower.starts_with("start transaction")
        || lower.starts_with("savepoint")
        || lower.starts_with("release savepoint")
}

fn word_bounded(lower: &str, prefix: &str) -> bool {
    match lower.get(prefix.len()..) {
        Some(rest) => rest.starts_with(|c: char| c.is_whitespace()) || rest.is_empty(),
        None => false,
    }
}

fn is_admin_keyword(stripped: &str) -> bool {
    let lower = stripped.trim_start().to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "grant ",
        "revoke ",
        "set global",
        "set persist",
        "set persist_only",
        "set @@global",
        "set @@persist",
        "kill ",
        "flush",
        "reset master",
        "reset slave",
        "reset replica",
        "lock tables",
        "unlock tables",
        "load data",
        "handler ",
        "do ",
        "change master",
        "change replication",
        "start slave",
        "stop slave",
        "start replica",
        "stop replica",
        "optimize table",
        "repair table",
        "analyze table",
        "check table",
        "create user",
        "alter user",
        "drop user",
        "rename user",
        "set password",
        "attach database",
        "detach database",
        "vacuum",
        "reindex",
    ];
    PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// The 22 read-only PRAGMA names (legacy allowlist).
const READ_ONLY_PRAGMAS: [&str; 22] = [
    "application_id",
    "collation_list",
    "compile_options",
    "database_list",
    "foreign_key_check",
    "foreign_key_list",
    "freelist_count",
    "function_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "integrity_check",
    "module_list",
    "page_count",
    "page_size",
    "quick_check",
    "schema_version",
    "table_info",
    "table_list",
    "table_xinfo",
    "user_version",
    "pragma_list",
];

/// SQLite PRAGMA fast path. Returns the category when the statement is a
/// pragma: read for allowlisted pragmas without `=`, admin otherwise.
fn classify_sqlite_pragma(stripped: &str) -> Option<SqlCategory> {
    let lower = stripped.trim_start().to_ascii_lowercase();
    let rest = lower.strip_prefix("pragma ")?.trim_start();
    // Optional schema qualifier: `name.` or quoted forms.
    let rest = match rest.find('.') {
        Some(dot)
            if !rest.starts_with('\'') && !rest.starts_with('"') && !rest.starts_with('[') =>
        {
            &rest[dot + 1..]
        }
        _ => rest,
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    if stripped.contains('=') || !READ_ONLY_PRAGMAS.contains(&name.as_str()) {
        Some(SqlCategory::Admin)
    } else {
        Some(SqlCategory::Read)
    }
}

/// Classify one statement. See module docs for the behavioural contract.
pub fn classify_statement(
    sql: &str,
    dialect: Dialect,
) -> Result<ClassifiedStatement, ClassifyError> {
    if sql.trim().is_empty() {
        return Err(ClassifyError::Empty);
    }
    let stripped = strip_comments(sql);
    if stripped.trim().is_empty() {
        return Err(ClassifyError::CommentOnly);
    }
    if looks_like_multiple_statements(sql) {
        return Err(ClassifyError::MultipleStatements);
    }

    if dialect == Dialect::SQLite
        && let Some(category) = classify_sqlite_pragma(&stripped)
    {
        return Ok(empty_result(category, "pragma"));
    }

    if is_tx_keyword(&stripped) {
        return Ok(empty_result(SqlCategory::TxCtrl, "transaction"));
    }
    if is_admin_keyword(&stripped) {
        let file_io = {
            let lower = stripped.to_ascii_lowercase();
            lower.contains("infile") || lower.contains("outfile") || lower.contains("dumpfile")
        };
        let mut r = empty_result(SqlCategory::Admin, "admin-keyword");
        r.file_io = file_io;
        // Best-effort target extraction for statements the AST layer cannot
        // express; qualified refs only.
        r.target_databases = collect_qualified_databases(&stripped);
        return Ok(r);
    }

    let statements = match Parser::parse_sql(dialect.as_dyn(), &stripped) {
        Ok(stmts) => stmts,
        Err(e) => {
            // `SELECT … INTO OUTFILE/DUMPFILE` and MySQL `LOCK IN SHARE
            // MODE` do not parse, but the legacy classifier accepted both;
            // keep the read category and flag them so the policy gate
            // applies the stricter authorization (file I/O denied; locking
            // reads are not ordinary reads).
            let lower = stripped.to_ascii_lowercase();
            if lower.contains("into outfile") || lower.contains("into dumpfile") {
                let mut r = empty_result(SqlCategory::Read, "select");
                r.file_io = true;
                r.target_databases = collect_qualified_databases(&stripped);
                return Ok(r);
            }
            if lower.contains("lock in share mode") {
                let mut r = empty_result(SqlCategory::Read, "select");
                r.locking_read = true;
                r.target_databases = collect_qualified_databases(&stripped);
                return Ok(r);
            }
            // MySQL user-variable assignments (`SET @x = …`) do not parse;
            // the legacy classifier treated every `SET` as admin.
            if lower.trim_start().starts_with("set ") || lower.trim_start() == "set" {
                return Ok(empty_result(SqlCategory::Admin, "set"));
            }
            return Err(ClassifyError::Parse(e.to_string()));
        }
    };
    if statements.len() > 1 {
        return Err(ClassifyError::MultipleStatements);
    }
    let stmt = statements.into_iter().next().ok_or(ClassifyError::Empty)?;
    classify_ast(&stmt, sql)
}

fn empty_result(category: SqlCategory, ast_type: &'static str) -> ClassifiedStatement {
    ClassifiedStatement {
        category,
        ast_type,
        target_databases: Vec::new(),
        read_tables: Vec::new(),
        mutated_tables: Vec::new(),
        locking_read: false,
        file_io: false,
        executes_wrapped: false,
        if_exists: false,
    }
}

/// Textual scan for `db.`-qualified identifiers used for fast-path admin
/// statements the AST cannot represent. Quoted regions are skipped so
/// literals like `'/tmp/x.csv'` cannot fabricate database names.
fn collect_qualified_databases(stripped: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut chars = stripped.chars().peekable();
    let mut word = String::new();
    while let Some(c) = chars.next() {
        if c == '\'' || c == '"' || c == '`' {
            // Skip the quoted region (backslash-escaped in single quotes).
            while let Some(qc) = chars.next() {
                if qc == '\\' && c == '\'' {
                    chars.next();
                } else if qc == c {
                    break;
                }
            }
            word.clear();
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            word.push(c);
            continue;
        }
        if !word.is_empty()
            && c == '.'
            && let Some(next) = chars.peek()
            && (next.is_ascii_alphabetic() || *next == '_' || *next == '`')
        {
            out.insert(word.clone());
        }
        word.clear();
    }
    out.into_iter().collect()
}

fn object_name_parts(name: &ObjectName) -> (Option<String>, String) {
    let mut parts = Vec::new();
    for p in &name.0 {
        match p {
            sqlparser::ast::ObjectNamePart::Identifier(ident) => parts.push(ident.value.clone()),
            sqlparser::ast::ObjectNamePart::Function(_) => {}
        }
    }
    match parts.len() {
        0 => (None, String::new()),
        1 => (None, parts.remove(0)),
        _ => {
            let table = parts.pop().unwrap_or_default();
            // Multi-part (db.table for MySQL, schema.table for SQLite).
            (Some(parts.pop().unwrap_or_default()), table)
        }
    }
}

/// Object-graph collector over one statement.
#[derive(Default)]
struct ObjectGraph {
    read: BTreeSet<TableRef>,
    cte_names: BTreeSet<String>,
    locking: bool,
}

impl ObjectGraph {
    fn add_table_factor(&mut self, factor: &TableFactor) {
        match factor {
            TableFactor::Table { name, .. } => {
                let (db, table) = object_name_parts(name);
                if self.cte_names.contains(&table) {
                    return;
                }
                self.read.insert(TableRef {
                    database: db,
                    table,
                });
            }
            TableFactor::Derived {
                lateral, subquery, ..
            } => {
                let _ = lateral;
                self.walk_query(subquery);
            }
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                for j in &table_with_joins.joins {
                    self.add_table_factor(&j.relation);
                }
                self.add_table_factor(&table_with_joins.relation);
            }
            // Table functions and UNNEST are not authorizable tables; treat
            // conservatively elsewhere, but do not add a phantom target.
            _ => {}
        }
    }

    fn add_table_with_joins(&mut self, twj: &sqlparser::ast::TableWithJoins) {
        self.add_table_factor(&twj.relation);
        for j in &twj.joins {
            self.add_table_factor(&j.relation);
        }
    }

    fn walk_query(&mut self, q: &Query) {
        if !q.locks.is_empty() {
            self.locking = true;
        }
        if let Some(with) = &q.with {
            for cte in &with.cte_tables {
                self.cte_names.insert(cte.alias.name.value.clone());
                self.walk_query(&cte.query);
            }
        }
        self.walk_set_expr(&q.body);
    }

    fn walk_set_expr(&mut self, body: &SetExpr) {
        match body {
            SetExpr::Select(select) => {
                for twj in &select.from {
                    self.add_table_with_joins(twj);
                }
                if let Some(expr) = &select.selection {
                    self.walk_expr_tables(expr);
                }
            }
            SetExpr::Query(q) => self.walk_query(q),
            SetExpr::SetOperation { left, right, .. } => {
                self.walk_set_expr(left);
                self.walk_set_expr(right);
            }
            SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) => {}
            SetExpr::Delete(_) | SetExpr::Merge(_) | SetExpr::Table(_) => {}
        }
    }

    /// Subqueries inside expressions (`IN (SELECT …)`, EXISTS, scalar).
    fn walk_expr_tables(&mut self, expr: &Expr) {
        match expr {
            Expr::Subquery(s) => self.walk_query(s),
            Expr::InSubquery { subquery, .. } => self.walk_query(subquery),
            Expr::Exists { subquery, .. } => self.walk_query(subquery),
            Expr::BinaryOp { left, right, .. } => {
                self.walk_expr_tables(left);
                self.walk_expr_tables(right);
            }
            Expr::UnaryOp { expr, .. } => self.walk_expr_tables(expr),
            Expr::Nested(e) => self.walk_expr_tables(e),
            _ => {}
        }
    }

    fn finish(self) -> (Vec<TableRef>, Vec<TableRef>, bool) {
        (self.read.into_iter().collect(), Vec::new(), self.locking)
    }
}

fn classify_ast(
    stmt: &Statement,
    original_sql: &str,
) -> Result<ClassifiedStatement, ClassifyError> {
    let mut r = empty_result(SqlCategory::Read, "select");
    r.if_exists = stmt_if_exists(stmt);
    let lower = strip_comments(original_sql).to_ascii_lowercase();
    r.file_io = lower.contains("into outfile")
        || lower.contains("into dumpfile")
        || lower.contains("load data");

    match stmt {
        Statement::Query(q) => {
            r.category = SqlCategory::Read;
            r.ast_type = "select";
            let (read, _mutated, locking) = {
                let mut g = ObjectGraph::default();
                g.walk_query(q);
                g.finish()
            };
            r.read_tables = read;
            r.locking_read = locking;
        }
        Statement::Insert(insert) => {
            r.category = SqlCategory::Write;
            r.ast_type = if insert.replace_into {
                "replace"
            } else {
                "insert"
            };
            if let sqlparser::ast::TableObject::TableName(name) = &insert.table {
                let (db, table) = object_name_parts(name);
                r.mutated_tables.push(TableRef {
                    database: db,
                    table,
                });
            }
            if let Some(source) = &insert.source {
                let mut g = ObjectGraph::default();
                g.walk_query(source);
                let (read, _, _) = g.finish();
                r.read_tables = read;
            }
        }
        Statement::Update(update) => {
            r.category = SqlCategory::Write;
            r.ast_type = "update";
            // MySQL can mutate every table in the FROM list; authorize all
            // of them as mutations (strictest-wins then applies per table).
            let mut g = ObjectGraph::default();
            g.add_table_with_joins(&update.table);
            if let Some(from) = &update.from {
                match from {
                    sqlparser::ast::UpdateTableFromKind::BeforeSet(twjs)
                    | sqlparser::ast::UpdateTableFromKind::AfterSet(twjs) => {
                        for twj in twjs {
                            g.add_table_with_joins(twj);
                        }
                    }
                }
            }
            let (read, _, _) = g.finish();
            r.mutated_tables = read;
        }
        Statement::Delete(delete) => {
            r.category = SqlCategory::Write;
            r.ast_type = "delete";
            let mut g = ObjectGraph::default();
            walk_delete_sources(delete, &mut g);
            let (read, _, _) = g.finish();
            r.mutated_tables = read;
        }
        Statement::Truncate(trunc) => {
            r.category = SqlCategory::Ddl;
            r.ast_type = "truncate";
            for target in &trunc.table_names {
                let (db, table) = object_name_parts(&target.name);
                r.mutated_tables.push(TableRef {
                    database: db,
                    table,
                });
            }
        }
        Statement::CreateTable(create) => {
            r.category = SqlCategory::Ddl;
            r.ast_type = "create";
            let (db, table) = object_name_parts(&create.name);
            r.mutated_tables.push(TableRef {
                database: db,
                table,
            });
            if let Some(q) = &create.query {
                let mut g = ObjectGraph::default();
                g.walk_query(q);
                let (read, _, _) = g.finish();
                r.read_tables = read;
            }
        }
        Statement::Drop { names, .. } => {
            r.category = SqlCategory::Ddl;
            r.ast_type = "drop";
            for obj in names {
                let (db, table) = object_name_parts(obj);
                r.mutated_tables.push(TableRef {
                    database: db,
                    table,
                });
            }
        }
        Statement::AlterTable(alter) => {
            r.category = SqlCategory::Ddl;
            r.ast_type = "alter";
            let (db, table) = object_name_parts(&alter.name);
            r.mutated_tables.push(TableRef {
                database: db,
                table,
            });
        }
        Statement::RenameTable(renames) => {
            r.category = SqlCategory::Ddl;
            r.ast_type = "rename";
            for rn in renames {
                let (odb, otable) = object_name_parts(&rn.old_name);
                let (ndb, ntable) = object_name_parts(&rn.new_name);
                r.mutated_tables.push(TableRef {
                    database: odb,
                    table: otable,
                });
                r.mutated_tables.push(TableRef {
                    database: ndb,
                    table: ntable,
                });
            }
        }
        Statement::ShowTables { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowFunctions { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowColumns { .. } => {
            r.category = SqlCategory::Read;
            r.ast_type = "show";
        }
        Statement::ExplainTable { .. } => {
            // `DESCRIBE tbl` / `EXPLAIN tbl` / MySQL 8 `EXPLAIN ANALYZE
            // FOR CONNECTION`-style table describes are reads.
            r.category = SqlCategory::Read;
            r.ast_type = "describe";
        }
        Statement::Explain {
            statement: inner,
            analyze,
            ..
        } => {
            if *analyze {
                // EXPLAIN ANALYZE executes its wrapped statement.
                let mut inner = classify_ast(inner, original_sql)?;
                inner.executes_wrapped = true;
                return Ok(inner);
            }
            r.category = SqlCategory::Read;
            r.ast_type = "explain";
        }
        Statement::Grant { .. } => {
            r.category = SqlCategory::Admin;
            r.ast_type = "grant";
        }
        Statement::Revoke { .. } => {
            r.category = SqlCategory::Admin;
            r.ast_type = "revoke";
        }
        Statement::Set(_) => {
            r.category = SqlCategory::Admin;
            r.ast_type = "set";
        }
        other => {
            let name = variant_name(other);
            return Err(ClassifyError::Unknown(name));
        }
    }

    r.target_databases = {
        let mut dbs = BTreeSet::new();
        for t in r.read_tables.iter().chain(r.mutated_tables.iter()) {
            if let Some(db) = &t.database {
                dbs.insert(db.clone());
            }
        }
        dbs.into_iter().collect()
    };
    Ok(r)
}

fn walk_delete_sources(delete: &sqlparser::ast::Delete, g: &mut ObjectGraph) {
    match &delete.from {
        sqlparser::ast::FromTable::WithFromKeyword(twjs)
        | sqlparser::ast::FromTable::WithoutKeyword(twjs) => {
            for twj in twjs {
                g.add_table_with_joins(twj);
            }
        }
    }
    if let Some(using) = &delete.using {
        for twj in using {
            g.add_table_with_joins(twj);
        }
    }
    for t in &delete.tables {
        let (db, table) = object_name_parts(t);
        g.mutated_extra(db, table);
    }
}

impl ObjectGraph {
    fn mutated_extra(&mut self, db: Option<String>, table: String) {
        if self.cte_names.contains(&table) {
            return;
        }
        self.read.insert(TableRef {
            database: db,
            table,
        });
    }
}

/// Extract `IF EXISTS` from DROP/TRUNCATE statements.
fn stmt_if_exists(stmt: &Statement) -> bool {
    match stmt {
        Statement::Drop { if_exists, .. } => *if_exists,
        Statement::Truncate(t) => t.if_exists,
        _ => false,
    }
}

fn variant_name(stmt: &Statement) -> String {
    let debug = format!("{stmt:?}");
    debug
        .split('(')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(sql: &str, dialect: Dialect) -> Result<SqlCategory, ClassifyError> {
        classify_statement(sql, dialect).map(|c| c.category)
    }

    #[test]
    fn legacy_category_buckets() {
        let mysql = Dialect::MySql;
        assert_eq!(cat("SELECT 1", mysql).unwrap(), SqlCategory::Read);
        assert_eq!(
            cat(
                "SELECT u.id FROM users u JOIN orders o ON o.user_id = u.id",
                mysql
            )
            .unwrap(),
            SqlCategory::Read
        );
        assert_eq!(cat("SHOW TABLES", mysql).unwrap(), SqlCategory::Read);
        assert_eq!(cat("DESCRIBE users", mysql).unwrap(), SqlCategory::Read);
        assert_eq!(
            cat("EXPLAIN SELECT * FROM users", mysql).unwrap(),
            SqlCategory::Read
        );
        assert_eq!(
            cat(
                "WITH top AS (SELECT id FROM users ORDER BY id LIMIT 10) SELECT * FROM top",
                mysql
            )
            .unwrap(),
            SqlCategory::Read
        );
        assert_eq!(
            cat("INSERT INTO users (id, name) VALUES (1, 'a')", mysql).unwrap(),
            SqlCategory::Write
        );
        assert_eq!(
            cat("UPDATE users SET name = 'x' WHERE id = 1", mysql).unwrap(),
            SqlCategory::Write
        );
        assert_eq!(
            cat("DELETE FROM users WHERE id = 1", mysql).unwrap(),
            SqlCategory::Write
        );
        assert_eq!(
            cat("REPLACE INTO users (id, name) VALUES (1, 'a')", mysql).unwrap(),
            SqlCategory::Write
        );
        assert_eq!(
            cat("CREATE TABLE t1 (id INT PRIMARY KEY)", mysql).unwrap(),
            SqlCategory::Ddl
        );
        assert_eq!(cat("DROP TABLE users", mysql).unwrap(), SqlCategory::Ddl);
        assert_eq!(
            cat("ALTER TABLE users ADD COLUMN email TEXT", mysql).unwrap(),
            SqlCategory::Ddl
        );
        assert_eq!(
            cat("TRUNCATE TABLE users", mysql).unwrap(),
            SqlCategory::Ddl
        );
        assert_eq!(cat("RENAME TABLE a TO b", mysql).unwrap(), SqlCategory::Ddl);
        assert_eq!(cat("BEGIN", mysql).unwrap(), SqlCategory::TxCtrl);
        assert_eq!(cat("COMMIT", mysql).unwrap(), SqlCategory::TxCtrl);
        assert_eq!(cat("ROLLBACK", mysql).unwrap(), SqlCategory::TxCtrl);
        assert_eq!(
            cat("START TRANSACTION", mysql).unwrap(),
            SqlCategory::TxCtrl
        );
        assert_eq!(cat("SAVEPOINT sp1", mysql).unwrap(), SqlCategory::TxCtrl);
        assert_eq!(
            cat("RELEASE SAVEPOINT sp1", mysql).unwrap(),
            SqlCategory::TxCtrl
        );
        assert_eq!(
            cat("GRANT ALL ON *.* TO 'x'@'localhost'", mysql).unwrap(),
            SqlCategory::Admin
        );
        assert_eq!(
            cat("SET GLOBAL max_connections = 100", mysql).unwrap(),
            SqlCategory::Admin
        );
        assert_eq!(cat("KILL 42", mysql).unwrap(), SqlCategory::Admin);
        assert_eq!(cat("FLUSH TABLES", mysql).unwrap(), SqlCategory::Admin);
        assert_eq!(cat("VACUUM", mysql).unwrap(), SqlCategory::Admin);
        assert_eq!(
            cat("ATTACH DATABASE '/tmp/o.db' AS other", mysql).unwrap(),
            SqlCategory::Admin
        );
        assert_eq!(cat("SET @x = 1", mysql).unwrap(), SqlCategory::Admin);
    }

    #[test]
    fn rejections() {
        let mysql = Dialect::MySql;
        assert!(matches!(
            classify_statement("SELECT 1; SELECT 2", mysql).unwrap_err(),
            ClassifyError::MultipleStatements
        ));
        assert!(matches!(
            classify_statement("", mysql).unwrap_err(),
            ClassifyError::Empty
        ));
        assert!(matches!(
            classify_statement("   ", mysql).unwrap_err(),
            ClassifyError::Empty
        ));
        assert!(matches!(
            classify_statement("-- just a comment", mysql).unwrap_err(),
            ClassifyError::CommentOnly
        ));
        assert!(matches!(
            classify_statement("SELECT ';' FROM t", mysql).unwrap(),
            classified if classified.category == SqlCategory::Read
        ));
        assert!(classify_statement("garbage not sql ((", mysql).is_err());
    }

    #[test]
    fn sqlite_pragmas() {
        let sqlite = Dialect::SQLite;
        assert_eq!(
            cat("PRAGMA table_info(users)", sqlite).unwrap(),
            SqlCategory::Read
        );
        assert_eq!(
            cat("PRAGMA main.table_info(users)", sqlite).unwrap(),
            SqlCategory::Read
        );
        assert_eq!(
            cat("PRAGMA integrity_check", sqlite).unwrap(),
            SqlCategory::Read
        );
        assert_eq!(
            cat("PRAGMA user_version = 7", sqlite).unwrap(),
            SqlCategory::Admin
        );
        assert_eq!(
            cat("PRAGMA journal_mode = WAL", sqlite).unwrap(),
            SqlCategory::Admin
        );
        assert_eq!(
            cat("PRAGMA unknown_thing", sqlite).unwrap(),
            SqlCategory::Admin
        );
    }

    #[test]
    fn objects_and_flags() {
        let mysql = Dialect::MySql;
        let c = classify_statement(
            "SELECT * FROM app.users WHERE id IN (SELECT uid FROM analytics.events)",
            mysql,
        )
        .unwrap();
        assert_eq!(c.read_tables.len(), 2);
        assert!(c.read_tables.contains(&TableRef {
            database: Some("app".into()),
            table: "users".into()
        }));
        assert!(c.read_tables.contains(&TableRef {
            database: Some("analytics".into()),
            table: "events".into()
        }));
        assert_eq!(
            c.target_databases,
            vec!["analytics".to_string(), "app".to_string()]
        );

        let c = classify_statement("SELECT * FROM users FOR UPDATE", mysql).unwrap();
        assert!(c.locking_read);

        let c = classify_statement("SELECT * FROM users INTO OUTFILE '/tmp/x'", mysql).unwrap();
        assert!(c.file_io);

        let c = classify_statement("LOAD DATA INFILE '/tmp/x' INTO TABLE users", mysql).unwrap();
        assert_eq!(c.category, SqlCategory::Admin);
        assert!(c.file_io);

        let c = classify_statement(
            "INSERT INTO app.jobs (id) SELECT id FROM staging.users",
            mysql,
        )
        .unwrap();
        assert_eq!(
            c.mutated_tables,
            vec![TableRef {
                database: Some("app".into()),
                table: "jobs".into()
            }]
        );
        assert_eq!(
            c.read_tables,
            vec![TableRef {
                database: Some("staging".into()),
                table: "users".into()
            }]
        );

        // Multi-table UPDATE: every joined table is a mutation target.
        let c = classify_statement(
            "UPDATE app.jobs JOIN app.users ON app.users.id = app.jobs.user_id SET app.jobs.state = 'ok'",
            mysql,
        )
        .unwrap();
        assert_eq!(c.mutated_tables.len(), 2);

        let c = classify_statement(
            "DELETE a FROM a JOIN b ON a.id = b.id WHERE b.flag = 1",
            mysql,
        )
        .unwrap();
        assert!(c.mutated_tables.iter().any(|t| t.table == "a"));
        assert!(c.mutated_tables.iter().any(|t| t.table == "b"));

        // CTE names are not tables.
        let c = classify_statement(
            "WITH top AS (SELECT id FROM users ORDER BY id LIMIT 10) SELECT * FROM top",
            mysql,
        )
        .unwrap();
        assert_eq!(c.read_tables.len(), 1);
        assert_eq!(c.read_tables[0].table, "users");

        let c = classify_statement("EXPLAIN ANALYZE SELECT * FROM users", mysql).unwrap();
        assert!(c.executes_wrapped);
        assert_eq!(c.category, SqlCategory::Read);
    }

    /// Differential check against the legacy fixture corpus: categories and
    /// target databases must match for every case the legacy classifier
    /// accepted; error classes must match for structural errors.
    #[test]
    fn matches_legacy_classifier_fixtures() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy/classifier.json"
        );
        let data = std::fs::read_to_string(path).expect("fixtures present");
        let cases: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
        let mut checked = 0;
        // Legacy parser limitations the Rust parser deliberately improves on:
        // these statements failed to parse under node-sql-parser.
        let legacy_parse_failures = [
            "EXPLAIN ANALYZE SELECT * FROM users",
            "UPDATE app.jobs JOIN app.users ON app.users.id = app.jobs.user_id SET app.jobs.state = 'ok'",
        ];
        for case in cases {
            let sql = case["sql"].as_str().unwrap();
            let dialect = match case["dialect"].as_str().unwrap() {
                "sqlite" => Dialect::SQLite,
                _ => Dialect::MySql,
            };
            let legacy = &case["result"];
            let ours = classify_statement(sql, dialect);
            if legacy_parse_failures.contains(&sql) {
                continue;
            }
            if legacy["ok"].as_bool().unwrap_or(false) {
                let c = ours.unwrap_or_else(|e| panic!("rust rejected {sql:?}: {e:?}"));
                assert_eq!(
                    c.category.as_str(),
                    legacy["category"].as_str().unwrap(),
                    "category mismatch for {sql:?}"
                );
                let want_dbs: Vec<&str> = legacy["targetDatabases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                let got_dbs: Vec<&str> = c.target_databases.iter().map(String::as_str).collect();
                assert_eq!(got_dbs, want_dbs, "databases mismatch for {sql:?}");
                checked += 1;
            } else {
                // Structural errors must match; parser message texts differ
                // by design (different parser).
                let err_msg = legacy["error"].as_str().unwrap_or_default();
                let structural = err_msg.starts_with("multiple statements")
                    || err_msg.starts_with("empty input")
                    || err_msg.starts_with("input contains only comments");
                if structural {
                    let e = ours.expect_err("rust accepted what legacy structurally rejected");
                    let msg = e.message();
                    assert!(
                        msg.starts_with(&err_msg[..err_msg.len().min(30)]),
                        "{sql:?}: {msg}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 100, "fixture coverage collapsed: {checked}");
    }
}
