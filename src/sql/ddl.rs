//! DDL semantics (D4): protection modelling and absent-target preflight.
//!
//! DDL in MySQL/MariaDB commonly performs an implicit commit, so a
//! preceding backup transaction cannot be atomic with the DDL itself.
//! DDL protection is therefore modelled as **a durable pre-operation
//! snapshot with explicit nontransactional warnings** — never as
//! transactional DML protection. Absent targets are resolved by preflight
//! (existence checked with bound parameters) instead of converting
//! `ER_NO_SUCH_TABLE` at backup time into "empty backup, proceed".

use mysql_async::Conn;
use mysql_async::prelude::Queryable;
use thiserror::Error;

/// How a statement's backup/protection guarantee is modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionModel {
    /// START TRANSACTION → lock+capture pre-image → durable backup →
    /// mutation → COMMIT all on one physical connection; rollback-grade
    /// protection.
    TransactionalDmlProtection,
    /// Durable pre-operation snapshot persisted BEFORE the DDL; implicit
    /// commit may occur; snapshot and DDL are not one atomic transaction;
    /// automatic rollback is not guaranteed.
    NonTransactionalDdlSnapshot,
    /// No protection can be provided (nontransactional engine, unresolved
    /// targets, or an unrewritable backup query) — deny by default.
    UnprotectedDenied,
}

impl ProtectionModel {
    /// Warnings that must appear in the operation plan, confirmation, and
    /// audit event for this protection model.
    pub fn warnings(&self) -> &'static [&'static str] {
        match self {
            ProtectionModel::TransactionalDmlProtection => &[],
            ProtectionModel::NonTransactionalDdlSnapshot => &[
                "pre-operation snapshot only",
                "implicit commit may occur",
                "snapshot and DDL are not one atomic transaction",
                "automatic rollback is not guaranteed",
            ],
            ProtectionModel::UnprotectedDenied => &["no backup protection can be guaranteed"],
        }
    }

    pub fn is_transactional(&self) -> bool {
        matches!(self, ProtectionModel::TransactionalDmlProtection)
    }
}

/// Map a classified statement to its protection model. DDL categories get
/// snapshot semantics; writes get transactional semantics when a backup is
/// captured (or none is required); everything else is by definition not a
/// mutation.
pub fn protection_model_for(
    category: crate::policy::model::SqlCategory,
    ast_type: &str,
) -> ProtectionModel {
    use crate::policy::model::SqlCategory;
    match category {
        SqlCategory::Ddl => ProtectionModel::NonTransactionalDdlSnapshot,
        SqlCategory::Write => {
            if crate::backup::extractor::is_backup_required(ast_type) {
                ProtectionModel::TransactionalDmlProtection
            } else {
                // Writes without a backup strategy (e.g. classified but
                // unhandled forms) still execute in one transaction.
                ProtectionModel::TransactionalDmlProtection
            }
        }
        _ => ProtectionModel::TransactionalDmlProtection,
    }
}

#[derive(Debug, Clone, Error, PartialEq)]
pub enum DdlPreflightError {
    #[error("table {schema}.{table} does not exist: {hint}")]
    NotFound {
        schema: String,
        table: String,
        hint: &'static str,
    },
    #[error("preflight query failed: {0}")]
    Query(String),
}

/// Result of checking DDL targets for existence before execution.
#[derive(Debug, Clone, PartialEq)]
pub enum DdlPreflight {
    /// All mutated targets exist; proceed with snapshot + DDL.
    Present,
    /// All mutated targets are missing AND the statement says IF EXISTS:
    /// audited local no-op — no DDL is sent to the server.
    MissingNoOp(Vec<(String, String)>),
    /// A target is missing without IF EXISTS: typed not-found error.
    NotFound(DdlPreflightError),
}

/// Check every mutated table of a DDL statement for existence using
/// `information_schema.tables` with bound parameters. `fallback_db`
/// resolves unqualified names (connection default).
pub async fn preflight_ddl(
    conn: &mut Conn,
    classified: &crate::policy::classifier::ClassifiedStatement,
    fallback_db: Option<&str>,
) -> Result<DdlPreflight, DdlPreflightError> {
    use crate::policy::model::SqlCategory;
    if classified.category != SqlCategory::Ddl || classified.mutated_tables.is_empty() {
        return Ok(DdlPreflight::Present);
    }

    let mut missing: Vec<(String, String)> = Vec::new();
    for (idx, target) in classified.mutated_tables.iter().enumerate() {
        // RENAME statements list old and new identities per pair (old,
        // new, old, new, ...). Only the OLD identity must exist; the new
        // one is created by the rename itself.
        if classified.ast_type == "rename" && idx % 2 == 1 {
            continue;
        }
        // CREATE statements create their target: absence is expected, not
        // an error; presence is a replace, also fine. Skip existence
        // gating for `create` entirely.
        if classified.ast_type == "create" {
            return Ok(DdlPreflight::Present);
        }
        let schema = target
            .database
            .clone()
            .or_else(|| fallback_db.map(str::to_string));
        let Some(schema) = schema else {
            // Unresolved schema scope: fail closed via the not-found path
            // with a hint (the gate denies unqualified targets anyway).
            return Err(DdlPreflightError::NotFound {
                schema: "?".into(),
                table: target.table.clone(),
                hint: "no database in scope for the DDL target",
            });
        };
        let exists: Option<i8> = conn
            .exec_first(
                "SELECT 1 FROM information_schema.tables
                  WHERE table_schema = ? AND table_name = ?",
                (&schema, &target.table),
            )
            .await
            .map_err(|e| DdlPreflightError::Query(e.to_string()))?;
        if exists.is_none() {
            missing.push((schema, target.table.clone()));
        }
    }

    if missing.is_empty() {
        return Ok(DdlPreflight::Present);
    }
    if classified.if_exists {
        Ok(DdlPreflight::MissingNoOp(missing))
    } else {
        let (schema, table) = missing[0].clone();
        Err(DdlPreflightError::NotFound {
            schema,
            table,
            hint: "DROP/TRUNCATE target does not exist (no IF EXISTS)",
        })
    }
}
