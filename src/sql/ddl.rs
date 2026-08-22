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
    #[error("table {schema}.{table} already exists: {hint}")]
    Conflict {
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
    /// Some targets exist and some are missing under IF EXISTS: execute
    /// ONLY the preflight-approved existing subset — as a REWRITTEN
    /// statement naming exactly those targets (never the original
    /// multi-target statement, which would also drop any target created
    /// between preflight and execution); the missing list must be audited
    /// as absent (never silently suppressed).
    Mixed {
        existing: Vec<(String, String)>,
        missing: Vec<(String, String)>,
    },
}

/// Build the fail-closed rewrite of a Mixed multi-target DROP: only the
/// preflight-approved existing targets, fully qualified, backtick-escaped,
/// with IF EXISTS retained. Returns `None` for object types whose drop
/// cannot be safely reconstructed (`DROP INDEX` and friends) — the caller
/// fails closed in that case. This closes the plan→execute TOCTOU: a
/// table created after the preflight is not named by the rewritten
/// statement, so it cannot be dropped without a fresh plan and approval.
pub fn rewrite_drop_subset(object_type: &str, existing: &[(String, String)]) -> Option<String> {
    let keyword = match object_type {
        "table" => "DROP TABLE IF EXISTS",
        "view" => "DROP VIEW IF EXISTS",
        _ => return None,
    };
    if existing.is_empty() {
        return None;
    }
    let targets = existing
        .iter()
        .map(|(schema, table)| {
            format!(
                "`{}`.`{}`",
                schema.replace('`', "``"),
                table.replace('`', "``")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!("{keyword} {targets}"))
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

    let resolve_schema = |target: &crate::policy::classifier::TableRef| -> Option<String> {
        target
            .database
            .clone()
            .or_else(|| fallback_db.map(str::to_string))
    };

    async fn table_exists(
        conn: &mut Conn,
        schema: &str,
        table: &str,
    ) -> Result<bool, DdlPreflightError> {
        let found: Option<i8> = conn
            .exec_first(
                "SELECT 1 FROM information_schema.tables
                  WHERE table_schema = ? AND table_name = ?",
                (schema, table),
            )
            .await
            .map_err(|e| DdlPreflightError::Query(e.to_string()))?;
        Ok(found.is_some())
    }

    match classified.ast_type {
        // CREATE statements create their targets: existence is not an
        // error either way; skip gating entirely.
        "create" => Ok(DdlPreflight::Present),

        // RENAME chains execute left-to-right. Model the chain locally:
        // each source must exist (after earlier steps), each destination
        // must be absent (after earlier steps) — this correctly allows
        // swap chains (a→tmp, b→a, tmp→b).
        "rename" => {
            let pairs: Vec<(
                &crate::policy::classifier::TableRef,
                &crate::policy::classifier::TableRef,
            )> = classified
                .mutated_tables
                .chunks(2)
                .map(|c| (&c[0], &c[1]))
                .collect();
            let mut known: Vec<((String, String), bool)> = Vec::new();
            for (src, dst) in &pairs {
                let src_schema = resolve_schema(src).ok_or(DdlPreflightError::NotFound {
                    schema: "?".into(),
                    table: src.table.clone(),
                    hint: "no database in scope for the RENAME source",
                })?;
                let dst_schema = resolve_schema(dst).ok_or(DdlPreflightError::NotFound {
                    schema: "?".into(),
                    table: dst.table.clone(),
                    hint: "no database in scope for the RENAME destination",
                })?;
                let src_id = (src_schema.clone(), src.table.clone());
                let dst_id = (dst_schema.clone(), dst.table.clone());

                // Source present? (chain-aware: earlier renames move ids)
                let src_present =
                    if let Some(p) = known.iter().find(|(id, _p)| *id == src_id).map(|(_, p)| *p) {
                        p
                    } else {
                        table_exists(conn, &src_schema, &src.table).await?
                    };
                if !src_present {
                    return Err(DdlPreflightError::NotFound {
                        schema: src_schema,
                        table: src.table.clone(),
                        hint: "RENAME source does not exist",
                    });
                }

                // Destination absent? (chain-aware)
                let dst_present =
                    if let Some(p) = known.iter().find(|(id, _p)| *id == dst_id).map(|(_, p)| *p) {
                        p
                    } else {
                        table_exists(conn, &dst_schema, &dst.table).await?
                    };
                if dst_present {
                    return Err(DdlPreflightError::Conflict {
                        schema: dst_schema,
                        table: dst.table.clone(),
                        hint: "RENAME destination already exists",
                    });
                }

                known.retain(|(id, _)| *id != src_id);
                known.push((src_id, false));
                known.push((dst_id, true));
            }
            Ok(DdlPreflight::Present)
        }

        // DROP / TRUNCATE: multi-target normalization across engines.
        // Without IF EXISTS: ANY missing target → typed not-found, nothing
        // executed (stricter than MariaDB's partial behaviour, matching
        // MySQL 8.4). With IF EXISTS: all missing → audited no-op; some
        // missing → proceed on the existing complete approved set with the
        // absent list attached for audit.
        _ => {
            let mut existing: Vec<(String, String)> = Vec::new();
            let mut missing: Vec<(String, String)> = Vec::new();
            for target in &classified.mutated_tables {
                let schema = resolve_schema(target).ok_or(DdlPreflightError::NotFound {
                    schema: "?".into(),
                    table: target.table.clone(),
                    hint: "no database in scope for the DDL target",
                })?;
                if table_exists(conn, &schema, &target.table).await? {
                    existing.push((schema, target.table.clone()));
                } else {
                    missing.push((schema, target.table.clone()));
                }
            }
            if missing.is_empty() {
                return Ok(DdlPreflight::Present);
            }
            if !classified.if_exists {
                let (schema, table) = missing[0].clone();
                return Err(DdlPreflightError::NotFound {
                    schema,
                    table,
                    hint: "DDL target does not exist (no IF EXISTS)",
                });
            }
            if existing.is_empty() {
                Ok(DdlPreflight::MissingNoOp(missing))
            } else {
                Ok(DdlPreflight::Mixed { existing, missing })
            }
        }
    }
}
