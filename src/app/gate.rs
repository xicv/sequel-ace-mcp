//! The operation gate: the single execution authority shared by MCP tools,
//! CLI commands and (future) GUI actions.
//!
//! Pipeline: resolve connection → classify → two-layer policy → Touch ID
//! (fail closed) → approval (elicitation/IPC; unavailable ⇒ fail closed) →
//! revalidate → execute → audit.

use crate::approval::digest::{OperationDigestInput, canonical_sql, operation_digest};
use crate::approval::{ApprovalEngine, ConfirmOutcome, GrantChoice, SessionGrantKey};
use crate::audit::{AuditDb, AuditEntry, WriteOptions};
use crate::config::{Config, ConfigStore, Connection};
use crate::policy::classifier::{self, ClassifiedStatement, Dialect};
use crate::policy::model::{PolicyAction, SqlCategory, TableId};
use crate::policy::resolver::{self, Resolution};
use crate::sql::sqlite::{self, SqliteExecuteParams};
use crate::vault::touchid::SessionAuthenticator;
use serde_json::json;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum GateError {
    #[error("{0}")]
    NoConnection(String),
    #[error("cannot run statement: {0}")]
    Classify(String),
    #[error(
        "query tool only accepts read statements (got {0}). Use the \"execute\" tool for non-read statements."
    )]
    NotReadOnly(SqlCategory),
    #[error("denied by policy: {0}")]
    Denied(String),
    #[error("Touch ID authentication failed")]
    TouchIdFailed,
    #[error("confirmation for {0} statement was declined")]
    Declined(SqlCategory),
    #[error(
        "confirmation required for {0} statement, but no prompt could be shown: {1}. Statement not executed - nothing was changed. This is not a refusal: the prompt could not be delivered."
    )]
    Unavailable(SqlCategory, String),
    #[error("approval expired before execution")]
    Expired,
    #[error("SQL execution failed: {0}")]
    Execution(String),
    #[error(
        "no password stored for connection {0:?}. Run add_connection or import_from_sequel_ace first."
    )]
    NoPassword(String),
    #[error("MySQL execution is not wired in this build: {0}")]
    MySql(String),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
}

/// Where approvals are sought.
pub trait ApprovalSink: Send + Sync {
    fn confirm(&self, request: ApprovalRequest) -> ConfirmOutcome;
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub category: SqlCategory,
    pub statement_snippet: String,
    pub connection_name: String,
    pub database: Option<String>,
    pub tables: Vec<TableId>,
}

/// Sink used when no interactive surface exists. Fails closed and reports
/// the real reason — never fabricates a refusal.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableSink;

impl ApprovalSink for UnavailableSink {
    fn confirm(&self, _request: ApprovalRequest) -> ConfirmOutcome {
        ConfirmOutcome::Unavailable {
            reason: "no approval channel is available in this context".into(),
        }
    }
}

pub struct GateDeps {
    pub config: Arc<ConfigStore>,
    pub audit: Arc<AuditDb>,
    pub approvals: Arc<ApprovalEngine>,
    pub auth: Arc<SessionAuthenticator>,
    pub sink: Box<dyn ApprovalSink>,
    #[allow(dead_code)]
    pub secrets: Arc<dyn crate::vault::keychain::SecretStore>,
}

impl GateDeps {
    pub fn with_sink(sink: Box<dyn ApprovalSink>) -> Self {
        Self {
            config: Arc::new(ConfigStore::new()),
            audit: AuditDb::shared(),
            approvals: Arc::new(ApprovalEngine::new()),
            auth: Arc::new(SessionAuthenticator::new(
                crate::vault::touchid::system_touch_id(),
            )),
            sink,
            secrets: crate::vault::keychain::default_store(),
        }
    }
}

pub struct RunSqlArgs {
    pub connection: Option<String>,
    pub sql: String,
    pub database: Option<String>,
    /// Plan-time approved DDL target set carried from an MRTR approval
    /// (plan→retry gap enforcement); `None` for single-shot execution.
    pub expected_ddl_targets: Option<Vec<(String, String)>>,
}

#[derive(Debug)]
pub struct RunOutcome {
    pub connection: String,
    pub category: SqlCategory,
    pub ast_type: String,
    pub resolution: Resolution,
    pub rows: Vec<serde_json::Value>,
    pub fields: Vec<String>,
    pub affected_rows: u64,
    pub truncated: bool,
    pub duration_ms: u64,
    pub backup_id: Option<i64>,
    pub backup_row_count: u64,
    pub request_id: String,
    /// DDL absent-target no-op (IF EXISTS over missing tables): nothing
    /// was sent to the server (D4).
    pub ddl_no_op: bool,
    /// Targets absent under IF EXISTS in a Mixed set (recorded, never
    /// suppressed); empty unless a Mixed DROP occurred.
    pub ddl_absent_targets: Vec<String>,
    /// Targets actually named by the rewritten Mixed DROP statement
    /// (the preflight-approved existing subset); empty otherwise.
    pub ddl_executed_targets: Vec<String>,
    /// Protection-model warnings (nontransactional DDL snapshot).
    pub warnings: Vec<&'static str>,
}

fn dialect_for(conn: &Connection) -> Dialect {
    if conn.is_mysql() {
        Dialect::MySql
    } else {
        Dialect::SQLite
    }
}

fn resolve_table_ids(classified: &ClassifiedStatement, fallback: Option<&str>) -> Vec<TableId> {
    let mut out: Vec<TableId> = Vec::new();
    for t in classified
        .read_tables
        .iter()
        .chain(classified.mutated_tables.iter())
    {
        let db = t.database.clone().or_else(|| fallback.map(str::to_string));
        if let Some(db) = db {
            let id = TableId {
                database: db,
                table: t.table.clone(),
            };
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

/// The single statement pipeline. `expect_read_only` rejects non-read
/// categories before any policy work (legacy `query` behaviour).
pub fn run_sql(
    deps: &GateDeps,
    args: &RunSqlArgs,
    expect_read_only: bool,
) -> Result<RunOutcome, GateError> {
    let cfg: Config = deps.config.load()?;
    let conn = cfg
        .resolve(args.connection.as_deref())
        .cloned()
        .ok_or_else(|| {
            GateError::NoConnection(no_connection_message(args.connection.as_deref()))
        })?;

    let dialect = dialect_for(&conn);
    let classified = classifier::classify_statement(&args.sql, dialect)
        .map_err(|e| GateError::Classify(e.message()))?;

    if expect_read_only && classified.category != SqlCategory::Read {
        return Err(GateError::NotReadOnly(classified.category));
    }

    let fallback = args
        .database
        .clone()
        .or_else(|| conn.database().map(str::to_string));
    let resolution = resolver::resolve(&conn, &classified, fallback.as_deref());

    let request_id = Uuid::new_v4().to_string();
    let databases_for_log: Vec<String> = if !classified.target_databases.is_empty() {
        classified.target_databases.clone()
    } else {
        fallback.clone().into_iter().collect()
    };

    let write_opts = WriteOptions {
        redact_sql_in_log: cfg.retention.redact_sql_in_log,
        tamper_evident_chain: cfg.retention.tamper_evident_chain,
    };

    // Policy decision + approval.
    let mut approval_scope: Option<String> = None;
    let mut approval_digest: Option<[u8; 32]> = None;
    match resolution.action {
        PolicyAction::Deny => {
            audit(
                deps,
                &request_id,
                &conn,
                &databases_for_log,
                &classified,
                &args.sql,
                &resolution,
                false,
                crate::approval::outcomes::ApprovalOutcome::Denied,
                None,
                None,
                None,
                None,
                &write_opts,
            );
            let hint = resolution
                .contributions
                .iter()
                .map(|c| format!("{}.{}", c.table.database, c.table.table))
                .next()
                .map(|t| format!(" ({t})"))
                .unwrap_or_default();
            return Err(GateError::Denied(format!(
                "{} statements not allowed on {:?}{}.",
                classified.category.as_str(),
                conn.name(),
                hint
            )));
        }
        PolicyAction::Allow => {}
        PolicyAction::Confirm => {
            // Touch ID first (fail closed).
            if resolution.effective.require_touch_id {
                let ok = deps.auth.ensure_authenticated(&format!(
                    "Authenticate to run {} on {}",
                    classified.category.as_str(),
                    conn.name()
                ));
                if !ok {
                    audit(
                        deps,
                        &request_id,
                        &conn,
                        &databases_for_log,
                        &classified,
                        &args.sql,
                        &resolution,
                        false,
                        crate::approval::outcomes::ApprovalOutcome::Denied,
                        None,
                        None,
                        None,
                        None,
                        &write_opts,
                    );
                    return Err(GateError::TouchIdFailed);
                }
            }

            let tables = resolve_table_ids(&classified, fallback.as_deref());
            // Narrow session grant first (exact table set + category).
            let session_key = SessionGrantKey {
                connection: conn.name().to_string(),
                category: classified.category,
                tables: tables.clone(),
            };
            if deps.approvals.session_covers(&session_key) {
                approval_scope = Some("session".to_string());
            } else {
                let snippet = if args.sql.len() > 800 {
                    format!("{}…", &args.sql[..800])
                } else {
                    args.sql.clone()
                };
                let outcome = deps.sink.confirm(ApprovalRequest {
                    category: classified.category,
                    statement_snippet: snippet,
                    connection_name: conn.name().to_string(),
                    database: databases_for_log.first().cloned(),
                    tables: tables.clone(),
                });
                match outcome {
                    ConfirmOutcome::Unavailable { reason } => {
                        audit(
                            deps,
                            &request_id,
                            &conn,
                            &databases_for_log,
                            &classified,
                            &args.sql,
                            &resolution,
                            false,
                            crate::approval::outcomes::ApprovalOutcome::Unavailable,
                            None,
                            None,
                            None,
                            Some(&reason),
                            &write_opts,
                        );
                        return Err(GateError::Unavailable(classified.category, reason));
                    }
                    ConfirmOutcome::Chosen(GrantChoice::Decline) => {
                        audit(
                            deps,
                            &request_id,
                            &conn,
                            &databases_for_log,
                            &classified,
                            &args.sql,
                            &resolution,
                            false,
                            crate::approval::outcomes::ApprovalOutcome::Declined,
                            None,
                            None,
                            None,
                            None,
                            &write_opts,
                        );
                        return Err(GateError::Declined(classified.category));
                    }
                    ConfirmOutcome::Chosen(GrantChoice::Session) => {
                        deps.approvals.grant_session(session_key);
                        approval_scope = Some("session".to_string());
                    }
                    ConfirmOutcome::Chosen(GrantChoice::Once) => {
                        let canon = canonical_sql(&args.sql, dialect);
                        let nonce = crate::approval::random_nonce_32();
                        let digest = operation_digest(&OperationDigestInput {
                            connection: conn.name(),
                            driver: if conn.is_mysql() { "mysql" } else { "sqlite" },
                            database: fallback.as_deref(),
                            read_tables: &classified.read_tables,
                            mutated_tables: &classified.mutated_tables,
                            category: classified.category,
                            canonical_sql: &canon,
                            parameter_hashes: &[],
                            backup_plan_identity: None,
                            policy_revision: cfg.revision,
                            metadata_revision: 0,
                            nonce: *nonce,
                        });
                        deps.approvals.grant_once(digest);
                        approval_digest = Some(digest);
                        approval_scope = Some("once".to_string());
                    }
                }
            }
        }
    }

    // Revalidate: the policy may have changed since resolution began.
    let cfg2: Config = deps.config.load()?;
    if cfg2.revision != cfg.revision {
        let conn2 = cfg2
            .resolve(args.connection.as_deref())
            .cloned()
            .ok_or_else(|| {
                GateError::NoConnection(no_connection_message(args.connection.as_deref()))
            })?;
        let resolution2 = resolver::resolve(&conn2, &classified, fallback.as_deref());
        if resolution2.action != resolution.action {
            audit(
                deps,
                &request_id,
                &conn,
                &databases_for_log,
                &classified,
                &args.sql,
                &resolution,
                false,
                crate::approval::outcomes::ApprovalOutcome::Denied,
                approval_scope.as_deref(),
                approval_digest,
                Some(cfg2.revision),
                None,
                &write_opts,
            );
            return Err(GateError::Denied(
                "policy changed during approval; re-run the statement".into(),
            ));
        }
    }

    // Consume the one-time approval atomically (expiry fails closed).
    if let Some(digest) = approval_digest
        && deps.approvals.consume_once(digest).is_err()
    {
        return Err(GateError::Expired);
    }

    // Execute.
    let started = std::time::Instant::now();
    let exec_result: Result<crate::sql::sqlite::ExecuteResult, String> = match &conn {
        Connection::Sqlite(sc) => sqlite::execute_sqlite_statement(SqliteExecuteParams {
            connection: sc,
            sql: &args.sql,
            classified: &classified,
            policy: &resolution.effective,
            database: args.database.as_deref(),
            audit: Some(deps.audit.clone()),
        })
        .map_err(|e| e.to_string()),
        Connection::Mysql(mc) => {
            // MySQL is async; the gate runs on the blocking pool, so
            // block_on the runtime handle from here.
            let password = match deps.secrets.get_password(&mc.name, &mc.user) {
                Ok(p) => p,
                Err(_) => {
                    audit(
                        deps,
                        &request_id,
                        &conn,
                        &databases_for_log,
                        &classified,
                        &args.sql,
                        &resolution,
                        false,
                        crate::approval::outcomes::ApprovalOutcome::Denied,
                        approval_scope.as_deref(),
                        approval_digest,
                        Some(cfg.revision),
                        None,
                        &write_opts,
                    );
                    return Err(GateError::NoPassword(mc.name.clone()));
                }
            };
            let db = args.database.clone();
            let audit = deps.audit.clone();
            let revision = cfg.revision;
            let sql = args.sql.clone();
            let expected_ddl = args.expected_ddl_targets.clone();
            let tunnel_endpoint: Option<(String, u16)> = None; // SSH runtime pending
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    crate::sql::mysql::execute_mysql_statement(
                        crate::sql::mysql::MySqlExecuteParams {
                            connection: mc,
                            request_id: request_id.clone(),
                            databases_for_log: databases_for_log.clone(),
                            password,
                            sql: &sql,
                            classified: &classified,
                            policy: &resolution.effective,
                            database: db.as_deref(),
                            audit: Some(audit),
                            revision,
                            tunnel_endpoint,
                            expected_ddl_targets: expected_ddl,
                        },
                    )
                    .await
                })
            });
            res.map(|r| crate::sql::sqlite::ExecuteResult {
                journal_id: r.journal_id,
                ddl_no_op: r.ddl_no_op,
                ddl_absent_targets: r.ddl_absent_targets,
                ddl_executed_targets: r.ddl_executed_targets,
                warnings: r.warnings,
                rows: r.rows,
                fields: r.fields,
                affected_rows: r.affected_rows,
                truncated: r.truncated,
                duration_ms: r.duration_ms,
                backup_id: r.backup_id,
                backup_row_count: r.backup_row_count,
            })
            .map_err(|e| e.to_string())
        }
    };

    match exec_result {
        Ok(r) => {
            audit(
                deps,
                &request_id,
                &conn,
                &databases_for_log,
                &classified,
                &args.sql,
                &resolution,
                resolution.action == PolicyAction::Confirm,
                crate::approval::outcomes::ApprovalOutcome::Approved,
                approval_scope.as_deref(),
                approval_digest,
                Some(cfg.revision),
                None,
                &write_opts,
            );
            // D3: the audit row is durable, so the operation journal can
            // close out (mutation_committed -> audit_finalized).
            if let Some(jid) = r.journal_id {
                let j = crate::backup::journal::Journal::from_id(&deps.audit, jid);
                let _ = j.transition(crate::backup::journal::JournalState::AuditFinalized, None);
            }
            Ok(RunOutcome {
                connection: conn.name().to_string(),
                category: classified.category,
                ast_type: classified.ast_type.to_string(),
                resolution,
                rows: r.rows,
                fields: r.fields,
                affected_rows: r.affected_rows,
                truncated: r.truncated,
                duration_ms: r.duration_ms.max(started.elapsed().as_millis() as u64),
                backup_id: r.backup_id,
                backup_row_count: r.backup_row_count,
                ddl_no_op: r.ddl_no_op,
                ddl_absent_targets: r.ddl_absent_targets,
                ddl_executed_targets: r.ddl_executed_targets,
                warnings: r.warnings,
                request_id,
            })
        }
        Err(e) => {
            audit(
                deps,
                &request_id,
                &conn,
                &databases_for_log,
                &classified,
                &args.sql,
                &resolution,
                resolution.action == PolicyAction::Confirm,
                crate::approval::outcomes::ApprovalOutcome::ExecutionError,
                approval_scope.as_deref(),
                approval_digest,
                Some(cfg.revision),
                Some(&e),
                &write_opts,
            );
            Err(GateError::Execution(e))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn audit(
    deps: &GateDeps,
    request_id: &str,
    conn: &Connection,
    databases: &[String],
    classified: &ClassifiedStatement,
    sql: &str,
    resolution: &Resolution,
    confirmed: bool,
    outcome: crate::approval::outcomes::ApprovalOutcome,
    approval_scope: Option<&str>,
    approval_digest: Option<[u8; 32]>,
    policy_revision: Option<u64>,
    error: Option<&str>,
    opts: &WriteOptions,
) {
    let entry = AuditEntry {
        request_id: request_id.to_string(),
        connection: conn.name().to_string(),
        databases: databases.to_vec(),
        category: classified.category,
        ast_type: Some(classified.ast_type.to_string()),
        sql: sql.to_string(),
        decision: resolution.action,
        confirmed,
        outcome,
        affected_rows: None,
        duration_ms: None,
        error: error.map(str::to_string),
        backup_id: None,
        approval_scope: approval_scope.map(str::to_string),
        approval_digest,
        policy_revision,
    };
    let _ = crate::audit::write_audit_entry(&deps.audit, &entry, opts);
}

pub fn no_connection_message(explicit: Option<&str>) -> String {
    match explicit {
        Some(name) => {
            format!("Unknown connection {name:?}. Use list_connections to see available names.")
        }
        None => "No connection specified and no default set. Pass \"connection\" or call set_default_connection first.".into(),
    }
}

/// Map an outcome to the legacy tool JSON shape.
pub fn outcome_to_json(o: &RunOutcome) -> serde_json::Value {
    json!({
        "connection": o.connection,
        "category": o.category.as_str(),
        "contributingDatabase": o.resolution.contributing_databases.first(),
        "contributingDatabases": o.resolution.contributing_databases,
        "rows": o.rows,
        "fields": o.fields,
        "affectedRows": o.affected_rows,
        "truncated": o.truncated,
        "rowCap": o.resolution.effective.row_cap,
        "durationMs": o.duration_ms,
        "backupId": o.backup_id,
        "backupRowCount": o.backup_row_count,
        "requestId": o.request_id,
        "ddlNoOp": o.ddl_no_op,
        "ddlAbsentTargets": o.ddl_absent_targets,
        "ddlExecutedTargets": o.ddl_executed_targets,
        "warnings": o.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigStore, SqliteConnection};
    use crate::policy::model::{PartialPolicy, PolicyPresetName, TableRuleKey, policy_from_preset};
    use crate::vault::touchid::NoTouchId;
    use std::sync::Mutex;

    struct ScriptedSink(Vec<Mutex<Option<ConfirmOutcome>>>);

    impl ApprovalSink for ScriptedSink {
        fn confirm(&self, _r: ApprovalRequest) -> ConfirmOutcome {
            self.0
                .first()
                .and_then(|m| m.lock().unwrap().take())
                .unwrap_or(ConfirmOutcome::Unavailable {
                    reason: "script exhausted".into(),
                })
        }
    }

    fn sink_with(outcome: ConfirmOutcome) -> Box<dyn ApprovalSink> {
        Box::new(ScriptedSink(vec![Mutex::new(Some(outcome))]))
    }

    fn deps(dir: &tempfile::TempDir, sink: Box<dyn ApprovalSink>) -> GateDeps {
        let mut d = GateDeps::with_sink(sink);
        d.config = Arc::new(ConfigStore::with_path(dir.path().join("cfg.json")));
        d.audit = Arc::new(AuditDb::at_path(&dir.path().join("audit.sqlite")).unwrap());
        // Touch ID must never trigger in tests: unavailable prompt fails
        // closed, which is exactly what the read-only preset needs.
        d.auth = Arc::new(SessionAuthenticator::new(Box::new(NoTouchId)));
        d
    }

    fn sqlite_config(
        dir: &tempfile::TempDir,
        policy: crate::policy::model::Policy,
        rules: Vec<(TableRuleKey, PartialPolicy)>,
    ) {
        let mut sc = SqliteConnection {
            name: "local-sqlite".into(),
            path: dir.path().join("app.sqlite").display().to_string(),
            ..SqliteConnection::default()
        };
        sc.policy = policy;
        for (k, v) in rules {
            sc.table_policies.insert(k, v);
        }
        let store = ConfigStore::with_path(dir.path().join("cfg.json"));
        let cfg = store.load().unwrap();
        store
            .update(cfg.revision, |c| {
                c.connections.push(crate::config::Connection::Sqlite(sc));
                c.default_connection = Some("local-sqlite".into());
                Ok(())
            })
            .unwrap();
    }

    fn args(sql: &str) -> RunSqlArgs {
        RunSqlArgs {
            connection: None,
            sql: sql.into(),
            database: None,
            expected_ddl_targets: None,
        }
    }

    #[test]
    fn read_runs_without_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let d = deps(
            &dir,
            sink_with(ConfirmOutcome::Unavailable { reason: "x".into() }),
        );
        sqlite_config(&dir, policy_from_preset(PolicyPresetName::ReadOnly), vec![]);
        bootstrap_table(&d, &dir);
        let out = run_sql(&d, &args("SELECT id FROM users"), true).unwrap();
        assert_eq!(out.rows.len(), 1);
        assert_eq!(out.category, SqlCategory::Read);
    }

    #[test]
    fn write_denied_by_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let d = deps(
            &dir,
            sink_with(ConfirmOutcome::Unavailable { reason: "x".into() }),
        );
        sqlite_config(&dir, policy_from_preset(PolicyPresetName::ReadOnly), vec![]);
        bootstrap_table(&d, &dir);
        let err = run_sql(&d, &args("UPDATE users SET id = 2"), false).unwrap_err();
        assert!(matches!(err, GateError::Denied(_)), "{err}");
    }

    #[test]
    fn elevation_prompts_and_decline_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let d = deps(
            &dir,
            sink_with(ConfirmOutcome::Chosen(GrantChoice::Decline)),
        );
        let rule = PartialPolicy {
            write: Some(PolicyAction::Allow),
            ..PartialPolicy::default()
        };
        sqlite_config(
            &dir,
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![(TableRuleKey::parse("main.users").unwrap(), rule)],
        );
        bootstrap_table(&d, &dir);
        let err = run_sql(&d, &args("UPDATE users SET id = 2 WHERE id = 1"), false).unwrap_err();
        assert!(matches!(err, GateError::Declined(_)), "{err}");
        // Nothing changed.
        let d2 = deps(
            &dir,
            sink_with(ConfirmOutcome::Unavailable { reason: "x".into() }),
        );
        let out = run_sql(&d2, &args("SELECT id FROM users"), true).unwrap();
        assert_eq!(out.rows[0]["id"], json!(1));
    }

    #[test]
    fn unavailable_is_reported_as_unavailable_not_declined() {
        let dir = tempfile::tempdir().unwrap();
        let d = deps(&dir, Box::new(UnavailableSink));
        let rule = PartialPolicy {
            write: Some(PolicyAction::Allow),
            ..PartialPolicy::default()
        };
        sqlite_config(
            &dir,
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![(TableRuleKey::parse("main.users").unwrap(), rule)],
        );
        bootstrap_table(&d, &dir);
        let err = run_sql(&d, &args("UPDATE users SET id = 2 WHERE id = 1"), false).unwrap_err();
        assert!(matches!(err, GateError::Unavailable(_, _)), "{err}");
        // Audit recorded `unavailable`, not `declined`.
        let filters = crate::audit::AuditSearchFilters {
            limit: 10,
            ..Default::default()
        };
        let rows = crate::audit::search_audit_log(&d.audit, &filters).unwrap();
        assert!(rows.iter().any(|r| r.outcome == "unavailable"), "{rows:?}");
        assert!(!rows.iter().any(|r| r.outcome == "declined"));
    }

    #[test]
    fn approved_once_executes_and_backs_up() {
        let dir = tempfile::tempdir().unwrap();
        let d = deps(&dir, sink_with(ConfirmOutcome::Chosen(GrantChoice::Once)));
        let rule = PartialPolicy {
            write: Some(PolicyAction::Allow),
            ..PartialPolicy::default()
        };
        sqlite_config(
            &dir,
            policy_from_preset(PolicyPresetName::ReadOnly),
            vec![(TableRuleKey::parse("main.users").unwrap(), rule)],
        );
        bootstrap_table(&d, &dir);
        let out = run_sql(&d, &args("UPDATE users SET id = 2 WHERE id = 1"), false).unwrap();
        assert_eq!(out.affected_rows, 1);
        assert!(out.backup_id.is_some());
        let rows = crate::audit::search_audit_log(
            &d.audit,
            &crate::audit::AuditSearchFilters {
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(rows.iter().any(|r| r.outcome == "approved"));
    }

    #[test]
    fn query_tool_rejects_writes() {
        let dir = tempfile::tempdir().unwrap();
        let d = deps(
            &dir,
            sink_with(ConfirmOutcome::Unavailable { reason: "x".into() }),
        );
        sqlite_config(
            &dir,
            policy_from_preset(PolicyPresetName::Development),
            vec![],
        );
        bootstrap_table(&d, &dir);
        let err = run_sql(&d, &args("DELETE FROM users"), true).unwrap_err();
        assert!(matches!(err, GateError::NotReadOnly(_)));
    }

    fn bootstrap_table(d: &GateDeps, dir: &tempfile::TempDir) {
        let mut sc = SqliteConnection {
            name: "bootstrap".into(),
            path: dir.path().join("app.sqlite").display().to_string(),
            ..SqliteConnection::default()
        };
        sc.policy = policy_from_preset(PolicyPresetName::Administration);
        sc.policy.require_touch_id = false;
        let classified = crate::policy::classifier::classify_statement(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY)",
            Dialect::SQLite,
        )
        .unwrap();
        sqlite::execute_sqlite_statement(SqliteExecuteParams {
            connection: &sc,
            sql: "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY)",
            classified: &classified,
            policy: &sc.policy,
            database: None,
            audit: Some(d.audit.clone()),
        })
        .unwrap();
        let classified = crate::policy::classifier::classify_statement(
            "INSERT INTO users (id) VALUES (1)",
            Dialect::SQLite,
        )
        .unwrap();
        sqlite::execute_sqlite_statement(SqliteExecuteParams {
            connection: &sc,
            sql: "INSERT INTO users (id) VALUES (1)",
            classified: &classified,
            policy: &sc.policy,
            database: None,
            audit: Some(d.audit.clone()),
        })
        .unwrap();
    }
}
