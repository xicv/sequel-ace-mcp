//! MCP tool registrations: 19 tools on the shared library services.
//! `query`/`execute` go through the gate with elicitation approvals; every
//! other tool maps to a library service with the legacy JSON shape.

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResponse, CallToolResult};
use rmcp::schemars;
use rmcp::tool;
use rmcp::tool_router;
use rmcp::{ServerHandler, tool_handler};
use serde::Deserialize;
use serde_json::json;

use crate::app::gate::{self, GateDeps, RunSqlArgs};
use crate::config::{ConfigStore, Connection, SqliteConnection};
use crate::policy::model::{PartialPolicy, PolicyPresetName, SqlCategory, TableRuleKey};

use super::{SequelServer, error_tool_result, json_tool_result, text_tool_result};

impl SequelServer {
    /// Process-shared approval engine: "Allow for session" grants must
    /// survive across tool calls (a fresh engine per call silently
    /// voided the documented session scope).
    fn gate_deps_blocking(&self, sink: Box<dyn gate::ApprovalSink>) -> GateDeps {
        GateDeps::with_sink_and_approvals(sink, self.ctx.approvals.clone())
    }
}

fn resolve_conn(store: &ConfigStore, name: Option<&str>) -> Result<Option<Connection>, String> {
    store
        .load()
        .map(|cfg| cfg.resolve(name).cloned())
        .map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EmptyParams {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SqlParams {
    /// Configured connection name. Omit to use the default connection.
    #[serde(default)]
    pub connection: Option<String>,
    /// Single SQL statement (multi-statement input rejected).
    pub sql: String,
    /// Override default database/schema.
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectionRef {
    #[serde(default)]
    pub connection: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddSqliteParams {
    pub name: String,
    /// SQLite database file path. `~/` is expanded at execution time.
    pub path: String,
    /// SQLite schema name used for policy scope and metadata lookups.
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub policy_preset: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddConnectionParams {
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub user: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub ssl: Option<bool>,
    #[serde(default)]
    pub policy_preset: Option<String>,
    #[serde(default)]
    pub ssh_host: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub ssh_user: Option<String>,
    #[serde(default)]
    pub ssh_key_path: Option<String>,
    /// Docker container name (validated `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`).
    #[serde(default)]
    pub ssh_docker_container: Option<String>,
    /// `nc` (default), `ncat`, or `socat`.
    #[serde(default)]
    pub ssh_docker_bridge_tool: Option<String>,
    /// `lenient` (default) or `strict`.
    #[serde(default)]
    pub ssh_host_key_policy: Option<String>,
    #[serde(default)]
    pub ssh_known_hosts_path: Option<String>,
    #[serde(default)]
    pub ssl_server_name: Option<String>,
    /// PEM/DER file of a private CA the server certificate is verified
    /// against (merged with the system roots).
    #[serde(default)]
    pub ssl_ca_path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoveParams {
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetDefaultParams {
    /// Connection name, or empty string to clear the default.
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SelectDatabaseParams {
    #[serde(default)]
    pub connection: Option<String>,
    pub database: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DescribeParams {
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    pub table: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PolicyParams {
    pub name: String,
    pub policy: PartialPolicy,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DatabasePolicyParams {
    #[serde(default)]
    pub connection: Option<String>,
    pub database: String,
    pub policy: PartialPolicy,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DatabaseOnlyParams {
    #[serde(default)]
    pub connection: Option<String>,
    pub database: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TablePolicyParams {
    #[serde(default)]
    pub connection: Option<String>,
    /// Table key: `database.table` for exact rules or `database.*` wildcard.
    pub table: String,
    pub policy: PartialPolicy,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TableOnlyParams {
    #[serde(default)]
    pub connection: Option<String>,
    pub table: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExplainParams {
    #[serde(default)]
    pub connection: Option<String>,
    pub sql: String,
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuditSearchParams {
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub since_iso: Option<String>,
    #[serde(default)]
    pub until_iso: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BackupListParams {
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RestoreParams {
    /// Backup id from list_backups.
    pub backup_id: i64,
    /// Default true: inspect the plan without executing anything.
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuditCleanupParams {
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RetentionParams {
    #[serde(default)]
    pub retention_days_by_category: Option<RetentionPartial>,
    #[serde(default)]
    pub backup_days: Option<u32>,
    #[serde(default)]
    pub audit_max_mb: Option<u32>,
    #[serde(default)]
    pub backup_max_mb: Option<u32>,
    #[serde(default)]
    pub auto_cleanup_hours: Option<u32>,
    #[serde(default)]
    pub redact_sql_in_log: Option<bool>,
    #[serde(default)]
    pub tamper_evident_chain: Option<bool>,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct RetentionPartial {
    #[serde(default)]
    pub read: Option<u32>,
    #[serde(default)]
    pub write: Option<u32>,
    #[serde(default)]
    pub ddl: Option<u32>,
    #[serde(default)]
    pub admin: Option<u32>,
    #[serde(default)]
    pub tx_ctrl: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HistorySearchParams {
    #[serde(default)]
    pub since_iso: Option<String>,
    #[serde(default)]
    pub until_iso: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SequelAceHistoryParams {
    #[serde(default)]
    pub since_iso: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImportParams {
    /// Copy passwords from the Sequel Ace Keychain (macOS may prompt).
    #[serde(default = "default_true")]
    pub copy_passwords: bool,
}

fn parse_preset(s: &Option<String>) -> Result<PolicyPresetName, String> {
    match s.as_deref() {
        None => Ok(PolicyPresetName::ReadOnly),
        Some(name) => {
            PolicyPresetName::parse(name).ok_or_else(|| format!("unknown policy preset {name:?}"))
        }
    }
}

#[tool_router]
impl SequelServer {
    #[tool(
        name = "query",
        title = "Run a read-only SQL query",
        description = "Run a single read-only SQL statement (SELECT/SHOW/DESCRIBE/EXPLAIN, plus read-only SQLite PRAGMA). SQLite opens a read-only file handle.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn query(&self, Parameters(p): Parameters<SqlParams>) -> CallToolResult {
        // Hand-routed in call_tool for elicitation; this entry exists for
        // discovery and direct dispatch without interactive approvals.
        self.run_sql_blocking(
            RunSqlArgs {
                connection: p.connection,
                sql: p.sql,
                database: p.database,
                expected_ddl_targets: None,
            },
            true,
        )
    }

    #[tool(
        name = "execute",
        title = "Execute a write/DDL/admin SQL statement",
        description = "Run a non-read SQL statement (INSERT/UPDATE/DELETE/DDL/admin). Subject to the two-layer policy: table-rule elevation still requires user confirmation.",
        annotations(destructive_hint = true, open_world_hint = false)
    )]
    fn execute(&self, Parameters(p): Parameters<SqlParams>) -> CallToolResult {
        self.run_sql_blocking(
            RunSqlArgs {
                connection: p.connection,
                sql: p.sql,
                database: p.database,
                expected_ddl_targets: None,
            },
            false,
        )
    }

    #[tool(
        name = "list_connections",
        title = "List configured connections",
        description = "Return all connections configured in the local config (no passwords).",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn list_connections(&self, _p: Parameters<EmptyParams>) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("config load failed: {e}")),
        };
        let mut items = Vec::new();
        for c in &cfg.connections {
            let has_password = c.is_mysql()
                && self
                    .ctx
                    .secrets
                    .has_password(c.name(), mysql_user(c).as_deref().unwrap_or(""));
            items.push(json!({
                "name": c.name(),
                "driver": if c.is_mysql() { "mysql" } else { "sqlite" },
                "database": c.database(),
                "policy": c.policy(),
                "tablePolicies": c.table_policies(),
                "isDefault": Some(c.name()) == cfg.default_connection.as_deref(),
                "hasStoredPassword": has_password,
            }));
        }
        json_tool_result(json!({
            "defaultConnection": cfg.default_connection,
            "connections": items,
        }))
    }

    #[tool(
        name = "add_connection",
        title = "Add or update a MySQL/MariaDB connection",
        description = "Persist a MySQL/MariaDB connection. The password is captured via elicitation and stored in the macOS Keychain; it never appears in tool arguments or logs.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn add_connection(&self, _p: Parameters<AddConnectionParams>) -> CallToolResult {
        // Hand-routed in call_tool: password capture needs the session
        // peer for the elicitation round trip.
        error_tool_result(
            "add_connection is hand-routed for password elicitation; connect through the full tool call path",
        )
    }

    #[tool(
        name = "add_sqlite_connection",
        title = "Add or update a SQLite connection",
        description = "Persist a SQLite database file connection. Stores only the local file path and policy; no password or Keychain entry is used.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn add_sqlite_connection(&self, Parameters(p): Parameters<AddSqliteParams>) -> CallToolResult {
        let preset = match parse_preset(&p.policy_preset) {
            Ok(v) => v,
            Err(e) => return error_tool_result(e),
        };
        let mut sc = SqliteConnection {
            name: p.name.clone(),
            path: p.path.clone(),
            database: p.database.clone().unwrap_or_else(|| "main".into()),
            ..SqliteConnection::default()
        };
        sc.policy = crate::policy::model::policy_from_preset(preset);
        let conn = Connection::Sqlite(sc);
        if let Err(e) = conn.validate() {
            return error_tool_result(format!("{e}"));
        }
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        let name = p.name.clone();
        let preset_name = preset.as_str().to_string();
        match self.ctx.config.update(cfg.revision, move |c| {
            upsert(c, conn);
            Ok(())
        }) {
            Ok(()) => text_tool_result(format!(
                "Saved SQLite connection \"{name}\" with policy preset \"{preset_name}\". No password was stored."
            )),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "remove_connection",
        title = "Remove a connection",
        description = "Delete the connection from config and delete any associated MySQL/MariaDB Keychain password.",
        annotations(
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn remove_connection(&self, Parameters(p): Parameters<RemoveParams>) -> CallToolResult {
        let conn = match resolve_conn(&self.ctx.config, Some(&p.name)) {
            Ok(Some(c)) => c,
            Ok(None) => return error_tool_result(format!("Connection {:?} not found", p.name)),
            Err(e) => return error_tool_result(e),
        };
        if let Connection::Mysql(m) = &conn {
            let _ = self.ctx.secrets.delete_password(&m.name, &m.user);
            if let Some(ssh) = &m.ssh {
                let _ = self
                    .ctx
                    .secrets
                    .delete_password(&format!("{}::ssh", m.name), &ssh.user);
            }
        }
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        let name = p.name.clone();
        match self.ctx.config.update(cfg.revision, move |c| {
            c.connections.retain(|x| x.name() != name);
            if c.default_connection.as_deref() == Some(name.as_str()) {
                c.default_connection = None;
            }
            Ok(())
        }) {
            Ok(()) => text_tool_result(format!("Removed connection \"{}\".", p.name)),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "set_default_connection",
        title = "Set the default connection",
        description = "Mark a saved connection as the default. Subsequent query/execute/describe_table/list_databases calls without an explicit \"connection\" arg use it. Pass an empty string to clear.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn set_default_connection(
        &self,
        Parameters(p): Parameters<SetDefaultParams>,
    ) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        if p.name.is_empty() {
            let _ = self.ctx.config.update(cfg.revision, |c| {
                c.default_connection = None;
                Ok(())
            });
            return text_tool_result("Default connection cleared.");
        }
        let exists = cfg.connections.iter().any(|c| c.name() == p.name);
        if !exists {
            return error_tool_result(format!("Connection \"{}\" not found", p.name));
        }
        let name = p.name.clone();
        match self.ctx.config.update(cfg.revision, move |c| {
            c.default_connection = Some(name.clone());
            Ok(())
        }) {
            Ok(()) => text_tool_result(format!("Default connection is now \"{}\".", p.name)),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "get_default_connection",
        title = "Get the default connection",
        description = "Return the connection name currently used when \"connection\" arg is omitted.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn get_default_connection(&self, _p: Parameters<EmptyParams>) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        json_tool_result(json!({ "defaultConnection": cfg.default_connection }))
    }

    #[tool(
        name = "select_database",
        title = "Set the default database on a connection",
        description = "Update a saved connection so that subsequent query/execute calls default to this database when no per-call override is supplied.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn select_database(&self, Parameters(p): Parameters<SelectDatabaseParams>) -> CallToolResult {
        if !p
            .database
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        {
            return error_tool_result("database must be identifier-safe");
        }
        let mut conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        match &mut conn {
            Connection::Mysql(m) => m.database = Some(p.database.clone()),
            Connection::Sqlite(s) => s.database = p.database.clone(),
        }
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        let name = conn.name().to_string();
        let db = p.database.clone();
        let name_for_msg = name.clone();
        match self.ctx.config.update(cfg.revision, move |c| {
            upsert(c, conn);
            let _ = (&name, &db);
            Ok(())
        }) {
            Ok(()) => text_tool_result(format!(
                "Default database for \"{}\" set to \"{}\". Per-call database overrides still take precedence.",
                name_for_msg, p.database
            )),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "set_policy",
        title = "Update a connection policy",
        description = "Change the action set (read|write|ddl|admin|txCtrl → allow|confirm|deny) and limits for an existing connection baseline.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn set_policy(&self, Parameters(p): Parameters<PolicyParams>) -> CallToolResult {
        let mut conn = match resolve_conn(&self.ctx.config, Some(&p.name)) {
            Ok(Some(c)) => c,
            Ok(None) => return error_tool_result(format!("Connection {:?} not found", p.name)),
            Err(e) => return error_tool_result(e),
        };
        match &mut conn {
            Connection::Mysql(m) => {
                m.policy = m.policy.merged_with(&p.policy);
            }
            Connection::Sqlite(s) => {
                s.policy = s.policy.merged_with(&p.policy);
            }
        }
        if let Err(e) = conn.validate() {
            return error_tool_result(format!("{e}"));
        }
        let policy = match &conn {
            Connection::Mysql(m) => m.policy.clone(),
            Connection::Sqlite(s) => s.policy.clone(),
        };
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        match self.ctx.config.update(cfg.revision, move |c| {
            upsert(c, conn);
            Ok(())
        }) {
            Ok(()) => json_tool_result(json!({ "name": p.name, "policy": policy })),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "set_table_policy",
        title = "Set a table policy rule",
        description = "Set an exact (`database.table`) or wildcard (`database.*`) table rule. Exact rules take precedence over wildcards. A rule that elevates what the baseline denies still requires confirmation per statement.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn set_table_policy(&self, Parameters(p): Parameters<TablePolicyParams>) -> CallToolResult {
        let key = match TableRuleKey::parse(&p.table) {
            Some(k) => k,
            None => {
                return error_tool_result(format!(
                    "invalid table key {:?} (expected database.table or database.*)",
                    p.table
                ));
            }
        };
        let mut conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        let rendered = key.render();
        let partial = p.policy.clone();
        match &mut conn {
            Connection::Mysql(m) => {
                m.table_policies.insert(key, partial);
            }
            Connection::Sqlite(s) => {
                s.table_policies.insert(key, partial);
            }
        }
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        let name = conn.name().to_string();
        match self.ctx.config.update(cfg.revision, move |c| {
            upsert(c, conn);
            Ok(())
        }) {
            Ok(()) => json_tool_result(json!({
                "connection": name,
                "table": rendered,
                "policy": p.policy,
            })),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "clear_table_policy",
        title = "Clear a table policy rule",
        description = "Remove an exact or wildcard table rule; the connection baseline applies again.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn clear_table_policy(&self, Parameters(p): Parameters<TableOnlyParams>) -> CallToolResult {
        let key = match TableRuleKey::parse(&p.table) {
            Some(k) => k,
            None => return error_tool_result(format!("invalid table key {:?}", p.table)),
        };
        let mut conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        let existed = match &mut conn {
            Connection::Mysql(m) => m.table_policies.remove(&key).is_some(),
            Connection::Sqlite(s) => s.table_policies.remove(&key).is_some(),
        };
        if !existed {
            return text_tool_result(format!("No rule exists for {}.", p.table));
        }
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("{e}")),
        };
        match self.ctx.config.update(cfg.revision, move |c| {
            upsert(c, conn);
            Ok(())
        }) {
            Ok(()) => text_tool_result(format!("Cleared table rule {}.", p.table)),
            Err(e) => error_tool_result(format!("{e}")),
        }
    }

    #[tool(
        name = "list_table_policies",
        title = "List table policy rules",
        description = "Show the connection baseline plus every exact and wildcard table rule.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn list_table_policies(&self, Parameters(p): Parameters<ConnectionRef>) -> CallToolResult {
        let conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        json_tool_result(json!({
            "connection": conn.name(),
            "baseline": conn.policy(),
            "tablePolicies": conn.table_policies(),
        }))
    }

    #[tool(
        name = "explain_policy",
        title = "Explain effective policy for a statement",
        description = "Classify a statement and show the per-table resolution (baseline vs rule, strictest-wins, elevation flags) without executing it.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn explain_policy(&self, Parameters(p): Parameters<ExplainParams>) -> CallToolResult {
        let conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        let dialect = if conn.is_mysql() {
            crate::policy::classifier::Dialect::MySql
        } else {
            crate::policy::classifier::Dialect::SQLite
        };
        let classified = match crate::policy::classifier::classify_statement(&p.sql, dialect) {
            Ok(c) => c,
            Err(e) => {
                return error_tool_result(format!("Cannot classify statement: {}", e.message()));
            }
        };
        let fallback = p
            .database
            .clone()
            .or_else(|| conn.database().map(str::to_string));
        let r = crate::policy::resolver::resolve(&conn, &classified, fallback.as_deref());
        let contributions: Vec<serde_json::Value> = r
            .contributions
            .iter()
            .map(|c| {
                json!({
                    "table": format!("{}.{}", c.table.database, c.table.table),
                    "kind": c.kind,
                    "category": c.category.as_str(),
                    "action": c.action.as_str(),
                    "baselineAction": c.baseline_action.as_str(),
                    "rule": c.rule,
                    "elevated": c.elevated,
                })
            })
            .collect();
        json_tool_result(json!({
            "category": classified.category.as_str(),
            "astType": classified.ast_type,
            "action": r.action.as_str(),
            "elevated": r.elevated,
            "denyReason": r.deny_reason.as_ref().map(|d| format!("{d:?}")),
            "contributions": contributions,
            "contributingDatabases": r.contributing_databases,
            "flags": {
                "lockingRead": classified.locking_read,
                "fileIo": classified.file_io,
                "executesWrapped": classified.executes_wrapped,
            },
        }))
    }

    #[tool(
        name = "set_database_policy",
        title = "Set per-database policy override (compatibility)",
        description = "Compatibility wrapper: operates on the wildcard table rule `<database>.*`. Prefer set_table_policy.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn set_database_policy(
        &self,
        Parameters(p): Parameters<DatabasePolicyParams>,
    ) -> CallToolResult {
        self.set_table_policy(Parameters(TablePolicyParams {
            connection: p.connection.clone(),
            table: format!("{}.*", p.database),
            policy: p.policy.clone(),
        }))
    }

    #[tool(
        name = "clear_database_policy",
        title = "Clear per-database policy override (compatibility)",
        description = "Compatibility wrapper: clears the wildcard table rule `<database>.*`.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn clear_database_policy(
        &self,
        Parameters(p): Parameters<DatabaseOnlyParams>,
    ) -> CallToolResult {
        self.clear_table_policy(Parameters(TableOnlyParams {
            connection: p.connection.clone(),
            table: format!("{}.*", p.database),
        }))
    }

    #[tool(
        name = "list_database_policies",
        title = "List per-database policy overrides (compatibility)",
        description = "Compatibility wrapper: shows baseline + wildcard (`db.*`) rules rendered as per-database overrides.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn list_database_policies(&self, Parameters(p): Parameters<ConnectionRef>) -> CallToolResult {
        let conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        let mut overrides = serde_json::Map::new();
        for (k, v) in conn.table_policies() {
            if let TableRuleKey::Wildcard { database } = k {
                overrides.insert(
                    database.clone(),
                    serde_json::to_value(v).unwrap_or_default(),
                );
            }
        }
        json_tool_result(json!({
            "connection": conn.name(),
            "baseline": conn.policy(),
            "overrides": overrides,
        }))
    }

    #[tool(
        name = "describe_table",
        title = "Describe a table",
        description = "Describe a table. Uses DESCRIBE on MySQL/MariaDB and PRAGMA table_info on SQLite. Always read-only.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn describe_table(&self, Parameters(p): Parameters<DescribeParams>) -> CallToolResult {
        let conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        let q = format!("`{}`", p.table.replace('`', "``"));
        let sql = if conn.is_mysql() {
            match &p.database {
                Some(db) => format!(
                    "DESCRIBE `{}`.`{}`",
                    db.replace('`', "``"),
                    p.table.replace('`', "``")
                ),
                None => format!("DESCRIBE {q}"),
            }
        } else {
            let schema = p
                .database
                .as_deref()
                .or(conn.database().map(|_| ""))
                .unwrap_or("main");
            let _ = schema;
            format!(
                "PRAGMA `{}`.table_info('{}')",
                p.database
                    .clone()
                    .unwrap_or_else(|| "main".into())
                    .replace('`', "``"),
                p.table.replace('\'', "''")
            )
        };
        self.run_sql_blocking(
            RunSqlArgs {
                connection: p.connection.clone(),
                sql,
                database: p.database.clone(),
                expected_ddl_targets: None,
            },
            true,
        )
    }

    #[tool(
        name = "list_databases",
        title = "List databases",
        description = "SHOW DATABASES on MySQL/MariaDB or PRAGMA database_list on SQLite.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn list_databases(&self, Parameters(p): Parameters<ConnectionRef>) -> CallToolResult {
        let conn = match resolve_conn(&self.ctx.config, p.connection.as_deref()) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return error_tool_result(gate::no_connection_message(p.connection.as_deref()));
            }
            Err(e) => return error_tool_result(e),
        };
        let sql = if conn.is_mysql() {
            "SHOW DATABASES".to_string()
        } else {
            "PRAGMA database_list".to_string()
        };
        self.run_sql_blocking(
            RunSqlArgs {
                connection: p.connection.clone(),
                sql,
                database: None,
                expected_ddl_targets: None,
            },
            true,
        )
    }

    #[tool(
        name = "audit_search",
        title = "Search audit log",
        description = "Query the local audit-log SQLite. Returns redacted SQL by default. Includes connection, decision, outcome, duration, and backup_id.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn audit_search(&self, Parameters(p): Parameters<AuditSearchParams>) -> CallToolResult {
        let filters = crate::audit::AuditSearchFilters {
            since: p.since_iso.clone(),
            until: p.until_iso.clone(),
            connection: p.connection.clone(),
            category: p.category.as_deref().and_then(SqlCategory::parse),
            outcome: p.outcome.clone(),
            limit: p.limit.unwrap_or(200),
        };
        match crate::audit::search_audit_log(&self.ctx.audit, &filters) {
            Ok(rows) => json_tool_result(json!({ "count": rows.len(), "rows": rows })),
            Err(e) => error_tool_result(format!("audit search failed: {e}")),
        }
    }

    #[tool(
        name = "list_backups",
        title = "List recent row/schema backups",
        description = "Show recent pre-mutation backups taken before UPDATE/DELETE/TRUNCATE/DROP/ALTER. Each row links to a backup_id.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn list_backups(&self, Parameters(p): Parameters<BackupListParams>) -> CallToolResult {
        match crate::backup::list_backups(
            &self.ctx.audit,
            p.connection.as_deref(),
            p.limit.unwrap_or(50),
        ) {
            Ok(rows) => json_tool_result(json!({ "count": rows.len(), "rows": rows })),
            Err(e) => error_tool_result(format!("backup list failed: {e}")),
        }
    }

    #[tool(
        name = "restore_backup",
        title = "Restore from a pre-mutation backup",
        description = "Replay backup #N into the originating connection. Generates dialect-specific upserts for row backups and CREATE TABLE for schema backups. Subject to the same policy gate (counts as a write). Pass dryRun=true to inspect the plan first.",
        annotations(
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    fn restore_backup(&self, _p: Parameters<RestoreParams>) -> CallToolResult {
        // Hand-routed in call_tool for confirm-gated execution; this
        // entry exists for discovery and dry-run dispatch without
        // interactive approvals.
        error_tool_result(
            "restore_backup is hand-routed for confirmation; pass dryRun=true for the plan",
        )
    }

    #[tool(
        name = "audit_cleanup",
        title = "Clean up audit log + old backups",
        description = "Prune audit entries older than retention.auditDays and backups older than retention.backupDays. Hard size caps trigger an additional 20% trim. VACUUMs the file. Pass dryRun=true to preview.",
        annotations(
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn audit_cleanup(&self, Parameters(p): Parameters<AuditCleanupParams>) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("config load failed: {e}")),
        };
        let r = crate::audit::retention::cleanup_audit(&self.ctx.audit, &cfg.retention, p.dry_run);
        json_tool_result(json!({
            "auditDeleted": r.audit_deleted,
            "auditDeletedByCategory": serde_json::Map::from_iter(
                r.audit_deleted_by_category
                    .iter()
                    .map(|(k, v)| (k.to_string(), serde_json::json!(v))),
            ),
            "backupDeleted": r.backup_deleted,
            "bytesReclaimed": r.bytes_reclaimed,
            "ranAt": r.ran_at,
            "dryRun": p.dry_run,
        }))
    }

    #[tool(
        name = "set_retention",
        title = "Update retention / cleanup config",
        description = "Configure per-category retention (read=7, write=30, ddl=90, admin=180, txCtrl=7 by default), backup retention, hard size caps, and how often auto-cleanup runs on server boot. Pass any subset; missing fields keep current values.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn set_retention(&self, Parameters(p): Parameters<RetentionParams>) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("config load failed: {e}")),
        };
        let mut next = cfg.retention.clone();
        if let Some(days) = p.retention_days_by_category {
            let d = &mut next.retention_days_by_category;
            if let Some(v) = days.read {
                d.read = v;
            }
            if let Some(v) = days.write {
                d.write = v;
            }
            if let Some(v) = days.ddl {
                d.ddl = v;
            }
            if let Some(v) = days.admin {
                d.admin = v;
            }
            if let Some(v) = days.tx_ctrl {
                d.tx_ctrl = v;
            }
        }
        if let Some(v) = p.backup_days {
            next.backup_days = v;
        }
        if let Some(v) = p.audit_max_mb {
            next.audit_max_mb = v.max(10);
        }
        if let Some(v) = p.backup_max_mb {
            next.backup_max_mb = v.max(10);
        }
        if let Some(v) = p.auto_cleanup_hours {
            next.auto_cleanup_hours = v.min(720);
        }
        if let Some(v) = p.redact_sql_in_log {
            next.redact_sql_in_log = v;
        }
        if let Some(v) = p.tamper_evident_chain {
            next.tamper_evident_chain = v;
        }
        let revision = cfg.revision;
        let to_persist = next.clone();
        match self.ctx.config.update(revision, move |c| {
            c.retention = to_persist;
            Ok(())
        }) {
            Ok(()) => json_tool_result(serde_json::to_value(&next).unwrap_or_default()),
            Err(e) => error_tool_result(e.to_string()),
        }
    }

    #[tool(
        name = "history_search",
        title = "Unified history (MCP audit + Sequel Ace)",
        description = "Merge our audit_log with Sequel Ace queryHistory.db, sorted by timestamp DESC. Each row has a source field (mcp | sequel-ace). Use source=mcp or source=sequel-ace to filter to one. Useful when you want a single timeline regardless of where a query was run.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn history_search(&self, Parameters(p): Parameters<HistorySearchParams>) -> CallToolResult {
        let source = p.source.as_deref().unwrap_or("both");
        let limit = p.limit.unwrap_or(200).min(5000);
        let mut out: Vec<serde_json::Value> = Vec::new();

        if source == "mcp" || source == "both" {
            let filters = crate::audit::AuditSearchFilters {
                since: p.since_iso.clone(),
                until: p.until_iso.clone(),
                connection: p.connection.clone(),
                category: None,
                outcome: None,
                limit: limit.saturating_mul(2),
            };
            if let Ok(rows) = crate::audit::search_audit_log(&self.ctx.audit, &filters) {
                for r in rows {
                    let sql = r.sql_redacted.clone();
                    if let Some(needle) = &p.search
                        && !sql.to_lowercase().contains(&needle.to_lowercase())
                    {
                        continue;
                    }
                    out.push(json!({
                        "source": "mcp",
                        "ts": r.ts,
                        "sql": sql,
                        "connection": r.connection,
                        "category": r.category,
                        "outcome": r.outcome,
                        "decision": r.decision,
                        "databases": r.databases,
                        "durationMs": r.duration_ms,
                        "affectedRows": r.affected_rows,
                        "backupId": r.backup_id,
                    }));
                }
            }
        }

        if source == "sequel-ace" || source == "both" {
            let filters = crate::importer::history::SequelAceHistoryFilters {
                since_iso: p.since_iso.as_deref(),
                search: p.search.as_deref(),
                limit: Some(limit.saturating_mul(2)),
            };
            for r in crate::importer::read_sequel_ace_history(&filters, None) {
                if let Some(until) = &p.until_iso
                    && r.created_at_iso.as_str() >= until.as_str()
                {
                    continue;
                }
                out.push(json!({
                    "source": "sequel-ace",
                    "ts": r.created_at_iso,
                    "sql": r.query,
                    "sequelAceId": r.id,
                }));
            }
        }

        out.sort_by(|a, b| b["ts"].as_str().cmp(&a["ts"].as_str()));
        out.truncate(limit as usize);
        json_tool_result(json!({ "count": out.len(), "rows": out }))
    }

    #[tool(
        name = "sequel_ace_history",
        title = "Read Sequel Ace query history",
        description = "Read the queryHistory.db that Sequel Ace maintains in its sandbox. Returns distinct queries the user has run in the GUI (deduplicated by Sequel Ace, with latest createdTime). Read-only — no modification. Optional sinceIso, search (LIKE %text%), limit (default 200, max 5000).",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn sequel_ace_history(
        &self,
        Parameters(p): Parameters<SequelAceHistoryParams>,
    ) -> CallToolResult {
        let stat = crate::importer::stat_sequel_ace_history(None);
        if !stat.exists {
            return error_tool_result(format!(
                "Sequel Ace queryHistory.db not found at {}. Open Sequel Ace and run at least one query first, or check that Sequel Ace is installed.",
                stat.path.display()
            ));
        }
        let filters = crate::importer::history::SequelAceHistoryFilters {
            since_iso: p.since_iso.as_deref(),
            search: p.search.as_deref(),
            limit: p.limit,
        };
        let rows: Vec<serde_json::Value> = crate::importer::read_sequel_ace_history(&filters, None)
            .into_iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "query": r.query,
                    "createdTime": r.created_time,
                    "createdAtIso": r.created_at_iso,
                })
            })
            .collect();
        let returned = rows.len();
        json_tool_result(json!({
            "source": "sequel-ace",
            "path": stat.path.display().to_string(),
            "totalAvailable": stat.entry_count,
            "returned": returned,
            "note": "Sequel Ace dedupes by query text — only the latest createdTime is kept per distinct query.",
            "rows": rows,
        }))
    }

    #[tool(
        name = "import_from_sequel_ace",
        title = "Import connections from Sequel Ace",
        description = "Read Sequel Ace Favorites.plist, copy connections (and optionally passwords via /usr/bin/security; macOS will prompt user to allow access) into our config + keychain. Sequel Ace data is never modified.",
        annotations(idempotent_hint = true, open_world_hint = false)
    )]
    fn import_from_sequel_ace(&self, Parameters(p): Parameters<ImportParams>) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("config load failed: {e}")),
        };
        let revision = cfg.revision;
        let copy = p.copy_passwords;
        let secrets = self.ctx.secrets.clone();
        let result = match self.ctx.config.update(revision, move |c| {
            Ok(crate::importer::import_from_sequel_ace(
                c, &*secrets, copy, None, None,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return error_tool_result(e.to_string()),
        };
        json_tool_result(json!({
            "total": result.total,
            "imported": result.imported,
            "withPasswords": result.with_passwords,
            "skipped": result.skipped.iter()
                .map(|(name, reason)| json!({ "name": name, "reason": reason }))
                .collect::<Vec<_>>(),
        }))
    }

    #[tool(
        name = "doctor",
        title = "Diagnostic report",
        description = "Print a sanitized JSON diagnostic of the MCP install: runtime versions, config state, every configured connection (host/user/db, policy), password presence. Contains zero passwords and zero secrets — redact hostnames before posting publicly.",
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    fn doctor(&self, _p: Parameters<EmptyParams>) -> CallToolResult {
        let cfg = match self.ctx.config.load() {
            Ok(c) => c,
            Err(e) => return error_tool_result(format!("config load failed: {e}")),
        };
        let default = cfg.default_connection.as_deref();
        let connections: Vec<serde_json::Value> = cfg
            .connections
            .iter()
            .map(|c| {
                json!({
                    "name": c.name(),
                    "driver": if c.is_mysql() { "mysql" } else { "sqlite" },
                    "database": c.database(),
                    "policy": c.policy(),
                    "isDefault": Some(c.name()) == default,
                })
            })
            .collect();
        json_tool_result(json!({
            "app": crate::PACKAGE_NAME,
            "version": crate::PACKAGE_VERSION,
            "runtime": {
                "platform": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            },
            "defaultConnection": cfg.default_connection,
            "connections": connections,
            "note": "no passwords or Keychain secrets included; hostnames/usernames/SQLite paths/key paths ARE included — redact before posting publicly.",
        }))
    }
}

impl SequelServer {
    /// Run one statement through the gate with no interactive approvals
    /// (read-only helper tools; confirm-gated statements report
    /// unavailable — use query/execute for those).
    fn run_sql_blocking(&self, args: RunSqlArgs, expect_read_only: bool) -> CallToolResult {
        let deps = self.gate_deps_blocking(Box::new(gate::UnavailableSink));
        match gate::run_sql(&deps, &args, expect_read_only) {
            Ok(out) => json_tool_result(gate::outcome_to_json(&out)),
            Err(e) => error_tool_result(e.to_string()),
        }
    }

    /// Modern-era (2026-07-28) query/execute: MRTR approvals. The first
    /// confirm-required call returns `input_required` with an
    /// elicitation/create input request and an OPAQUE SERVER-SIDE
    /// one-shot `requestState` (a random token; every binding — tool,
    /// connection, operation digest, policy revision, DDL plan targets,
    /// expiry — lives in the in-process pending store, never on the
    /// wire). The retry echoes the token plus `inputResponses`; after
    /// atomic single-use consumption and revalidation the statement
    /// executes through the normal gate with the pre-decided outcome
    /// injected. For MySQL DROP statements the plan-time preflight fixes
    /// the approved target set BEFORE the approval is issued, and the
    /// retry fails closed (`ddl_precondition_changed`) if any target
    /// changed existence in between.
    async fn call_sql_modern(
        &self,
        request: rmcp::model::CallToolRequestParams,
        p: SqlParams,
        expect_read_only: bool,
        tool: &'static str,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        use rmcp::model::{
            ElicitRequestParams, ElicitationSchema, InputRequest, InputRequiredResult,
        };

        // Cheap pure recomputation of the operation identity + decision.
        let cfg = self
            .ctx
            .config
            .load()
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        let conn = cfg
            .resolve(p.connection.as_deref())
            .cloned()
            .ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    gate::no_connection_message(p.connection.as_deref()),
                    None,
                )
            })?;
        let dialect = if conn.is_mysql() {
            crate::policy::classifier::Dialect::MySql
        } else {
            crate::policy::classifier::Dialect::SQLite
        };
        let classified =
            crate::policy::classifier::classify_statement(&p.sql, dialect).map_err(|e| {
                rmcp::ErrorData::invalid_params(format!("cannot classify: {}", e.message()), None)
            })?;
        if expect_read_only && classified.category != crate::policy::model::SqlCategory::Read {
            return Ok(CallToolResponse::Complete(error_tool_result(format!(
                "query tool only accepts read statements (got {}). Use the \"execute\" tool for non-read statements.",
                classified.category
            ))));
        }
        let fallback = p
            .database
            .clone()
            .or_else(|| conn.database().map(str::to_string));
        let resolution = crate::policy::resolver::resolve(&conn, &classified, fallback.as_deref());

        let run_with_sink =
            |outcome: Box<dyn gate::ApprovalSink>, expected_ddl: Option<Vec<(String, String)>>| {
                let args = RunSqlArgs {
                    connection: p.connection.clone(),
                    sql: p.sql.clone(),
                    database: p.database.clone(),
                    expected_ddl_targets: expected_ddl,
                };
                let deps = self.gate_deps_blocking(outcome);
                tokio::task::spawn_blocking(move || gate::run_sql(&deps, &args, expect_read_only))
            };

        if resolution.action != crate::policy::model::PolicyAction::Confirm {
            let out = run_with_sink(Box::new(gate::UnavailableSink), None)
                .await
                .map_err(|e| rmcp::ErrorData::internal_error(format!("gate join: {e}"), None))?
                .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
            return Ok(CallToolResponse::Complete(super::json_tool_result(
                gate::outcome_to_json(&out),
            )));
        }

        // Plan-time DDL preflight for MySQL DROP statements: fix the
        // approved target set BEFORE any approval is issued. The retry
        // can then only ever execute targets that existed when the user
        // approved — a target created in between fails closed.
        let mut approved_ddl: Option<Vec<(String, String)>> = None;
        let mut plan_split: Option<(Vec<String>, Vec<String>)> = None;
        if conn.is_mysql()
            && classified.category == crate::policy::model::SqlCategory::Ddl
            && classified.ast_type == "drop"
        {
            let Connection::Mysql(mysql_conn) = &conn else {
                unreachable!("checked is_mysql above");
            };
            let pw = match self
                .ctx
                .secrets
                .get_password(&mysql_conn.name, &mysql_conn.user)
            {
                Ok(pw) => pw,
                Err(_) => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!(
                            "no password stored for connection {:?}; cannot plan the approval",
                            mysql_conn.name
                        ),
                        None,
                    ));
                }
            };
            let preflight = async {
                // Tunnel connections plan through the SAME tunnel runtime
                // as the gate (a tunnel-only database must be plannable,
                // and the plan's pool must carry the tunnel generation).
                let (host, port, tunnel_generation) = if let Some(ssh) = &mysql_conn.ssh {
                    let ssh_pw = self
                        .ctx
                        .secrets
                        .get_password(&format!("{}::ssh", mysql_conn.name), &ssh.user)
                        .ok();
                    let lease = crate::sql::ssh::tunnel_endpoint(
                        &mysql_conn.name,
                        ssh,
                        ssh_pw.as_ref().map(|p| p.as_str()),
                        &mysql_conn.host,
                        mysql_conn.port,
                        cfg.revision,
                    )
                    .await
                    .map_err(|e| format!("ssh tunnel: {e}"))?;
                    (lease.host, lease.port, Some(lease.generation))
                } else {
                    (mysql_conn.host.clone(), mysql_conn.port, None)
                };
                let pool = crate::sql::mysql::pool_manager()
                    .verified_pool(
                        mysql_conn,
                        &pw,
                        fallback.as_deref(),
                        cfg.revision,
                        Some(&host),
                        Some(port),
                        tunnel_generation,
                    )
                    .await
                    .map_err(|e| format!("pool initialization failed: {e}"))?;
                let mut pconn = pool
                    .get_conn()
                    .await
                    .map_err(|e| format!("connection failed: {e}"))?;
                crate::sql::ddl::preflight_ddl(&mut pconn, &classified, fallback.as_deref())
                    .await
                    .map_err(|e| e.to_string())
            };
            match preflight.await {
                Ok(crate::sql::ddl::DdlPreflight::Present) => {
                    let mut targets = Vec::new();
                    for t in &classified.mutated_tables {
                        if let Some(schema) = t.database.clone().or_else(|| fallback.clone()) {
                            targets.push((schema, t.table.clone()));
                        }
                    }
                    approved_ddl = Some(targets);
                }
                Ok(crate::sql::ddl::DdlPreflight::Mixed { existing, missing }) => {
                    plan_split = Some((
                        existing.iter().map(|(s, t)| format!("{s}.{t}")).collect(),
                        missing.iter().map(|(s, t)| format!("{s}.{t}")).collect(),
                    ));
                    approved_ddl = Some(existing);
                }
                Ok(crate::sql::ddl::DdlPreflight::MissingNoOp(missing)) => {
                    plan_split = Some((
                        Vec::new(),
                        missing.iter().map(|(s, t)| format!("{s}.{t}")).collect(),
                    ));
                    approved_ddl = Some(Vec::new());
                }
                Err(e) => {
                    return Ok(CallToolResponse::Complete(error_tool_result(format!(
                        "cannot plan the approval (DDL preflight failed; nothing executed): {e}"
                    ))));
                }
            }
        }

        // Bind the approval to the effective database scope as well:
        // replaying the same SQL against a different database arg (or a
        // changed connection default) must fail with mrtr_invalid_state.
        let digest =
            super::mrtr::operation_digest(&p.sql, conn.name(), fallback.as_deref(), cfg.revision);

        // Retry: consume + validate the echoed state, parse the response,
        // execute with the plan-approved DDL target set.
        if let Some(responses) = &request.input_responses {
            if serde_json::to_string(responses)
                .map(|s| s.len())
                .unwrap_or(usize::MAX)
                > super::limits::MAX_INPUT_RESPONSES_BYTES
            {
                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                    "[argument_too_large] inputResponses exceeds {} bytes",
                    super::limits::MAX_INPUT_RESPONSES_BYTES
                ))));
            }
            let state = request
                .request_state
                .as_deref()
                .ok_or_else(|| rmcp::ErrorData::invalid_params("missing requestState", None))?;
            if state.len() > super::limits::MAX_REQUEST_STATE_BYTES {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "[mrtr_invalid_state] requestState exceeds {} bytes",
                        super::limits::MAX_REQUEST_STATE_BYTES
                    ),
                    None,
                ));
            }
            let pending = super::mrtr::take(state, tool, conn.name(), &digest, cfg.revision)
                .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("{}; approval rejected", e.message()),
                        None,
                    )
                })?;
            let value = responses.get("approval").cloned().ok_or_else(|| {
                rmcp::ErrorData::invalid_params("missing approval response", None)
            })?;
            match super::mrtr::parse_response(&value) {
                crate::approval::ConfirmOutcome::Chosen(crate::approval::GrantChoice::Decline) => {
                    Ok(CallToolResponse::Complete(error_tool_result(
                        "User declined confirmation. Statement not executed.",
                    )))
                }
                outcome @ crate::approval::ConfirmOutcome::Chosen(_) => {
                    let out = run_with_sink(
                        Box::new(PreDecidedSink(outcome)),
                        pending.approved_ddl_targets,
                    )
                    .await
                    .map_err(|e| rmcp::ErrorData::internal_error(format!("gate join: {e}"), None))?
                    .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
                    Ok(CallToolResponse::Complete(super::json_tool_result(
                        gate::outcome_to_json(&out),
                    )))
                }
                crate::approval::ConfirmOutcome::Unavailable { reason } => {
                    Ok(CallToolResponse::Complete(error_tool_result(format!(
                        "confirmation required, but no prompt could be shown: {reason}. Statement not executed - nothing was changed. This is not a refusal."
                    ))))
                }
            }
        } else {
            // First call: emit the input request (redacted SQL preview +
            // the plan-time target split for mixed DROP statements).
            let snippet = if p.sql.len() > 800 {
                format!("{}…", &p.sql[..800])
            } else {
                p.sql.clone()
            };
            let tables: Vec<String> = resolution
                .contributions
                .iter()
                .map(|c| format!("{}.{}", c.table.database, c.table.table))
                .collect();
            let plan_note = match &plan_split {
                Some((exec, absent)) => format!(
                    "\n\nConfirmed to exist at plan time (will be affected): {}\nAbsent at plan time (skipped, recorded in audit): {}",
                    if exec.is_empty() {
                        "(none — this will be a no-op)".to_string()
                    } else {
                        exec.join(", ")
                    },
                    absent.join(", ")
                ),
                None => String::new(),
            };
            let message = format!(
                "About to run a {} statement on {}.\n\n--- SQL ---\n{}\n--- end ---\n\nAffected tables: {}{}\n\nPick an authorization scope.",
                classified.category,
                conn.name(),
                snippet,
                if tables.is_empty() {
                    "(statement scope)".to_string()
                } else {
                    tables.join(", ")
                },
                plan_note,
            );
            let mut input_requests = std::collections::BTreeMap::new();
            input_requests.insert(
                "approval".to_string(),
                InputRequest::Elicitation(rmcp::model::ElicitRequest::new(
                    ElicitRequestParams::FormElicitationParams {
                        meta: None,
                        message,
                        requested_schema: ElicitationSchema::from_json_schema(
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "choice": {
                                        "type": "string",
                                        "title": "Authorization",
                                        "enum": ["once", "session", "decline"]
                                    }
                                },
                                "required": ["choice"]
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        )
                        .map_err(|e| {
                            rmcp::ErrorData::internal_error(
                                format!("elicitation schema: {e}"),
                                None,
                            )
                        })?,
                    },
                )),
            );
            let pending = super::mrtr::PendingApproval {
                tool,
                connection: conn.name().to_string(),
                operation_digest: digest,
                policy_revision: cfg.revision,
                approved_ddl_targets: approved_ddl,
                expires_at: std::time::Instant::now() + super::mrtr::TTL,
            };
            let state = super::mrtr::issue(pending);
            Ok(rmcp::model::CallToolResponse::InputRequired(
                InputRequiredResult::new(Some(input_requests), Some(state)),
            ))
        }
    }
}

impl SequelServer {
    /// add_connection: validates arguments, elicits the password through
    /// the session peer (never via tool args), stores it in the secret
    /// store (macOS Keychain; the in-memory store under test mode), and
    /// upserts the connection. Any decline/cancel/unavailable prompt
    /// leaves config AND secrets untouched.
    async fn call_add_connection(
        &self,
        p: AddConnectionParams,
        peer: rmcp::service::Peer<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        use crate::config::{BridgeTool, MySqlConnection, SshDocker, SshHostKeyPolicy, SshTunnel};

        let preset = match parse_preset(&p.policy_preset) {
            Ok(v) => v,
            Err(e) => {
                return Ok(CallToolResponse::Complete(error_tool_result(e)));
            }
        };
        if p.name.trim().is_empty() {
            return Ok(CallToolResponse::Complete(error_tool_result(
                "connection name must not be empty",
            )));
        }
        if p.host.trim().is_empty() {
            return Ok(CallToolResponse::Complete(error_tool_result(
                "host must not be empty",
            )));
        }
        if p.user.trim().is_empty() {
            return Ok(CallToolResponse::Complete(error_tool_result(
                "user must not be empty",
            )));
        }

        let bridge_tool = match p.ssh_docker_bridge_tool.as_deref() {
            None => BridgeTool::Nc,
            Some("nc") => BridgeTool::Nc,
            Some("ncat") => BridgeTool::Ncat,
            Some("socat") => BridgeTool::Socat,
            Some(other) => {
                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                    "unknown bridge tool {other:?} (nc | ncat | socat)"
                ))));
            }
        };
        let host_key_policy = match p.ssh_host_key_policy.as_deref() {
            None => None,
            Some("lenient") => Some(SshHostKeyPolicy::Lenient),
            Some("strict") => Some(SshHostKeyPolicy::Strict),
            Some(other) => {
                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                    "unknown host key policy {other:?} (lenient | strict)"
                ))));
            }
        };

        let ssh = match (p.ssh_host.as_deref(), p.ssh_user.as_deref()) {
            (Some(host), Some(user)) if !host.trim().is_empty() && !user.trim().is_empty() => {
                Some(SshTunnel {
                    host: host.trim().to_string(),
                    port: p.ssh_port.unwrap_or(22),
                    user: user.trim().to_string(),
                    auth_method: if p.ssh_key_path.is_some() {
                        crate::config::SshAuthMethod::Key
                    } else {
                        crate::config::SshAuthMethod::Password
                    },
                    private_key_path: p.ssh_key_path.clone(),
                    docker: p
                        .ssh_docker_container
                        .as_deref()
                        .map(|container| SshDocker {
                            container: container.to_string(),
                            bridge_tool,
                        }),
                    host_key_policy,
                    host_key_policy_migrated: false,
                    known_hosts_path: p.ssh_known_hosts_path.clone(),
                })
            }
            (None, None) => None,
            _ => {
                return Ok(CallToolResponse::Complete(error_tool_result(
                    "ssh tunnel requires both ssh_host and ssh_user",
                )));
            }
        };

        let port = p.port.unwrap_or(3306);
        let mut mc = MySqlConnection {
            name: p.name.clone(),
            host: p.host.trim().to_string(),
            port,
            user: p.user.trim().to_string(),
            database: p.database.clone(),
            ssl: p.ssl.unwrap_or(false),
            ssl_server_name: p.ssl_server_name.clone(),
            ssl_ca_path: p.ssl_ca_path.clone(),
            ssh,
            ..MySqlConnection::default()
        };
        mc.policy = crate::policy::model::policy_from_preset(preset);
        let conn = Connection::Mysql(mc);
        if let Err(e) = conn.validate() {
            return Ok(CallToolResponse::Complete(error_tool_result(format!(
                "{e}"
            ))));
        }

        // Elicit the password LAST, after every argument check, so a
        // prompt only ever appears for a connection that would save.
        let message = format!(
            "Enter MySQL/MariaDB password for {}@{}:{} (connection \"{}\"). Stored locally in the macOS Keychain; never in tool arguments or logs.",
            p.user.trim(),
            p.host.trim(),
            port,
            p.name
        );
        let password = match super::confirm::run_password_elicitation(&peer, message).await {
            Ok(pw) => pw,
            Err(reason) => {
                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                    "Password capture cancelled. Connection not saved. ({reason})"
                ))));
            }
        };

        let cfg = self
            .ctx
            .config
            .load()
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        let (name, user, preset_name) = (
            p.name.clone(),
            p.user.trim().to_string(),
            preset.as_str().to_string(),
        );
        match self.ctx.config.update(cfg.revision, move |c| {
            upsert(c, conn);
            Ok(())
        }) {
            Ok(()) => {
                if let Err(e) = self.ctx.secrets.set_password(&name, &user, &password) {
                    // The connection saved but the secret did not: say so
                    // plainly rather than pretending all is well.
                    return Ok(CallToolResponse::Complete(error_tool_result(format!(
                        "Saved connection \"{name}\", but storing the password failed: {e}. Re-add the connection or store the password manually."
                    ))));
                }
                Ok(CallToolResponse::Complete(text_tool_result(format!(
                    "Saved connection \"{name}\" with policy preset \"{preset_name}\". Password stored in the secret store (macOS Keychain)."
                ))))
            }
            Err(e) => Ok(CallToolResponse::Complete(error_tool_result(format!(
                "{e}"
            )))),
        }
    }

    /// restore_backup: dry-run returns the plan; execution is
    /// confirmation-gated (MRTR in the modern era, elicitation in the
    /// legacy era) and replays the plan on ONE connection inside ONE
    /// transaction, after a policy deny-check. Faithful to the legacy
    /// tool, which confirmed once and executed directly.
    async fn call_restore(
        &self,
        p: RestoreParams,
        modern: bool,
        peer: rmcp::service::Peer<rmcp::RoleServer>,
        request: rmcp::model::CallToolRequestParams,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        use crate::backup::restore::{RestoreDialect, plan_restore};

        let cfg = self
            .ctx
            .config
            .load()
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        let Some(detail) = crate::backup::restore::get_backup(&self.ctx.audit, p.backup_id) else {
            return Ok(CallToolResponse::Complete(error_tool_result(format!(
                "Backup #{} not found.",
                p.backup_id
            ))));
        };
        let Some(conn) = cfg.resolve(Some(detail.connection.as_str())).cloned() else {
            return Ok(CallToolResponse::Complete(error_tool_result(format!(
                "Connection {:?} referenced by backup no longer exists.",
                detail.connection
            ))));
        };
        let dialect = if conn.is_mysql() {
            RestoreDialect::MySql
        } else {
            RestoreDialect::SQLite
        };
        let plan = match plan_restore(&self.ctx.audit, p.backup_id, dialect) {
            Ok(plan) => plan,
            Err(e) => {
                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                    "Cannot plan restore: {e}"
                ))));
            }
        };

        if p.dry_run {
            return Ok(CallToolResponse::Complete(json_tool_result(json!({
                "backupId": p.backup_id,
                "connection": detail.connection,
                "rowCount": plan.row_count,
                "statementCount": plan.statements.len(),
                "warnings": plan.warnings,
                "isInsertHintDelete": plan.is_insert_hint_delete,
                "firstStatementPreview":
                    plan.statements.first().map(|s| s.chars().take(240).collect::<String>()),
                "note": "dry-run; pass dryRun=false to actually execute",
            }))));
        }
        if plan.statements.is_empty() {
            return Ok(CallToolResponse::Complete(json_tool_result(json!({
                "backupId": p.backup_id,
                "executedStatements": 0,
                "warnings": plan.warnings,
                "note": "nothing to restore",
            }))));
        }

        // Confirmation: modern era = MRTR one-shot state bound to the
        // backup id + policy revision; legacy era = elicitation.
        let digest = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(b"sequel-mcp/restore/v1\n");
            h.update(detail.connection.as_bytes());
            h.update(b"\n");
            h.update(p.backup_id.to_le_bytes());
            h.update(cfg.revision.to_le_bytes());
            d_hex(h)
        };

        if modern {
            if let Some(responses) = &request.input_responses {
                let state = request
                    .request_state
                    .as_deref()
                    .ok_or_else(|| rmcp::ErrorData::invalid_params("missing requestState", None))?;
                if state.len() > super::limits::MAX_REQUEST_STATE_BYTES {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!(
                            "[mrtr_invalid_state] requestState exceeds {} bytes",
                            super::limits::MAX_REQUEST_STATE_BYTES
                        ),
                        None,
                    ));
                }
                let _pending = super::mrtr::take(
                    state,
                    "restore_backup",
                    &detail.connection,
                    &digest,
                    cfg.revision,
                )
                .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("{}; approval rejected", e.message()),
                        None,
                    )
                })?;
                let value = responses.get("approval").cloned().ok_or_else(|| {
                    rmcp::ErrorData::invalid_params("missing approval response", None)
                })?;
                match super::mrtr::parse_response(&value) {
                    crate::approval::ConfirmOutcome::Chosen(
                        crate::approval::GrantChoice::Decline,
                    ) => Ok(CallToolResponse::Complete(error_tool_result(
                        "Restore declined.",
                    ))),
                    outcome @ crate::approval::ConfirmOutcome::Chosen(_) => {
                        let _ = outcome;
                        self.execute_restore_plan(&conn, &detail, &plan).await
                    }
                    crate::approval::ConfirmOutcome::Unavailable { reason } => {
                        Ok(CallToolResponse::Complete(error_tool_result(format!(
                            "Restore needs confirmation, but no prompt could be shown: {reason}. Nothing was restored. This is not a refusal - set an explicit write policy, or restore outside this tool."
                        ))))
                    }
                }
            } else {
                use rmcp::model::{
                    ElicitRequestParams, ElicitationSchema, InputRequest, InputRequiredResult,
                };
                let message = format!(
                    "Restore backup #{}: {} statement(s) into {}.{}.{}\n\nWarnings: {}\n\nPick an authorization scope.",
                    p.backup_id,
                    plan.statements.len(),
                    detail.connection,
                    detail.database.as_deref().unwrap_or("<default>"),
                    detail.table_name,
                    if plan.warnings.is_empty() {
                        "(none)".to_string()
                    } else {
                        plan.warnings.join("; ")
                    }
                );
                let mut input_requests = std::collections::BTreeMap::new();
                input_requests.insert(
                    "approval".to_string(),
                    InputRequest::Elicitation(rmcp::model::ElicitRequest::new(
                        ElicitRequestParams::FormElicitationParams {
                            meta: None,
                            message,
                            requested_schema: ElicitationSchema::from_json_schema(
                                serde_json::json!({
                                    "type": "object",
                                    "properties": {
                                        "choice": {
                                            "type": "string",
                                            "title": "Authorization",
                                            "enum": ["once", "decline"]
                                        }
                                    },
                                    "required": ["choice"]
                                })
                                .as_object()
                                .cloned()
                                .unwrap_or_default(),
                            )
                            .map_err(|e| {
                                rmcp::ErrorData::internal_error(
                                    format!("elicitation schema: {e}"),
                                    None,
                                )
                            })?,
                        },
                    )),
                );
                let pending = super::mrtr::PendingApproval {
                    tool: "restore_backup",
                    connection: detail.connection.clone(),
                    operation_digest: digest,
                    policy_revision: cfg.revision,
                    approved_ddl_targets: None,
                    expires_at: std::time::Instant::now() + super::mrtr::TTL,
                };
                let state = super::mrtr::issue(pending);
                Ok(rmcp::model::CallToolResponse::InputRequired(
                    InputRequiredResult::new(Some(input_requests), Some(state)),
                ))
            }
        } else {
            // Legacy era: elicit directly through the session peer.
            let message = format!(
                "About to RESTORE backup #{}: {} statement(s) into {}.{}.{}",
                p.backup_id,
                plan.statements.len(),
                detail.connection,
                detail.database.as_deref().unwrap_or("<default>"),
                detail.table_name
            );
            let outcome = super::confirm::run_elicitation(&peer, message).await;
            match outcome {
                crate::approval::ConfirmOutcome::Chosen(crate::approval::GrantChoice::Decline) => {
                    Ok(CallToolResponse::Complete(error_tool_result(
                        "Restore declined.",
                    )))
                }
                crate::approval::ConfirmOutcome::Chosen(_) => {
                    self.execute_restore_plan(&conn, &detail, &plan).await
                }
                crate::approval::ConfirmOutcome::Unavailable { reason } => {
                    Ok(CallToolResponse::Complete(error_tool_result(format!(
                        "Restore needs confirmation, but no prompt could be shown: {reason}. Nothing was restored. This is not a refusal."
                    ))))
                }
            }
        }
    }

    /// Replay the plan on one connection in one transaction, after a
    /// policy deny-check (writes must not be denied for the backup's
    /// table scope).
    async fn execute_restore_plan(
        &self,
        conn: &crate::config::Connection,
        detail: &crate::backup::restore::BackupDetail,
        plan: &crate::backup::restore::RestorePlan,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        // Policy deny-check: classify the first statement; a Deny on the
        // write scope refuses the restore before touching anything.
        let dialect = if conn.is_mysql() {
            crate::policy::classifier::Dialect::MySql
        } else {
            crate::policy::classifier::Dialect::SQLite
        };
        let classified =
            crate::policy::classifier::classify_statement(&plan.statements[0], dialect).map_err(
                |e| {
                    rmcp::ErrorData::internal_error(
                        format!("cannot classify restore statement: {}", e.message()),
                        None,
                    )
                },
            )?;
        let fallback = detail
            .database
            .clone()
            .or_else(|| conn.database().map(str::to_string));
        let resolution = crate::policy::resolver::resolve(conn, &classified, fallback.as_deref());
        if resolution.action == crate::policy::model::PolicyAction::Deny {
            return Ok(CallToolResponse::Complete(error_tool_result(
                "Restore denied by policy for this connection/table scope.",
            )));
        }

        let started = std::time::Instant::now();
        let result: Result<crate::backup::restore::RestoreOutcome, String> = match conn {
            crate::config::Connection::Sqlite(sc) => {
                let sc = sc.clone();
                let stmts = plan.statements.clone();
                tokio::task::spawn_blocking(move || {
                    let db = crate::sql::sqlite::open_sqlite_database(
                        &sc,
                        false,
                        sc.policy.stmt_timeout_ms,
                    )
                    .map_err(|e| e.to_string())?;
                    db.execute_batch("BEGIN IMMEDIATE")
                        .map_err(|e| e.to_string())?;
                    match crate::backup::restore::execute_restore_sqlite(&db, &fake_plan(&stmts)) {
                        Ok(r) => {
                            db.execute_batch("COMMIT").map_err(|e| e.to_string())?;
                            Ok(r)
                        }
                        Err(e) => {
                            let _ = db.execute_batch("ROLLBACK");
                            Err(e.to_string())
                        }
                    }
                })
                .await
                .map_err(|e| format!("join: {e}"))
                .and_then(|r| r)
            }
            crate::config::Connection::Mysql(mc) => {
                let Some(password) = self.ctx.secrets.get_password(&mc.name, &mc.user).ok() else {
                    return Ok(CallToolResponse::Complete(error_tool_result(format!(
                        "No password for {:?}.",
                        mc.name
                    ))));
                };
                let (host, port) = match &mc.ssh {
                    Some(ssh) => {
                        let ssh_pw = self
                            .ctx
                            .secrets
                            .get_password(&format!("{}::ssh", mc.name), &ssh.user)
                            .ok();
                        match crate::sql::ssh::tunnel_endpoint(
                            &mc.name,
                            ssh,
                            ssh_pw.as_ref().map(|p| p.as_str()),
                            &mc.host,
                            mc.port,
                            1,
                        )
                        .await
                        {
                            Ok(lease) => (lease.host, lease.port),
                            Err(e) => {
                                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                                    "ssh tunnel: {e}"
                                ))));
                            }
                        }
                    }
                    None => (mc.host.clone(), mc.port),
                };
                let mc = mc.clone();
                let db = detail.database.clone();
                let stmts = plan.statements.clone();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let opts = crate::sql::mysql::build_opts(
                            &mc,
                            &password,
                            db.as_deref(),
                            Some(&host),
                            Some(port),
                        );
                        use mysql_async::prelude::Queryable;
                        let mut c = mysql_async::Conn::new(opts)
                            .await
                            .map_err(|e| format!("connect: {e}"))?;
                        c.query_drop("START TRANSACTION READ WRITE")
                            .await
                            .map_err(|e| format!("start tx: {e}"))?;
                        let mut affected: u64 = 0;
                        let mut run = 0usize;
                        for stmt in &stmts {
                            match c.query_iter(stmt.as_str()).await {
                                Ok(_) => {
                                    affected += c.affected_rows();
                                    run += 1;
                                }
                                Err(e) => {
                                    let _ = c.query_drop("ROLLBACK").await;
                                    return Err(format!("statement {run} failed: {e}"));
                                }
                            }
                        }
                        c.query_drop("COMMIT")
                            .await
                            .map_err(|e| format!("commit: {e}"))?;
                        let _ = c.disconnect().await;
                        Ok(crate::backup::restore::RestoreOutcome {
                            statements_run: run,
                            affected,
                        })
                    })
                })
            }
        };

        match result {
            Ok(r) => Ok(CallToolResponse::Complete(json_tool_result(json!({
                "backupId": detail.id,
                "executedStatements": r.statements_run,
                "affected": r.affected,
                "warnings": plan.warnings,
                "durationMs": started.elapsed().as_millis() as u64,
            })))),
            Err(e) => Ok(CallToolResponse::Complete(error_tool_result(format!(
                "Restore failed: {e}"
            )))),
        }
    }
}

fn d_hex(h: sha2::Sha256) -> String {
    use sha2::Digest;
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn fake_plan(stmts: &[String]) -> crate::backup::restore::RestorePlan {
    crate::backup::restore::RestorePlan {
        backup_id: 0,
        statements: stmts.to_vec(),
        row_count: 0,
        warnings: Vec::new(),
        is_insert_hint_delete: false,
    }
}

/// Approval sink with a pre-decided outcome (MRTR retry path).
struct PreDecidedSink(crate::approval::ConfirmOutcome);

impl gate::ApprovalSink for PreDecidedSink {
    fn confirm(&self, _request: gate::ApprovalRequest) -> crate::approval::ConfirmOutcome {
        self.0.clone()
    }
}

fn mysql_user(c: &Connection) -> Option<String> {
    match c {
        Connection::Mysql(m) => Some(m.user.clone()),
        Connection::Sqlite(_) => None,
    }
}

fn upsert(cfg: &mut crate::config::Config, conn: Connection) {
    match cfg.connections.iter_mut().find(|c| c.name() == conn.name()) {
        Some(slot) => *slot = conn,
        None => cfg.connections.push(conn),
    }
}

#[tool_handler]
impl ServerHandler for SequelServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        super::build_server_info()
    }

    // ---- Prompts (legacy `server/prompts.ts` parity) ----

    fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::ListPromptsResult, rmcp::ErrorData>> + '_ {
        use rmcp::model::{Prompt, PromptArgument};
        let setup = Prompt::new(
            "setup-connection",
            Some("Walks through adding either a MySQL/MariaDB connection with Keychain password capture or a SQLite file connection with no password."),
            Some(vec![PromptArgument::new("suggestedName")
                .with_title("Suggested name")
                .with_description("Optional name to prefill")]),
        )
        .with_title("Set up a new database connection");
        let analyze = Prompt::new(
            "analyze-table",
            Some("Read-only investigation: schema, row count, indexes, sample rows."),
            Some(vec![
                PromptArgument::new("connection")
                    .with_title("Connection")
                    .with_required(true),
                PromptArgument::new("database").with_title("Database"),
                PromptArgument::new("table")
                    .with_title("Table")
                    .with_required(true),
            ]),
        )
        .with_title("Analyze a table");
        std::future::ready(Ok(rmcp::model::ListPromptsResult::with_all_items(vec![
            setup, analyze,
        ])))
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::GetPromptResponse, rmcp::ErrorData> {
        use rmcp::model::{GetPromptResult, PromptMessage, Role};
        let arg = |k: &str| -> Option<String> {
            request
                .arguments
                .as_ref()
                .and_then(|a| a.get(k))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let (text, description): (String, Option<&str>) = match request.name.as_str() {
            "setup-connection" => {
                let name = arg("suggestedName");
                let named = match &name {
                    Some(n) => format!(" called \"{n}\""),
                    None => String::new(),
                };
                (
                    format!(
                        "I want to add a new database connection{named}.\n\n\
First ask whether it is MySQL/MariaDB or SQLite. For MySQL/MariaDB, use \"add_connection\" and ask for: name, host, port (default 3306), user, database (optional), ssl (default false), policy preset (read-only | dev | admin), and optional SSH tunnel (host/port/user/keyPath). The tool will then prompt me for the password via elicitation. Do NOT include the password in the tool arguments. For SQLite, use \"add_sqlite_connection\" and ask for name, path, database/schema (usually main), and policy preset; no password is used."
                    ),
                    Some("Set up a new database connection"),
                )
            }
            "analyze-table" => {
                let Some(connection) = arg("connection") else {
                    return Err(rmcp::ErrorData::invalid_params(
                        "missing required argument \"connection\"",
                        None,
                    ));
                };
                let Some(table) = arg("table") else {
                    return Err(rmcp::ErrorData::invalid_params(
                        "missing required argument \"table\"",
                        None,
                    ));
                };
                let database = arg("database");
                let in_db = match &database {
                    Some(d) => format!(" in database `{d}`"),
                    None => String::new(),
                };
                (
                    format!(
                        "Analyze table `{table}`{in_db} on connection \"{connection}\". \
Use only read-only tools: describe_table, list_databases, and query (SELECT/SHOW or read-only SQLite PRAGMA only). Specifically: \
1) describe schema, 2) inspect indexes (SHOW INDEX for MySQL/MariaDB; PRAGMA index_list/index_info for SQLite), 3) SELECT COUNT(*), 4) SELECT * LIMIT 5. Summarize findings."
                    ),
                    Some("Analyze a table"),
                )
            }
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("unknown prompt: {other:?}"),
                    None,
                ));
            }
        };
        Ok(rmcp::model::GetPromptResponse::from(
            GetPromptResult::new(vec![PromptMessage::new_text(Role::User, text)])
                .with_description(description.unwrap_or_default()),
        ))
    }

    // ---- Resources (legacy `server/resources.ts` parity) ----

    fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::ListResourcesResult, rmcp::ErrorData>> + '_ {
        let resource = rmcp::model::Resource::new("sequel-mcp://connections", "connections")
            .with_title("Configured connections")
            .with_description("JSON listing of saved connections (no secrets).")
            .with_mime_type("application/json");
        std::future::ready(Ok(rmcp::model::ListResourcesResult::with_all_items(vec![
            resource,
        ])))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        use rmcp::model::{ReadResourceResult, ResourceContents};
        if request.uri != *"sequel-mcp://connections" {
            return Err(rmcp::ErrorData::invalid_params(
                format!("unknown resource: {:?}", request.uri),
                None,
            ));
        }
        let cfg = self
            .ctx
            .config
            .load()
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        let presets: Vec<&str> = crate::policy::model::POLICY_PRESET_NAMES.to_vec();
        let items: Vec<serde_json::Value> = cfg
            .connections
            .iter()
            .map(|c| {
                let (host, port, user, ssh_json) = match c {
                    crate::config::Connection::Mysql(m) => {
                        let ssh_json = m.ssh.as_ref().map(|ssh| {
                            json!({
                                "host": ssh.host,
                                "user": ssh.user,
                                "docker": ssh.docker.as_ref().map(|d| json!({
                                    "container": d.container,
                                    "bridgeTool": d.bridge_tool.as_str(),
                                })),
                            })
                        });
                        (json!(m.host), json!(m.port), json!(m.user), ssh_json)
                    }
                    crate::config::Connection::Sqlite(_) => (
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        None,
                    ),
                };
                let has_password = c.is_mysql()
                    && self
                        .ctx
                        .secrets
                        .has_password(c.name(), mysql_user(c).as_deref().unwrap_or(""));
                json!({
                    "name": c.name(),
                    "driver": if c.is_mysql() { "mysql" } else { "sqlite" },
                    "host": host,
                    "port": port,
                    "user": user,
                    "path": if c.is_mysql() { serde_json::Value::Null } else {
                        match c {
                            crate::config::Connection::Sqlite(s) => json!(s.path),
                            _ => serde_json::Value::Null,
                        }
                    },
                    "database": c.database(),
                    "ssh": ssh_json,
                    "policy": c.policy(),
                    "presets": presets,
                    "hasPassword": has_password,
                })
            })
            .collect();
        let text = serde_json::to_string_pretty(&json!({ "connections": items }))
            .unwrap_or_else(|_| "{\n  \"connections\": []\n}".into());
        Ok(rmcp::model::ReadResourceResponse::from(
            ReadResourceResult::new(vec![
                ResourceContents::text(text, "sequel-mcp://connections")
                    .with_mime_type("application/json"),
            ]),
        ))
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let name = request.name.as_ref();
        if name == "add_connection" {
            let arg_value =
                serde_json::Value::Object(request.arguments.clone().unwrap_or_default());
            let Ok(p) = serde_json::from_value::<AddConnectionParams>(arg_value) else {
                return Ok(CallToolResponse::Complete(error_tool_result(
                    "invalid arguments for add_connection",
                )));
            };
            return self.call_add_connection(p, context.peer.clone()).await;
        }
        if name == "restore_backup" {
            let arg_value =
                serde_json::Value::Object(request.arguments.clone().unwrap_or_default());
            let Ok(p) = serde_json::from_value::<RestoreParams>(arg_value) else {
                return Ok(CallToolResponse::Complete(error_tool_result(
                    "invalid arguments for restore_backup",
                )));
            };
            let modern = context
                .meta
                .protocol_version()
                .map(|v| v >= rmcp::model::ProtocolVersion::V_2026_07_28)
                .unwrap_or(false);
            return self
                .call_restore(p, modern, context.peer.clone(), request)
                .await;
        }
        if name == "query" || name == "execute" {
            let expect_read_only = name == "query";
            let tool: &'static str = if expect_read_only { "query" } else { "execute" };
            let arg_value =
                serde_json::Value::Object(request.arguments.clone().unwrap_or_default());
            let params: Result<SqlParams, _> = serde_json::from_value(arg_value);
            let Ok(p) = params else {
                return Ok(CallToolResponse::Complete(error_tool_result(
                    "invalid arguments for query/execute",
                )));
            };
            if p.sql.len() > super::limits::MAX_TOOL_ARGUMENT_BYTES {
                return Ok(CallToolResponse::Complete(error_tool_result(format!(
                    "[argument_too_large] sql argument exceeds {} bytes",
                    super::limits::MAX_TOOL_ARGUMENT_BYTES
                ))));
            }

            // Modern (2026-07-28) era: rmcp's stdio server does not
            // propagate per-request _meta capabilities into the legacy
            // elicit path, so approvals go through MRTR here. The wire
            // _meta lives in the RequestContext, not the deserialized
            // params.
            let modern = context
                .meta
                .protocol_version()
                .map(|v| v >= rmcp::model::ProtocolVersion::V_2026_07_28)
                .unwrap_or(false);

            if modern {
                return self
                    .call_sql_modern(request, p, expect_read_only, tool)
                    .await;
            }

            let args = RunSqlArgs {
                connection: p.connection,
                sql: p.sql,
                database: p.database,
                expected_ddl_targets: None,
            };
            // Gate on the blocking pool; elicitation asks flow back over a
            // channel and are answered from the async runtime by a pump
            // thread (block_on from a blocking thread is legal).
            let (ask_tx, ask_rx) = std::sync::mpsc::sync_channel::<super::confirm::ElicitAsk>(4);
            let sink = super::confirm::ElicitationSink::new(ask_tx);
            let deps = self.gate_deps_blocking(Box::new(sink));
            let handle =
                tokio::task::spawn_blocking(move || gate::run_sql(&deps, &args, expect_read_only));
            let peer = context.peer.clone();
            let ipc_hub = self.ctx.approval_ipc.clone();
            let pump = tokio::task::spawn_blocking(move || {
                while let Ok(ask) = ask_rx.recv() {
                    match ask {
                        super::confirm::ElicitAsk::Request { message, reply } => {
                            let mut outcome = tokio::runtime::Handle::current().block_on(async {
                                super::confirm::run_elicitation(&peer, message.clone()).await
                            });
                            // Elicitation unavailable (client cannot
                            // prompt): fall back to the authenticated
                            // companion IPC and fail closed there too.
                            if matches!(
                                outcome,
                                crate::approval::ConfirmOutcome::Unavailable { .. }
                            ) && let Some(hub) = &ipc_hub
                            {
                                let request = gate::ApprovalRequest::from_message(&message);
                                outcome =
                                    tokio::runtime::Handle::current().block_on(hub.ask(request));
                            }
                            let _ = reply.send(outcome);
                        }
                    }
                }
            });
            let outcome = match handle.await {
                Ok(r) => r,
                Err(e) => Err(gate::GateError::Execution(format!("gate task failed: {e}"))),
            };
            // The pump exits once the gate (and its sink) drop the channel.
            let _ = pump.await;
            let result = match outcome {
                Ok(out) => super::json_tool_result(gate::outcome_to_json(&out)),
                Err(e) => super::error_tool_result(e.to_string()),
            };
            return Ok(CallToolResponse::Complete(result));
        }

        // Everything else: delegate to the macro-generated router.
        let tcc = ToolCallContext::new(self, request, context);
        Self::tool_router().call(tcc).await
    }
}
