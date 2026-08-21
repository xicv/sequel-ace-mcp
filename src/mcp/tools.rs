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

fn gate_deps_blocking(sink: Box<dyn gate::ApprovalSink>) -> GateDeps {
    GateDeps::with_sink(sink)
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
        let deps = gate_deps_blocking(Box::new(gate::UnavailableSink));
        match gate::run_sql(&deps, &args, expect_read_only) {
            Ok(out) => json_tool_result(gate::outcome_to_json(&out)),
            Err(e) => error_tool_result(e.to_string()),
        }
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

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let name = request.name.as_ref();
        if name == "query" || name == "execute" {
            let expect_read_only = name == "query";
            let arg_value =
                serde_json::Value::Object(request.arguments.clone().unwrap_or_default());
            let params: Result<SqlParams, _> = serde_json::from_value(arg_value);
            let Ok(p) = params else {
                return Ok(CallToolResponse::Complete(error_tool_result(
                    "invalid arguments for query/execute",
                )));
            };
            let args = RunSqlArgs {
                connection: p.connection,
                sql: p.sql,
                database: p.database,
            };
            // Gate on the blocking pool; elicitation asks flow back over a
            // channel and are answered from the async runtime by a pump
            // thread (block_on from a blocking thread is legal).
            let (ask_tx, ask_rx) = std::sync::mpsc::sync_channel::<super::confirm::ElicitAsk>(4);
            let sink = super::confirm::ElicitationSink::new(ask_tx);
            let deps = gate_deps_blocking(Box::new(sink));
            let handle =
                tokio::task::spawn_blocking(move || gate::run_sql(&deps, &args, expect_read_only));
            let peer = context.peer.clone();
            let pump = tokio::task::spawn_blocking(move || {
                while let Ok(ask) = ask_rx.recv() {
                    match ask {
                        super::confirm::ElicitAsk::Request { message, reply } => {
                            let outcome = tokio::runtime::Handle::current().block_on(async {
                                super::confirm::run_elicitation(&peer, message).await
                            });
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
