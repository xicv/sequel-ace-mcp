//! Policy model: categories, actions, connection baselines, table rules.
//!
//! Mirrors the legacy TypeScript schema (defaults included) and adds the
//! v2 table-rule layer. Validation bounds match `types.ts` exactly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SQL_CATEGORIES: [&str; 5] = ["read", "write", "ddl", "admin", "txCtrl"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SqlCategory {
    Read,
    Write,
    Ddl,
    Admin,
    TxCtrl,
}

impl std::fmt::Display for SqlCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SqlCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SqlCategory::Read => "read",
            SqlCategory::Write => "write",
            SqlCategory::Ddl => "ddl",
            SqlCategory::Admin => "admin",
            SqlCategory::TxCtrl => "txCtrl",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(SqlCategory::Read),
            "write" => Some(SqlCategory::Write),
            "ddl" => Some(SqlCategory::Ddl),
            "admin" => Some(SqlCategory::Admin),
            "txCtrl" => Some(SqlCategory::TxCtrl),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PolicyAction {
    Allow,
    Confirm,
    Deny,
}

impl PolicyAction {
    /// Strictness ranking used by strictest-wins resolution.
    pub fn rank(&self) -> u8 {
        match self {
            PolicyAction::Allow => 0,
            PolicyAction::Confirm => 1,
            PolicyAction::Deny => 2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyAction::Allow => "allow",
            PolicyAction::Confirm => "confirm",
            PolicyAction::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum BackupOverflow {
    Abort,
    Truncate,
}

/// Complete connection baseline. Field defaults replicate the legacy zod
/// schema so a v1 policy object with omitted fields parses identically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Policy {
    pub read: PolicyAction,
    pub write: PolicyAction,
    pub ddl: PolicyAction,
    pub admin: PolicyAction,
    pub tx_ctrl: PolicyAction,
    pub row_cap: u32,
    pub stmt_timeout_ms: u32,
    pub require_touch_id: bool,
    pub max_backup_rows: u32,
    pub max_backup_bytes: u64,
    pub on_backup_overflow: BackupOverflow,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            read: PolicyAction::Allow,
            write: PolicyAction::Confirm,
            ddl: PolicyAction::Deny,
            admin: PolicyAction::Deny,
            tx_ctrl: PolicyAction::Allow,
            row_cap: 1000,
            stmt_timeout_ms: 10_000,
            require_touch_id: false,
            max_backup_rows: 10_000,
            max_backup_bytes: 50 * 1024 * 1024,
            on_backup_overflow: BackupOverflow::Abort,
        }
    }
}

impl Policy {
    pub fn action_for(&self, category: SqlCategory) -> PolicyAction {
        match category {
            SqlCategory::Read => self.read,
            SqlCategory::Write => self.write,
            SqlCategory::Ddl => self.ddl,
            SqlCategory::Admin => self.admin,
            SqlCategory::TxCtrl => self.tx_ctrl,
        }
    }

    /// Legacy semantics: a partial override merges field-by-field onto the
    /// baseline. `None` fields fall through to `self`.
    pub fn merged_with(&self, over: &PartialPolicy) -> Policy {
        let mut next = self.clone();
        if let Some(v) = over.read {
            next.read = v;
        }
        if let Some(v) = over.write {
            next.write = v;
        }
        if let Some(v) = over.ddl {
            next.ddl = v;
        }
        if let Some(v) = over.admin {
            next.admin = v;
        }
        if let Some(v) = over.tx_ctrl {
            next.tx_ctrl = v;
        }
        if let Some(v) = over.row_cap {
            next.row_cap = v;
        }
        if let Some(v) = over.stmt_timeout_ms {
            next.stmt_timeout_ms = v;
        }
        if let Some(v) = over.require_touch_id {
            next.require_touch_id = v;
        }
        if let Some(v) = over.max_backup_rows {
            next.max_backup_rows = v;
        }
        if let Some(v) = over.max_backup_bytes {
            next.max_backup_bytes = v;
        }
        if let Some(v) = over.on_backup_overflow {
            next.on_backup_overflow = v;
        }
        next
    }

    /// Validate against the legacy bounds. Errors carry the offending field.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.row_cap == 0 || self.row_cap > 100_000 {
            return Err("rowCap must be an integer in 1..=100000");
        }
        if self.stmt_timeout_ms == 0 || self.stmt_timeout_ms > 600_000 {
            return Err("stmtTimeoutMs must be an integer in 1..=600000");
        }
        if self.max_backup_rows == 0 || self.max_backup_rows > 1_000_000 {
            return Err("maxBackupRows must be an integer in 1..=1000000");
        }
        if self.max_backup_bytes == 0 {
            return Err("maxBackupBytes must be positive");
        }
        Ok(())
    }
}

/// Partial policy override (legacy `PartialPolicySchema` + table rules).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct PartialPolicy {
    pub read: Option<PolicyAction>,
    pub write: Option<PolicyAction>,
    pub ddl: Option<PolicyAction>,
    pub admin: Option<PolicyAction>,
    pub tx_ctrl: Option<PolicyAction>,
    pub row_cap: Option<u32>,
    pub stmt_timeout_ms: Option<u32>,
    pub require_touch_id: Option<bool>,
    pub max_backup_rows: Option<u32>,
    pub max_backup_bytes: Option<u64>,
    pub on_backup_overflow: Option<BackupOverflow>,
}

impl PartialPolicy {
    pub fn action_for(&self, category: SqlCategory) -> Option<PolicyAction> {
        match category {
            SqlCategory::Read => self.read,
            SqlCategory::Write => self.write,
            SqlCategory::Ddl => self.ddl,
            SqlCategory::Admin => self.admin,
            SqlCategory::TxCtrl => self.tx_ctrl,
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == PartialPolicy::default()
    }
}

/// Named presets. `development` is the new name for legacy `dev`; both parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPresetName {
    ReadOnly,
    Development,
    Administration,
}

impl PolicyPresetName {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read-only" => Some(Self::ReadOnly),
            "dev" | "development" => Some(Self::Development),
            "admin" | "administration" => Some(Self::Administration),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyPresetName::ReadOnly => "read-only",
            PolicyPresetName::Development => "development",
            PolicyPresetName::Administration => "administration",
        }
    }
}

pub fn policy_from_preset(preset: PolicyPresetName) -> Policy {
    match preset {
        PolicyPresetName::ReadOnly => Policy {
            read: PolicyAction::Allow,
            write: PolicyAction::Deny,
            ddl: PolicyAction::Deny,
            admin: PolicyAction::Deny,
            tx_ctrl: PolicyAction::Allow,
            row_cap: 1000,
            stmt_timeout_ms: 10_000,
            require_touch_id: false,
            max_backup_rows: 10_000,
            max_backup_bytes: 50 * 1024 * 1024,
            on_backup_overflow: BackupOverflow::Abort,
        },
        PolicyPresetName::Development => Policy {
            read: PolicyAction::Allow,
            write: PolicyAction::Confirm,
            ddl: PolicyAction::Confirm,
            admin: PolicyAction::Deny,
            tx_ctrl: PolicyAction::Allow,
            row_cap: 5000,
            stmt_timeout_ms: 30_000,
            require_touch_id: false,
            max_backup_rows: 10_000,
            max_backup_bytes: 50 * 1024 * 1024,
            on_backup_overflow: BackupOverflow::Abort,
        },
        PolicyPresetName::Administration => Policy {
            read: PolicyAction::Allow,
            write: PolicyAction::Confirm,
            ddl: PolicyAction::Confirm,
            admin: PolicyAction::Confirm,
            tx_ctrl: PolicyAction::Allow,
            row_cap: 5000,
            stmt_timeout_ms: 60_000,
            require_touch_id: true,
            max_backup_rows: 10_000,
            max_backup_bytes: 50 * 1024 * 1024,
            on_backup_overflow: BackupOverflow::Abort,
        },
    }
}

pub const POLICY_PRESET_NAMES: [&str; 3] = ["read-only", "development", "administration"];

/// Retention defaults per category (legacy `DEFAULT_RETENTION_BY_CATEGORY`).
pub fn default_retention_days(category: SqlCategory) -> u32 {
    match category {
        SqlCategory::Read => 7,
        SqlCategory::Write => 30,
        SqlCategory::Ddl => 90,
        SqlCategory::Admin => 180,
        SqlCategory::TxCtrl => 7,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RetentionByCategory {
    pub read: u32,
    pub write: u32,
    pub ddl: u32,
    pub admin: u32,
    pub tx_ctrl: u32,
}

impl Default for RetentionByCategory {
    fn default() -> Self {
        Self {
            read: 7,
            write: 30,
            ddl: 90,
            admin: 180,
            tx_ctrl: 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RetentionConfig {
    pub retention_days_by_category: RetentionByCategory,
    pub backup_days: u32,
    pub audit_max_mb: u32,
    pub backup_max_mb: u32,
    pub auto_cleanup_hours: u32,
    pub redact_sql_in_log: bool,
    pub tamper_evident_chain: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_days_by_category: RetentionByCategory::default(),
            backup_days: 30,
            audit_max_mb: 500,
            backup_max_mb: 1000,
            auto_cleanup_hours: 24,
            redact_sql_in_log: false,
            tamper_evident_chain: false,
        }
    }
}

/// A qualified table target: `<database>.<table>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TableId {
    pub database: String,
    pub table: String,
}

impl TableId {
    pub fn new(database: impl Into<String>, table: impl Into<String>) -> Self {
        Self {
            database: database.into(),
            table: table.into(),
        }
    }
}

/// v2 layer-2 rule key. `Wildcard(db)` represents `db.*` (legacy per-database
/// override); `Exact(TableId)` represents an exact table rule. Serializes
/// as its rendered string so JSON config maps stay string-keyed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TableRuleKey {
    Exact(TableId),
    Wildcard { database: String },
}

impl serde::Serialize for TableRuleKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.render())
    }
}

impl<'de> serde::Deserialize<'de> for TableRuleKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        TableRuleKey::parse(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid table rule key {s:?}")))
    }
}

impl TableRuleKey {
    pub fn parse(s: &str) -> Option<Self> {
        let (db, table) = s.split_once('.')?;
        if db.is_empty() {
            return None;
        }
        if table == "*" {
            Some(TableRuleKey::Wildcard {
                database: db.to_string(),
            })
        } else if table.is_empty() {
            None
        } else {
            Some(TableRuleKey::Exact(TableId::new(db, table)))
        }
    }

    pub fn render(&self) -> String {
        match self {
            TableRuleKey::Exact(t) => format!("{}.{}", t.database, t.table),
            TableRuleKey::Wildcard { database } => format!("{database}.*"),
        }
    }

    /// Does this rule govern `table`? Exact rules match one table; wildcard
    /// rules match every table in the database.
    pub fn governs(&self, table: &TableId) -> bool {
        match self {
            TableRuleKey::Exact(t) => t == table,
            TableRuleKey::Wildcard { database } => database == &table.database,
        }
    }
}

pub type TablePolicies = BTreeMap<TableRuleKey, PartialPolicy>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_legacy_schema() {
        let p = Policy::default();
        assert_eq!(p.read, PolicyAction::Allow);
        assert_eq!(p.write, PolicyAction::Confirm);
        assert_eq!(p.ddl, PolicyAction::Deny);
        assert_eq!(p.admin, PolicyAction::Deny);
        assert_eq!(p.tx_ctrl, PolicyAction::Allow);
        assert_eq!(p.row_cap, 1000);
        assert_eq!(p.stmt_timeout_ms, 10_000);
        assert_eq!(p.max_backup_rows, 10_000);
        assert_eq!(p.max_backup_bytes, 52_428_800);
    }

    #[test]
    fn presets_parse_legacy_and_new_names() {
        assert_eq!(
            PolicyPresetName::parse("dev"),
            Some(PolicyPresetName::Development)
        );
        assert_eq!(
            PolicyPresetName::parse("admin"),
            Some(PolicyPresetName::Administration)
        );
        assert_eq!(
            policy_from_preset(PolicyPresetName::ReadOnly).write,
            PolicyAction::Deny
        );
        assert!(policy_from_preset(PolicyPresetName::Administration).require_touch_id);
    }

    #[test]
    fn table_rule_keys_parse_and_match() {
        let exact = TableRuleKey::parse("app.jobs").unwrap();
        let wild = TableRuleKey::parse("app.*").unwrap();
        let jobs = TableId::new("app", "jobs");
        assert!(exact.governs(&jobs));
        assert!(wild.governs(&jobs));
        assert!(!wild.governs(&TableId::new("analytics", "jobs")));
        assert_eq!(exact.render(), "app.jobs");
        assert_eq!(wild.render(), "app.*");
        assert!(TableRuleKey::parse("nodot").is_none());
        assert!(TableRuleKey::parse(".x").is_none());
    }

    #[test]
    fn merge_matches_legacy_spread() {
        let base = Policy::default();
        let over = PartialPolicy {
            write: Some(PolicyAction::Deny),
            row_cap: Some(42),
            ..PartialPolicy::default()
        };
        let merged = base.merged_with(&over);
        assert_eq!(merged.write, PolicyAction::Deny);
        assert_eq!(merged.row_cap, 42);
        assert_eq!(merged.read, PolicyAction::Allow);
    }
}
