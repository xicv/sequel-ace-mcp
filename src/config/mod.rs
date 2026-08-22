//! Configuration: connection model, v2 store with locked atomic writes,
//! and the v1 → v2 migration.

pub mod migrate;

use crate::policy::model::{PartialPolicy, Policy, RetentionConfig, TablePolicies, TableRuleKey};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

use crate::app::paths;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file is malformed: {0}")]
    Malformed(String),
    #[error("unsupported config version: {0}")]
    UnsupportedVersion(u64),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error(
        "revision conflict: config changed on disk (expected revision {expected}, found {found})"
    )]
    RevisionConflict { expected: u64, found: u64 },
    #[error("connection name {0:?} is invalid (allowed: A-Za-z0-9 _-:. up to 128 chars)")]
    InvalidConnectionName(String),
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshHostKeyPolicy {
    Lenient,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BridgeTool {
    Nc,
    Ncat,
    Socat,
}

impl BridgeTool {
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeTool::Nc => "nc",
            BridgeTool::Ncat => "ncat",
            BridgeTool::Socat => "socat",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nc" => Some(BridgeTool::Nc),
            "ncat" => Some(BridgeTool::Ncat),
            "socat" => Some(BridgeTool::Socat),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshDocker {
    pub container: String,
    pub bridge_tool: BridgeTool,
}

impl Default for SshDocker {
    fn default() -> Self {
        Self {
            container: String::new(),
            bridge_tool: BridgeTool::Nc,
        }
    }
}

impl SshDocker {
    pub fn validate(&self) -> Result<(), ConfigError> {
        crate::sql::docker::validate_container_name(&self.container)
            .map_err(ConfigError::Validation)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SshTunnel {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth_method: SshAuthMethod,
    pub private_key_path: Option<String>,
    pub docker: Option<SshDocker>,
    pub host_key_policy: Option<SshHostKeyPolicy>,
    /// Set when `host_key_policy` was inherited unset from v1 (lenient with
    /// a prominent warning rather than silently trusted).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub host_key_policy_migrated: bool,
    pub known_hosts_path: Option<String>,
}

impl Default for SshTunnel {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            user: String::new(),
            auth_method: SshAuthMethod::Key,
            private_key_path: None,
            docker: None,
            host_key_policy: None,
            host_key_policy_migrated: false,
            known_hosts_path: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshAuthMethod {
    Password,
    Key,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MySqlConnection {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: Option<String>,
    pub ssl: bool,
    pub ssl_server_name: Option<String>,
    /// Optional PEM/DER file of a private CA the server certificate is
    /// verified against (merged with the system roots).
    pub ssl_ca_path: Option<String>,
    pub ssh: Option<SshTunnel>,
    pub policy: Policy,
    /// v2 layer-2 rules (exact or wildcard). Migrated v1 `databasePolicies`
    /// appear here as `db.*` wildcards.
    pub table_policies: TablePolicies,
}

impl Default for MySqlConnection {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: String::new(),
            port: 3306,
            user: String::new(),
            database: None,
            ssl: false,
            ssl_server_name: None,
            ssl_ca_path: None,
            ssh: None,
            policy: Policy::default(),
            table_policies: TablePolicies::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SqliteConnection {
    pub name: String,
    pub path: String,
    pub database: String,
    pub policy: Policy,
    pub table_policies: TablePolicies,
}

impl Default for SqliteConnection {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            database: "main".to_string(),
            policy: Policy::default(),
            table_policies: TablePolicies::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "driver", rename_all = "lowercase")]
// Boxing the MySQL variant would ripple through every match site for a
// type that is constructed rarely and cloned per request anyway.
#[allow(clippy::large_enum_variant)]
pub enum Connection {
    Mysql(MySqlConnection),
    Sqlite(SqliteConnection),
}

impl Connection {
    pub fn name(&self) -> &str {
        match self {
            Connection::Mysql(c) => &c.name,
            Connection::Sqlite(c) => &c.name,
        }
    }

    pub fn database(&self) -> Option<&str> {
        match self {
            Connection::Mysql(c) => c.database.as_deref(),
            Connection::Sqlite(c) => Some(&c.database),
        }
    }

    pub fn policy(&self) -> &Policy {
        match self {
            Connection::Mysql(c) => &c.policy,
            Connection::Sqlite(c) => &c.policy,
        }
    }

    pub fn table_policies(&self) -> &TablePolicies {
        match self {
            Connection::Mysql(c) => &c.table_policies,
            Connection::Sqlite(c) => &c.table_policies,
        }
    }

    pub fn is_mysql(&self) -> bool {
        matches!(self, Connection::Mysql(_))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let name = self.name();
        let valid = !name.is_empty()
            && name.len() <= 128
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | ':' | '.'));
        if !valid {
            return Err(ConfigError::InvalidConnectionName(name.to_string()));
        }
        self.policy()
            .validate()
            .map_err(|e| ConfigError::Validation(e.into()))?;
        if let Connection::Mysql(c) = self {
            if c.host.is_empty() {
                return Err(ConfigError::Validation(
                    "mysql host must not be empty".into(),
                ));
            }
            if c.user.is_empty() {
                return Err(ConfigError::Validation(
                    "mysql user must not be empty".into(),
                ));
            }
            if let Some(name) = &c.ssl_server_name
                && (name.is_empty() || name.len() > 253)
            {
                return Err(ConfigError::Validation(
                    "sslServerName must be 1..=253 chars".into(),
                ));
            }
            if let Some(ca) = &c.ssl_ca_path
                && (ca.is_empty() || ca.len() > 4096)
            {
                return Err(ConfigError::Validation(
                    "sslCaPath must be 1..=4096 chars".into(),
                ));
            }
            if let Some(ssh) = &c.ssh {
                if ssh.host.is_empty() || ssh.user.is_empty() {
                    return Err(ConfigError::Validation(
                        "ssh host and user must not be empty".into(),
                    ));
                }
                if ssh.auth_method == SshAuthMethod::Key && ssh.private_key_path.is_none() {
                    return Err(ConfigError::Validation(
                        "ssh key auth requires privateKeyPath".into(),
                    ));
                }
                if let Some(d) = &ssh.docker {
                    d.validate()?;
                }
            }
        }
        if let Connection::Sqlite(c) = self {
            if c.path.is_empty() || c.path.len() > 4096 {
                return Err(ConfigError::Validation(
                    "sqlite path must be 1..=4096 chars".into(),
                ));
            }
            if c.database.is_empty() || c.database.len() > 64 {
                return Err(ConfigError::Validation(
                    "sqlite database (schema) must be 1..=64 chars".into(),
                ));
            }
        }
        Ok(())
    }
}

/// v2 top-level configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub version: u32,
    /// Compare-and-swap revision, bumped on every persisted change.
    pub revision: u64,
    pub connections: Vec<Connection>,
    pub default_connection: Option<String>,
    pub retention: RetentionConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            revision: 0,
            connections: Vec::new(),
            default_connection: None,
            retention: RetentionConfig::default(),
        }
    }
}

impl Config {
    pub fn get(&self, name: &str) -> Option<&Connection> {
        self.connections.iter().find(|c| c.name() == name)
    }

    pub fn resolve(&self, explicit: Option<&str>) -> Option<&Connection> {
        match explicit {
            Some(name) => self.get(name),
            None => self
                .default_connection
                .as_deref()
                .and_then(|def| self.get(def)),
        }
    }
}

/// Handle providing read/write access to the on-disk config with
/// inter-process locking and revision-checked writes.
#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: Arc<PathBuf>,
}

impl ConfigStore {
    pub fn new() -> Self {
        Self {
            path: Arc::new(paths::config_path()),
        }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Arc::new(path),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the config, transparently migrating a v1 file if found.
    pub fn load(&self) -> Result<Config, ConfigError> {
        if !self.path.exists() {
            return Ok(Config::default());
        }
        let raw = fs::read_to_string(&*self.path)?;
        let json: Json = serde_json::from_str(&raw)
            .map_err(|e| ConfigError::Malformed(format!("not valid JSON: {e}")))?;
        let version = json
            .get("version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ConfigError::Malformed("missing numeric version field".into()))?;
        match version {
            1 => {
                let v1 = migrate::parse_v1(&json)?;
                let v2 = migrate::v1_to_v2(v1);
                Ok(v2)
            }
            2 => serde_json::from_value(json).map_err(|e| {
                ConfigError::Malformed(format!("config does not match v2 schema: {e}"))
            }),
            other => Err(ConfigError::UnsupportedVersion(other)),
        }
    }

    /// Read-modify-write under the inter-process lock; the closure receives
    /// the current config and returns the next one. Revision is bumped and
    /// checked, so concurrent writers cannot silently overwrite each other.
    pub fn update<T>(
        &self,
        expected_revision: u64,
        mutate: impl FnOnce(&mut Config) -> Result<T, ConfigError>,
    ) -> Result<T, ConfigError> {
        let _guard = self.lock()?;
        let mut cfg = self.load_locked()?;
        if cfg.version == 1 {
            // v1 on disk: migrate in-memory before mutating (persist below
            // writes v2; the timestamped v1 backup is created by `migrate`).
            cfg = migrate::v1_to_v2(migrate::parse_v1(&serde_json::to_value(&cfg)?)?);
        }
        if cfg.revision != expected_revision {
            return Err(ConfigError::RevisionConflict {
                expected: expected_revision,
                found: cfg.revision,
            });
        }
        let out = mutate(&mut cfg)?;
        cfg.revision += 1;
        for c in &cfg.connections {
            c.validate()?;
        }
        if let Some(def) = &cfg.default_connection
            && !cfg.connections.iter().any(|c| c.name() == def)
        {
            return Err(ConfigError::Validation(format!(
                "default connection {def:?} does not exist"
            )));
        }
        self.persist(&cfg)?;
        Ok(out)
    }

    fn lock(&self) -> Result<fs::File, ConfigError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| ConfigError::Io(std::io::Error::other(e)))?;
            set_dir_mode_0700(parent);
        }
        let lock_path = self.path.with_extension("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        file.lock().map_err(std::io::Error::other)?;
        Ok(file)
    }

    fn load_locked(&self) -> Result<Config, ConfigError> {
        if !self.path.exists() {
            return Ok(Config::default());
        }
        let raw = fs::read_to_string(&*self.path)?;
        let json: Json = serde_json::from_str(&raw)
            .map_err(|e| ConfigError::Malformed(format!("not valid JSON: {e}")))?;
        let version = json
            .get("version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ConfigError::Malformed("missing numeric version field".into()))?;
        match version {
            1 => Ok(migrate::v1_to_v2(migrate::parse_v1(&json)?)),
            2 => serde_json::from_value(json).map_err(|e| {
                ConfigError::Malformed(format!("config does not match v2 schema: {e}"))
            }),
            other => Err(ConfigError::UnsupportedVersion(other)),
        }
    }

    /// Persist atomically: temp file (0600) → fsync → rename → fsync parent.
    pub(crate) fn persist(&self, cfg: &Config) -> Result<(), ConfigError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ConfigError::Validation("config path has no parent".into()))?;
        fs::create_dir_all(parent).map_err(std::io::Error::other)?;
        set_dir_mode_0700(parent);
        let mut json = serde_json::to_string_pretty(cfg)?;
        json.push('\n');
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                    .map_err(std::io::Error::other)?;
            }
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &*self.path)?;
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
fn set_dir_mode_0700(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_dir: &Path) {}

/// Partial policy map parsed from legacy `databasePolicies` JSON objects.
pub(crate) fn parse_partial_map(
    value: &Json,
) -> Result<BTreeMap<String, PartialPolicy>, ConfigError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ConfigError::Malformed("databasePolicies must be an object".into()))?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        if k.is_empty() || k.len() > 64 {
            return Err(ConfigError::Malformed(format!(
                "database policy key {k:?} out of bounds"
            )));
        }
        let partial: PartialPolicy = serde_json::from_value(v.clone())
            .map_err(|e| ConfigError::Malformed(format!("bad partial policy for {k:?}: {e}")))?;
        out.insert(k.clone(), partial);
    }
    Ok(out)
}

/// Helper for the wrapper tools: read a `db.*` rule as the legacy shape.
pub fn wildcard_rule<'a>(connection: &'a Connection, database: &str) -> Option<&'a PartialPolicy> {
    connection.table_policies().get(&TableRuleKey::Wildcard {
        database: database.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::{PolicyAction, TableId};

    fn tmp_store() -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::with_path(dir.path().join("config.json"));
        (dir, store)
    }

    #[test]
    fn pristine_install_loads_default() {
        let (_dir, store) = tmp_store();
        let cfg = store.load().unwrap();
        assert_eq!(cfg.version, 2);
        assert!(cfg.connections.is_empty());
        assert_eq!(cfg.revision, 0);
    }

    #[test]
    fn v1_config_migrates_to_wildcard_rules() {
        let (dir, store) = tmp_store();
        let v1 = serde_json::json!({
            "version": 1,
            "defaultConnection": "c1",
            "connections": [{
                "name": "c1",
                "host": "db.example.invalid",
                "user": "u",
                "policy": {
                    "read": "allow", "write": "deny", "ddl": "deny",
                    "admin": "deny", "txCtrl": "allow",
                    "rowCap": 1000, "stmtTimeoutMs": 10000,
                    "requireTouchID": false, "maxBackupRows": 10000,
                    "maxBackupBytes": 52428800, "onBackupOverflow": "abort"
                },
                "databasePolicies": { "app": { "write": "confirm" } }
            }],
            "retention": {}
        });
        fs::write(store.path(), serde_json::to_string(&v1).unwrap()).unwrap();
        let cfg = store.load().unwrap();
        assert_eq!(cfg.version, 2);
        let conn = cfg.get("c1").unwrap();
        let rule = conn
            .table_policies()
            .get(&TableRuleKey::Wildcard {
                database: "app".into(),
            })
            .unwrap();
        assert_eq!(rule.write, Some(PolicyAction::Confirm));
        // driver-less v1 connection becomes MySQL
        assert!(conn.is_mysql());
        let _ = dir;
    }

    #[test]
    fn update_bumps_revision_and_conflicts() {
        let (_dir, store) = tmp_store();
        let cfg = store.load().unwrap();
        let () = store
            .update(cfg.revision, |c| {
                c.connections.push(Connection::Sqlite(SqliteConnection {
                    name: "s1".into(),
                    path: "/tmp/app.sqlite".into(),
                    ..SqliteConnection::default()
                }));
                Ok(())
            })
            .unwrap();
        let cfg2 = store.load().unwrap();
        assert_eq!(cfg2.revision, 1);
        let err = store.update(0, |_| Ok(())).unwrap_err();
        assert!(matches!(err, ConfigError::RevisionConflict { .. }));
    }

    #[test]
    fn malformed_json_is_an_error() {
        let (dir, store) = tmp_store();
        fs::write(store.path(), "{ not json").unwrap();
        assert!(matches!(
            store.load().unwrap_err(),
            ConfigError::Malformed(_)
        ));
        let _ = dir;
    }

    #[test]
    fn unknown_version_rejected() {
        let (dir, store) = tmp_store();
        fs::write(store.path(), r#"{"version": 99}"#).unwrap();
        assert!(matches!(
            store.load().unwrap_err(),
            ConfigError::UnsupportedVersion(99)
        ));
        let _ = dir;
    }

    #[test]
    fn exact_rule_lookup_and_validate() {
        let mut conn = MySqlConnection {
            name: "c1".into(),
            host: "h".into(),
            user: "u".into(),
            ..MySqlConnection::default()
        };
        conn.table_policies.insert(
            TableRuleKey::Exact(TableId::new("app", "jobs")),
            PartialPolicy {
                write: Some(PolicyAction::Allow),
                ..PartialPolicy::default()
            },
        );
        let c = Connection::Mysql(conn);
        c.validate().unwrap();
    }
}
