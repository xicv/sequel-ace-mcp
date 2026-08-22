//! v1 → v2 migration parsing and mapping, plus the timestamped backup.

use super::*;
use crate::policy::model::{PartialPolicy, TableRuleKey};
use serde_json::Value as Json;
use std::fs;

/// A parsed v1 file (legacy TypeScript schema).
#[derive(Debug, Clone)]
pub struct V1Config {
    pub connections: Vec<V1Connection>,
    pub default_connection: Option<String>,
    pub retention: crate::policy::model::RetentionConfig,
}

#[derive(Debug, Clone)]
pub struct V1Connection {
    pub name: String,
    pub driver: V1Driver,
    /// Legacy `databasePolicies` as plain `<db>` → partial maps.
    pub database_policies: std::collections::BTreeMap<String, PartialPolicy>,
    pub policy: crate::policy::model::Policy,
    pub mysql: Option<MySqlConnection>,
    pub sqlite: Option<SqliteConnection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1Driver {
    Mysql,
    Sqlite,
}

fn str_field(obj: &Json, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

fn parse_policy(obj: &Json) -> Result<crate::policy::model::Policy, ConfigError> {
    serde_json::from_value(obj.clone())
        .map_err(|e| ConfigError::Malformed(format!("bad policy object: {e}")))
}

/// Parse a v1 JSON document. Mirrors the legacy zod preprocessing:
/// missing `driver` defaults to `mysql`; unknown drivers are errors.
pub fn parse_v1(json: &Json) -> Result<V1Config, ConfigError> {
    let obj = json
        .as_object()
        .ok_or_else(|| ConfigError::Malformed("v1 config must be an object".into()))?;
    let version = obj.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
    if version != 1 {
        return Err(ConfigError::UnsupportedVersion(version));
    }

    let mut connections = Vec::new();
    for (i, raw) in obj
        .get("connections")
        .map(|v| v.as_array().cloned().unwrap_or_default())
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let c = raw
            .as_object()
            .ok_or_else(|| ConfigError::Malformed(format!("connection #{i} is not an object")))?;
        let driver = match c.get("driver").and_then(|v| v.as_str()) {
            None | Some("mysql") => V1Driver::Mysql,
            Some("sqlite") => V1Driver::Sqlite,
            Some(other) => {
                return Err(ConfigError::Malformed(format!(
                    "connection #{i} has unknown driver {other:?}"
                )));
            }
        };
        let policy = c
            .get("policy")
            .map(parse_policy)
            .transpose()?
            .unwrap_or_default();
        let database_policies = c
            .get("databasePolicies")
            .map(parse_partial_map)
            .transpose()?
            .unwrap_or_default();

        let (mysql, sqlite) = match driver {
            V1Driver::Mysql => {
                let ssh = c.get("ssh").map(parse_ssh).transpose()?;
                (
                    Some(MySqlConnection {
                        name: str_field(raw, "name").unwrap_or_default(),
                        host: str_field(raw, "host").unwrap_or_default(),
                        port: raw.get("port").and_then(|v| v.as_u64()).unwrap_or(3306) as u16,
                        user: str_field(raw, "user").unwrap_or_default(),
                        database: str_field(raw, "database"),
                        ssl: raw.get("ssl").and_then(|v| v.as_bool()).unwrap_or(false),
                        ssl_server_name: str_field(raw, "sslServerName"),
                        ssl_ca_path: str_field(raw, "sslCaPath"),
                        ssh,
                        policy: policy.clone(),
                        table_policies: TablePolicies::default(),
                    }),
                    None,
                )
            }
            V1Driver::Sqlite => (
                None,
                Some(SqliteConnection {
                    name: str_field(raw, "name").unwrap_or_default(),
                    path: str_field(raw, "path").unwrap_or_default(),
                    database: str_field(raw, "database").unwrap_or_else(|| "main".into()),
                    policy: policy.clone(),
                    table_policies: TablePolicies::default(),
                }),
            ),
        };
        connections.push(V1Connection {
            name: str_field(raw, "name").unwrap_or_default(),
            driver,
            database_policies,
            policy,
            mysql,
            sqlite,
        });
    }

    // Retention with the legacy `auditDays` fan-out.
    let retention: crate::policy::model::RetentionConfig = obj
        .get("retention")
        .map(parse_retention)
        .transpose()?
        .unwrap_or_default();

    Ok(V1Config {
        connections,
        default_connection: str_field(json, "defaultConnection"),
        retention,
    })
}

fn parse_retention(value: &Json) -> Result<crate::policy::model::RetentionConfig, ConfigError> {
    let mut v = value.clone();
    if let Some(obj) = v.as_object_mut() {
        // Legacy preprocess: `auditDays` fans out to every category when
        // `retentionDaysByCategory` is absent.
        if let Some(days) = obj.get("auditDays").and_then(|d| d.as_u64()) {
            obj.entry("retentionDaysByCategory".to_string())
                .or_insert_with(|| {
                    serde_json::json!({
                        "read": days, "write": days, "ddl": days,
                        "admin": days, "txCtrl": days
                    })
                });
        }
        obj.remove("auditDays");
    }
    serde_json::from_value(v)
        .map_err(|e| ConfigError::Malformed(format!("bad retention object: {e}")))
}

fn parse_ssh(value: &Json) -> Result<SshTunnel, ConfigError> {
    let ssh: SshTunnel = serde_json::from_value(value.clone())
        .map_err(|e| ConfigError::Malformed(format!("bad ssh object: {e}")))?;
    Ok(ssh)
}

/// Map a parsed v1 config to v2: each `databasePolicies[db]` becomes the
/// wildcard table rule `db.*`; unset `hostKeyPolicy` becomes `lenient` with
/// the migrated warning flag.
pub fn v1_to_v2(v1: V1Config) -> Config {
    let connections = v1
        .connections
        .into_iter()
        .map(|c| {
            let mut table_policies = TablePolicies::new();
            for (db, partial) in &c.database_policies {
                table_policies.insert(
                    TableRuleKey::Wildcard {
                        database: db.clone(),
                    },
                    partial.clone(),
                );
            }
            match c.driver {
                V1Driver::Mysql => {
                    let mut m = c.mysql.unwrap_or_default();
                    m.policy = c.policy;
                    m.table_policies = table_policies;
                    if let Some(ssh) = &mut m.ssh
                        && ssh.host_key_policy.is_none()
                    {
                        ssh.host_key_policy = Some(SshHostKeyPolicy::Lenient);
                        ssh.host_key_policy_migrated = true;
                    }
                    Connection::Mysql(m)
                }
                V1Driver::Sqlite => {
                    let mut s = c.sqlite.unwrap_or_default();
                    s.policy = c.policy;
                    s.table_policies = table_policies;
                    Connection::Sqlite(s)
                }
            }
        })
        .collect();

    Config {
        version: 2,
        revision: 1,
        connections,
        default_connection: v1.default_connection,
        retention: v1.retention,
    }
}

/// Run the on-disk v1 → v2 migration with the documented safety steps.
pub fn migrate_file(store: &ConfigStore) -> Result<Config, ConfigError> {
    let _guard = store.lock()?;
    if !store.path().exists() {
        return Ok(Config::default());
    }
    let raw = fs::read_to_string(store.path())?;
    let json: Json = serde_json::from_str(&raw)
        .map_err(|e| ConfigError::Malformed(format!("not valid JSON: {e}")))?;
    let version = json
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ConfigError::Malformed("missing numeric version field".into()))?;
    if version == 2 {
        return serde_json::from_value(json)
            .map_err(|e| ConfigError::Malformed(format!("config does not match v2 schema: {e}")));
    }
    if version != 1 {
        return Err(ConfigError::UnsupportedVersion(version));
    }

    let v1 = parse_v1(&json)?;
    let v2 = v1_to_v2(v1);

    // Timestamped backup of the original v1 (mode 0600).
    let stamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
        .replace(':', "");
    let backup = store
        .path()
        .with_file_name(format!("config.pre-v2.{stamp}.json"));
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&backup)?;
        f.write_all(raw.as_bytes())?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&backup, fs::Permissions::from_mode(0o600));
        }
    }

    store.persist(&v2)?;

    // Reopen and validate: on failure the v1 original is untouched (the
    // rename either happened atomically or not at all) and the backup above
    // remains for manual rollback.
    let reopened = store.load_locked()?;
    if reopened.version != 2 {
        return Err(ConfigError::Validation(
            "post-migration validation failed".into(),
        ));
    }
    Ok(reopened)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_audit_days_fans_out() {
        let v = serde_json::json!({"auditDays": 14});
        let r = parse_retention(&v).unwrap();
        assert_eq!(r.retention_days_by_category.read, 14);
        assert_eq!(r.retention_days_by_category.admin, 14);
    }

    #[test]
    fn driverless_defaults_to_mysql() {
        let j = serde_json::json!({
            "version": 1,
            "connections": [{"name": "c", "host": "h", "user": "u", "policy": {}}]
        });
        let v1 = parse_v1(&j).unwrap();
        assert_eq!(v1.connections[0].driver, V1Driver::Mysql);
    }

    #[test]
    fn ssh_policy_unset_becomes_lenient_migrated() {
        let j = serde_json::json!({
            "version": 1,
            "connections": [{
                "name": "c", "host": "h", "user": "u", "policy": {},
                "ssh": {"host": "s", "user": "su"}
            }]
        });
        let v2 = v1_to_v2(parse_v1(&j).unwrap());
        match &v2.connections[0] {
            Connection::Mysql(m) => {
                let ssh = m.ssh.as_ref().unwrap();
                assert_eq!(ssh.host_key_policy, Some(SshHostKeyPolicy::Lenient));
                assert!(ssh.host_key_policy_migrated);
            }
            _ => panic!("expected mysql"),
        }
    }
}
