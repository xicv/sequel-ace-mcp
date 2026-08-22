//! Favorites.plist import (legacy `importer/sequelAcePlist.ts` port):
//! walk the favorites tree, map every usable favorite to a read-only
//! MySQL connection (with optional SSH tunnel), upsert into our
//! config, and optionally copy passwords from the legacy Sequel Ace
//! Keychain entries into our secret store. Sequel Ace data is never
//! modified.

use crate::config::{
    BridgeTool, Config, Connection, MySqlConnection, SshAuthMethod, SshDocker, SshTunnel,
};
use crate::vault::keychain::SecretStore;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ImportedFavorite {
    pub connection: MySqlConnection,
    pub legacy_keychain_service: String,
    pub legacy_ssh_keychain_service: Option<String>,
    pub legacy_account: String,
    pub legacy_ssh_account: Option<String>,
}

fn as_int(v: Option<&plist::Value>, fallback: i64) -> i64 {
    match v {
        Some(plist::Value::Integer(i)) => i.as_signed().unwrap_or(fallback),
        Some(plist::Value::String(s)) => s.parse().unwrap_or(fallback),
        Some(plist::Value::Real(f)) => *f as i64,
        _ => fallback,
    }
}

fn as_bool(v: Option<&plist::Value>) -> bool {
    match v {
        Some(plist::Value::Boolean(b)) => *b,
        Some(plist::Value::Integer(i)) => i.as_signed().unwrap_or(0) == 1,
        _ => false,
    }
}

fn as_str(v: Option<&plist::Value>) -> Option<&str> {
    v.and_then(|v| v.as_string()).filter(|s| !s.is_empty())
}

fn to_connection(fav: &plist::Dictionary) -> Option<ImportedFavorite> {
    let name = as_str(fav.get("name"))?;
    let host = as_str(fav.get("host"))?;
    let user = as_str(fav.get("user"))?;
    let id = fav.get("id")?;
    let id_num = match id {
        plist::Value::Integer(i) => i.as_signed()?,
        plist::Value::String(s) => s.parse().ok()?,
        _ => return None,
    };

    let ssh_host = as_str(fav.get("sshHost"));
    let fav_type = as_int(fav.get("type"), 0);
    let uses_ssh = fav_type == 1 || ssh_host.is_some();
    let ssh_key_location = as_str(fav.get("sshKeyLocation"));
    let key_enabled = as_bool(fav.get("sshKeyLocationEnabled")) && ssh_key_location.is_some();
    let ssh_user = as_str(fav.get("sshUser"));

    let ssh = if uses_ssh {
        Some(SshTunnel {
            host: ssh_host.unwrap_or_default().to_string(),
            port: as_int(fav.get("sshPort"), 22).clamp(1, 65535) as u16,
            user: ssh_user.unwrap_or_default().to_string(),
            auth_method: if key_enabled {
                SshAuthMethod::Key
            } else {
                SshAuthMethod::Password
            },
            private_key_path: ssh_key_location.map(str::to_string),
            ..SshTunnel::default()
        })
    } else {
        None
    };

    let connection = MySqlConnection {
        name: name.to_string(),
        host: host.to_string(),
        port: as_int(fav.get("port"), 3306).clamp(1, 65535) as u16,
        user: user.to_string(),
        database: as_str(fav.get("database")).map(str::to_string),
        ssl: as_bool(fav.get("useSSL")),
        ssh,
        policy: crate::policy::model::policy_from_preset(
            crate::policy::model::PolicyPresetName::ReadOnly,
        ),
        ..MySqlConnection::default()
    };

    Some(ImportedFavorite {
        legacy_keychain_service: crate::app::paths::sequel_ace_legacy_keychain_service_name(
            name, id_num,
        ),
        legacy_ssh_keychain_service: if uses_ssh {
            Some(crate::app::paths::sequel_ace_legacy_ssh_keychain_service_name(name, id_num))
        } else {
            None
        },
        legacy_account: user.to_string(),
        legacy_ssh_account: if uses_ssh {
            ssh_user.map(str::to_string)
        } else {
            None
        },
        connection,
    })
}

/// Parse the favorites tree. Accepts an explicit path (tests) or the
/// default Sequel Ace sandbox location.
pub fn read_favorites_plist(plist_path: Option<&Path>) -> Result<Vec<ImportedFavorite>, String> {
    let path: PathBuf = plist_path
        .map(PathBuf::from)
        .unwrap_or_else(crate::app::paths::sequel_ace_favorites_plist_path);
    // Reading the user's favorites is REAL user data — in test mode it
    // must stay below the isolated root.
    if crate::app::test_mode::is_active()
        && let Err(e) = crate::app::test_mode::check_sqlite_path(&path)
    {
        return Err(format!("favorites plist: {e}"));
    }
    let parsed =
        plist::Value::from_file(&path).map_err(|e| format!("cannot read {path:?}: {e}"))?;
    let root = parsed
        .as_dictionary()
        .and_then(|d| d.get("Favorites Root"))
        .and_then(|r| r.as_dictionary())
        .and_then(|r| r.get("Children"))
        .and_then(|c| c.as_array());
    let mut out = Vec::new();
    let Some(children) = root else { return Ok(out) };
    walk(children, &mut out);
    Ok(out)
}

fn walk(nodes: &[plist::Value], out: &mut Vec<ImportedFavorite>) {
    for node in nodes {
        if let Some(children) = node
            .as_dictionary()
            .and_then(|d| d.get("Children"))
            .and_then(|c| c.as_array())
        {
            walk(children, out);
        }
        if let Some(fav) = node.as_dictionary()
            && let Some(imported) = to_connection(fav)
        {
            out.push(imported);
        }
    }
}

/// Read one legacy Sequel Ace Keychain password. `/usr/bin/security`
/// with a fixed argument vector — no shell, no interpolation.
fn read_legacy_password(service: &str, account: &str) -> Option<String> {
    let out = std::process::Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[derive(Debug, Default, PartialEq)]
pub struct ImportResult {
    pub total: usize,
    pub imported: usize,
    pub with_passwords: usize,
    pub skipped: Vec<(String, String)>,
}

#[allow(clippy::too_many_arguments)]
pub fn import_from_sequel_ace(
    config: &mut Config,
    secrets: &dyn SecretStore,
    copy_passwords: bool,
    plist_path: Option<&Path>,
    _bridge: Option<(String, BridgeTool, SshDocker)>,
) -> ImportResult {
    let _ = BridgeTool::Nc; // bridge tool is informational here
    let items = match read_favorites_plist(plist_path) {
        Ok(items) => items,
        Err(e) => {
            return ImportResult {
                total: 0,
                imported: 0,
                with_passwords: 0,
                skipped: vec![("(plist)".into(), e)],
            };
        }
    };
    let total = items.len();
    let mut imported = 0;
    let mut with_passwords = 0;
    let mut skipped = Vec::new();

    for item in &items {
        let conn = Connection::Mysql(item.connection.clone());
        if let Err(e) = conn.validate() {
            skipped.push((item.connection.name.clone(), e.to_string()));
            continue;
        }
        // Upsert by name.
        match config
            .connections
            .iter_mut()
            .find(|c| c.name() == conn.name())
        {
            Some(slot) => *slot = conn,
            None => config.connections.push(conn),
        }
        imported += 1;
        if copy_passwords {
            if let Some(pwd) =
                read_legacy_password(&item.legacy_keychain_service, &item.legacy_account)
            {
                let _ = secrets.set_password(&item.connection.name, &item.connection.user, &pwd);
                with_passwords += 1;
            }
            if let (Some(service), Some(account)) = (
                item.legacy_ssh_keychain_service.as_deref(),
                item.legacy_ssh_account.as_deref(),
            ) && item.connection.ssh.is_some()
                && let Some(ssh_pwd) = read_legacy_password(service, account)
            {
                let _ = secrets.set_password(
                    &format!("{}::ssh", item.connection.name),
                    account,
                    &ssh_pwd,
                );
            }
        }
    }

    ImportResult {
        total,
        imported,
        with_passwords,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::keychain::InMemorySecretStore;

    fn dict(pairs: Vec<(&str, plist::Value)>) -> plist::Value {
        plist::Value::Dictionary(plist::Dictionary::from_iter(
            pairs.into_iter().map(|(k, v)| (k.to_string(), v)),
        ))
    }

    fn favorites_plist() -> String {
        let nested = dict(vec![
            ("id", plist::Value::Integer(13i64.into())),
            ("name", plist::Value::String("nested".into())),
            ("host", plist::Value::String("db3.acme.test".into())),
            ("user", plist::Value::String("u3".into())),
        ]);
        let children = vec![
            dict(vec![
                ("id", plist::Value::Integer(11i64.into())),
                ("name", plist::Value::String("acme".into())),
                ("host", plist::Value::String("db.acme.test".into())),
                ("port", plist::Value::Integer(3307i64.into())),
                ("user", plist::Value::String("u1".into())),
                ("database", plist::Value::String("app".into())),
                ("useSSL", plist::Value::Integer(1i64.into())),
            ]),
            // SSH favorite with a key file
            dict(vec![
                ("id", plist::Value::String("12".into())),
                ("name", plist::Value::String("bastioned".into())),
                ("host", plist::Value::String("db2.acme.test".into())),
                ("user", plist::Value::String("u2".into())),
                ("type", plist::Value::Integer(1i64.into())),
                ("sshHost", plist::Value::String("jump.acme.test".into())),
                ("sshPort", plist::Value::Integer(2222i64.into())),
                ("sshUser", plist::Value::String("jumpu".into())),
                ("sshKeyLocation", plist::Value::String("/keys/id_ed".into())),
                ("sshKeyLocationEnabled", plist::Value::Integer(1i64.into())),
            ]),
            // Folder with a nested child
            dict(vec![("Children", plist::Value::Array(vec![nested]))]),
            // Unusable: no host
            dict(vec![
                ("id", plist::Value::Integer(14i64.into())),
                ("name", plist::Value::String("broken".into())),
                ("user", plist::Value::String("u4".into())),
            ]),
        ];
        let root = dict(vec![("Children", plist::Value::Array(children))]);
        let mut xml = std::io::Cursor::new(Vec::new());
        plist::Value::Dictionary(plist::Dictionary::from_iter([(
            "Favorites Root".to_string(),
            root,
        )]))
        .to_writer_xml(&mut xml)
        .unwrap();
        String::from_utf8(xml.into_inner()).unwrap()
    }

    #[test]
    fn parses_walks_and_maps() {
        let dir = tempfile::TempDir::new().unwrap();
        let plist_path = dir.path().join("Favorites.plist");
        std::fs::write(&plist_path, favorites_plist()).unwrap();

        let items = read_favorites_plist(Some(&plist_path)).unwrap();
        assert_eq!(items.len(), 3, "broken favorite skipped, folder walked");

        let acme = &items[0];
        assert_eq!(acme.connection.name, "acme");
        assert_eq!(acme.connection.host, "db.acme.test");
        assert_eq!(acme.connection.port, 3307);
        assert!(acme.connection.ssl);
        assert!(acme.connection.ssh.is_none());
        assert_eq!(acme.legacy_keychain_service, "Sequel Ace : acme (11)");

        let bastioned = &items[1];
        let ssh = bastioned.connection.ssh.as_ref().unwrap();
        assert_eq!(ssh.host, "jump.acme.test");
        assert_eq!(ssh.port, 2222);
        assert_eq!(ssh.auth_method, SshAuthMethod::Key);
        assert_eq!(ssh.private_key_path.as_deref(), Some("/keys/id_ed"));
        assert_eq!(
            bastioned.legacy_ssh_keychain_service.as_deref(),
            Some("Sequel Ace SSHTunnel : bastioned (12)")
        );
    }

    #[test]
    fn imports_into_config_without_passwords() {
        let dir = tempfile::TempDir::new().unwrap();
        let plist_path = dir.path().join("Favorites.plist");
        std::fs::write(&plist_path, favorites_plist()).unwrap();

        let mut cfg = Config::default();
        let store = InMemorySecretStore::new();
        // copy_passwords=false: no Keychain process is spawned.
        let r = import_from_sequel_ace(&mut cfg, &store, false, Some(&plist_path), None);
        assert_eq!(r.total, 3);
        assert_eq!(r.imported, 3);
        assert_eq!(r.with_passwords, 0);
        assert!(r.skipped.is_empty());
        assert_eq!(cfg.connections.len(), 3);
        assert!(cfg.connections.iter().all(|c| c.is_mysql()));

        // Idempotent re-import does not duplicate.
        let r2 = import_from_sequel_ace(&mut cfg, &store, false, Some(&plist_path), None);
        assert_eq!(r2.imported, 3);
        assert_eq!(cfg.connections.len(), 3);
    }

    #[test]
    fn missing_plist_is_typed_error() {
        let mut cfg = Config::default();
        let store = InMemorySecretStore::new();
        let r = import_from_sequel_ace(
            &mut cfg,
            &store,
            false,
            Some(Path::new("/nonexistent/Favorites.plist")),
            None,
        );
        assert_eq!(r.imported, 0);
        assert_eq!(r.skipped.len(), 1);
        assert!(r.skipped[0].1.contains("cannot read"));
    }
}
