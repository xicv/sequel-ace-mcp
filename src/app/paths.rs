//! XDG-aware path resolution, byte-compatible with the legacy `vault/paths.ts`.

use std::path::PathBuf;

pub const APP_NAME: &str = "sequel-mcp";
pub const KEYCHAIN_SERVICE_PREFIX: &str = "sequel-mcp";

/// Legacy namespace retained only for one-time migration from
/// sequel-ace-mcp <= 0.1.0. Read-only.
pub const LEGACY_APP_NAME: &str = "sequel-ace-mcp";
pub const LEGACY_KEYCHAIN_SERVICE_PREFIX: &str = "sequel-ace-mcp";

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // No HOME: fall back to the passwd entry rather than crash so
            // diagnostics can still be produced.
            PathBuf::from("/")
        })
}

pub fn config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(xdg) if !xdg.is_empty() => PathBuf::from(xdg).join(APP_NAME),
        _ => home().join(".config").join(APP_NAME),
    }
}

pub fn legacy_config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(xdg) if !xdg.is_empty() => PathBuf::from(xdg).join(LEGACY_APP_NAME),
        _ => home().join(".config").join(LEGACY_APP_NAME),
    }
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

pub fn legacy_config_path() -> PathBuf {
    legacy_config_dir().join("config.json")
}

pub fn data_dir() -> PathBuf {
    match std::env::var_os("XDG_DATA_HOME") {
        Some(xdg) if !xdg.is_empty() => PathBuf::from(xdg).join(APP_NAME),
        _ => home().join(".local").join("share").join(APP_NAME),
    }
}

pub fn audit_db_path() -> PathBuf {
    data_dir().join("audit.sqlite")
}

/// Runtime registry for live MCP sessions (approval IPC discovery).
pub fn runtime_dir() -> PathBuf {
    data_dir().join("runtime")
}

pub fn keychain_service_name(connection_name: &str) -> String {
    format!("{KEYCHAIN_SERVICE_PREFIX} : {connection_name}")
}

pub fn legacy_keychain_service_name(connection_name: &str) -> String {
    format!("{LEGACY_KEYCHAIN_SERVICE_PREFIX} : {connection_name}")
}

pub fn sequel_ace_data_dir() -> PathBuf {
    home()
        .join("Library")
        .join("Containers")
        .join("com.sequel-ace.sequel-ace")
        .join("Data")
        .join("Library")
        .join("Application Support")
        .join("Sequel Ace")
        .join("Data")
}

pub fn sequel_ace_favorites_plist_path() -> PathBuf {
    sequel_ace_data_dir().join("Favorites.plist")
}

pub fn sequel_ace_query_history_db_path() -> PathBuf {
    sequel_ace_data_dir().join("queryHistory.db")
}

pub fn sequel_ace_legacy_keychain_service_name(favorite_name: &str, favorite_id: i64) -> String {
    format!("Sequel Ace : {favorite_name} ({favorite_id})")
}

pub fn sequel_ace_legacy_ssh_keychain_service_name(
    favorite_name: &str,
    favorite_id: i64,
) -> String {
    format!("Sequel Ace SSHTunnel : {favorite_name} ({favorite_id})")
}

/// Expand a leading `~` like the legacy `expandSqlitePath`/`expandTilde`.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == ":memory:" {
        return PathBuf::from(path);
    }
    if path == "~" {
        return home();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return home().join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_names_match_legacy() {
        assert_eq!(keychain_service_name("prod"), "sequel-mcp : prod");
        assert_eq!(
            legacy_keychain_service_name("prod"),
            "sequel-ace-mcp : prod"
        );
        assert_eq!(
            sequel_ace_legacy_keychain_service_name("acme", 12),
            "Sequel Ace : acme (12)"
        );
        assert_eq!(
            sequel_ace_legacy_ssh_keychain_service_name("acme", 12),
            "Sequel Ace SSHTunnel : acme (12)"
        );
    }

    #[test]
    fn expand_tilde_variants() {
        assert_eq!(expand_tilde("~"), home());
        assert_eq!(expand_tilde("~/x/y"), home().join("x/y"));
        assert_eq!(expand_tilde("/abs"), PathBuf::from("/abs"));
    }
}
