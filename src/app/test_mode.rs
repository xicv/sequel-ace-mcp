//! `SEQUEL_MCP_TEST_MODE=1`: fail-closed isolation for test and benchmark
//! runs. When active, the binary refuses to operate outside an explicitly
//! supplied temporary root:
//!
//! * `SEQUEL_MCP_TEST_ROOT` is required; HOME, config, data, audit and
//!   runtime paths must all resolve under it — otherwise the process
//!   terminates BEFORE the MCP server starts (exit code 78).
//! * MySQL endpoints must be loopback or explicitly allow-listed via
//!   `SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS` (`host` or `host:port`, comma
//!   separated) — checked before any connect attempt.
//! * SQLite files must live under the root (`:memory:` excepted).
//! * The production Keychain is unavailable; secrets come from the
//!   in-memory store optionally seeded via `SEQUEL_MCP_TEST_SECRETS`
//!   (`{"connection": {"user": "password"}}`, synthetic values only).
//!
//! Outside test mode none of these variables have any effect. This gate
//! exists so a test/benchmark process can never silently inherit the
//! developer's real configuration or reach a production server.

use crate::vault::keychain::SecretStore as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Exit code used when test-mode isolation is violated at startup
/// (sysexits `EX_CONFIG`).
pub const EXIT_ISOLATION: i32 = 78;

pub fn is_active() -> bool {
    std::env::var("SEQUEL_MCP_TEST_MODE").as_deref() == Ok("1")
}

fn root() -> Result<PathBuf, String> {
    std::env::var_os("SEQUEL_MCP_TEST_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| {
            "SEQUEL_MCP_TEST_MODE=1 requires SEQUEL_MCP_TEST_ROOT pointing at the isolated test tree"
                .to_string()
        })
}

fn under(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// Startup check: every derived writable path must live under the test
/// root. Called before the MCP server starts; a violation terminates the
/// process.
pub fn verify_startup() -> Result<(), String> {
    if !is_active() {
        return Ok(());
    }
    let root = root()?;
    let checks: [(&str, PathBuf); 6] = [
        ("HOME", crate::app::paths::home_dir()),
        ("config dir", crate::app::paths::config_dir()),
        ("legacy config dir", crate::app::paths::legacy_config_dir()),
        ("data dir", crate::app::paths::data_dir()),
        ("audit db", crate::app::paths::audit_db_path()),
        ("runtime dir", crate::app::paths::runtime_dir()),
    ];
    for (label, path) in checks {
        if !under(&path, &root) {
            return Err(format!(
                "{label} resolves outside SEQUEL_MCP_TEST_ROOT: {} (root {})",
                path.display(),
                root.display()
            ));
        }
    }
    Ok(())
}

/// Endpoint allow-list entry forms: `host` (any port) or `host:port`.
fn endpoint_allowed(host: &str, port: u16) -> bool {
    let Ok(raw) = std::env::var("SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS") else {
        return false;
    };
    raw.split(',').any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        match entry.rsplit_once(':') {
            Some((h, p)) => h == host && p.parse::<u16>() == Ok(port),
            None => entry == host,
        }
    })
}

/// Refuse non-loopback MySQL endpoints BEFORE any connect attempt. In
/// test mode the only legitimate targets are local (docker ports are
/// published on loopback) or explicitly listed test endpoints.
pub fn check_mysql_endpoint(host: &str, port: u16) -> Result<(), String> {
    if !is_active() {
        return Ok(());
    }
    let h = host.trim_matches(['[', ']']);
    let loopback = matches!(h, "127.0.0.1" | "::1" | "localhost");
    if loopback || endpoint_allowed(h, port) {
        return Ok(());
    }
    Err(format!(
        "MySQL endpoint {h}:{port} is not loopback and not in SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS; refusing before connect"
    ))
}

/// Refuse SQLite database files outside the test root (`:memory:` is
/// always allowed).
pub fn check_sqlite_path(path: &Path) -> Result<(), String> {
    if !is_active() {
        return Ok(());
    }
    if path == Path::new(":memory:") {
        return Ok(());
    }
    let root = root()?;
    if under(path, &root) {
        return Ok(());
    }
    Err(format!(
        "SQLite path {} is outside SEQUEL_MCP_TEST_ROOT; refusing to open",
        path.display()
    ))
}

/// In-memory secret store for test mode, optionally seeded from
/// `SEQUEL_MCP_TEST_SECRETS` (`{"connection": {"user": "password"}}`).
/// The production Keychain is never consulted in test mode.
pub fn secret_store() -> Arc<dyn crate::vault::keychain::SecretStore> {
    let store = Arc::new(crate::vault::keychain::InMemorySecretStore::new());
    if let Ok(raw) = std::env::var("SEQUEL_MCP_TEST_SECRETS")
        && let Ok(map) = serde_json::from_str::<serde_json::Value>(&raw)
        && let Some(obj) = map.as_object()
    {
        for (conn, users) in obj {
            let Some(users) = users.as_object() else {
                continue;
            };
            for (user, password) in users {
                if let Some(password) = password.as_str() {
                    let _ = store.set_password(conn, user, password);
                }
            }
        }
    }
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests manipulate the process environment, which is global;
    // they must not run concurrently with each other. Rust runs unit
    // tests in threads within one process, so guard with a lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
        // SAFETY: every caller holds ENV_LOCK; no other thread in this
        // process reads these keys while the lock is held (the library
        // code under test reads them synchronously below).
        unsafe { std::env::set_var(key, value) };
    }

    fn remove_var(key: &str) {
        // SAFETY: as above.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn inactive_by_default_and_allows_everything() {
        let _g = ENV_LOCK.lock().unwrap();
        remove_var("SEQUEL_MCP_TEST_MODE");
        assert!(!is_active());
        assert!(verify_startup().is_ok());
        assert!(check_mysql_endpoint("db.prod.example.invalid", 3306).is_ok());
        assert!(check_sqlite_path(Path::new("/tmp/anywhere.sqlite")).is_ok());
    }

    #[test]
    fn active_requires_root_and_paths_under_it() {
        let _g = ENV_LOCK.lock().unwrap();
        set_var("SEQUEL_MCP_TEST_MODE", "1");
        remove_var("SEQUEL_MCP_TEST_ROOT");
        assert!(verify_startup().is_err());

        let dir = tempfile::TempDir::new().unwrap();
        set_var("SEQUEL_MCP_TEST_ROOT", dir.path());
        set_var("HOME", dir.path().join("home"));
        set_var("XDG_CONFIG_HOME", dir.path().join("config"));
        set_var("XDG_DATA_HOME", dir.path().join("data"));
        assert!(verify_startup().is_ok(), "all paths under the root");

        // Point one path outside the root: startup must refuse.
        set_var("XDG_DATA_HOME", "/definitely/outside");
        let err = verify_startup().unwrap_err();
        assert!(err.contains("outside SEQUEL_MCP_TEST_ROOT"), "{err}");
        assert!(err.contains("data dir"), "{err}");

        remove_var("SEQUEL_MCP_TEST_MODE");
        remove_var("SEQUEL_MCP_TEST_ROOT");
        remove_var("XDG_DATA_HOME");
        remove_var("XDG_CONFIG_HOME");
        remove_var("HOME");
        let _ = dir;
    }

    #[test]
    fn mysql_endpoint_gate() {
        let _g = ENV_LOCK.lock().unwrap();
        set_var("SEQUEL_MCP_TEST_MODE", "1");
        let dir = tempfile::TempDir::new().unwrap();
        set_var("SEQUEL_MCP_TEST_ROOT", dir.path());
        remove_var("SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS");
        assert!(check_mysql_endpoint("127.0.0.1", 3306).is_ok());
        assert!(check_mysql_endpoint("localhost", 3307).is_ok());
        assert!(check_mysql_endpoint("::1", 3306).is_ok());
        let err = check_mysql_endpoint("192.0.2.10", 3306).unwrap_err();
        assert!(
            err.contains("192.0.2.10") && err.contains("refusing"),
            "{err}"
        );

        set_var(
            "SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS",
            "db.test.example,10.1.2.3:3307",
        );
        assert!(check_mysql_endpoint("db.test.example", 3306).is_ok());
        assert!(check_mysql_endpoint("10.1.2.3", 3307).is_ok());
        assert!(check_mysql_endpoint("10.1.2.3", 3306).is_err());

        remove_var("SEQUEL_MCP_TEST_MODE");
        remove_var("SEQUEL_MCP_TEST_ROOT");
        remove_var("SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS");
        let _ = dir;
    }

    #[test]
    fn sqlite_path_gate() {
        let _g = ENV_LOCK.lock().unwrap();
        set_var("SEQUEL_MCP_TEST_MODE", "1");
        let dir = tempfile::TempDir::new().unwrap();
        set_var("SEQUEL_MCP_TEST_ROOT", dir.path());
        assert!(check_sqlite_path(Path::new(":memory:")).is_ok());
        assert!(check_sqlite_path(&dir.path().join("a.sqlite")).is_ok());
        assert!(check_sqlite_path(Path::new("/tmp/outside.sqlite")).is_err());
        remove_var("SEQUEL_MCP_TEST_MODE");
        remove_var("SEQUEL_MCP_TEST_ROOT");
        let _ = dir;
    }

    #[test]
    fn secret_store_seeds_from_env() {
        let _g = ENV_LOCK.lock().unwrap();
        set_var(
            "SEQUEL_MCP_TEST_SECRETS",
            r#"{"db": {"root": "synthetic-password"}}"#,
        );
        let store = secret_store();
        assert_eq!(
            store.get_password("db", "root").unwrap().as_str(),
            "synthetic-password"
        );
        assert!(store.get_password("db", "other").is_err());
        remove_var("SEQUEL_MCP_TEST_SECRETS");
    }
}
