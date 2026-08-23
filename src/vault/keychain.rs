//! Keychain secret store on macOS (security-framework SecItem API) with
//! legacy-compatible service naming, this-device-only accessibility, and
//! no plaintext fallback on any platform.

// Used by the macOS SecItem store below; keep the import out of
// non-macOS lib builds (unused there → -D warnings).
#[cfg(target_os = "macos")]
use crate::app::paths;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secure storage is unsupported on this platform")]
    Unsupported,
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("secret not found")]
    NotFound,
}

pub trait SecretStore: Send + Sync {
    fn set_password(
        &self,
        connection_name: &str,
        account: &str,
        password: &str,
    ) -> Result<(), SecretStoreError>;
    fn get_password(
        &self,
        connection_name: &str,
        account: &str,
    ) -> Result<Zeroizing<String>, SecretStoreError>;
    fn delete_password(
        &self,
        connection_name: &str,
        account: &str,
    ) -> Result<bool, SecretStoreError>;
    fn has_password(&self, connection_name: &str, account: &str) -> bool {
        self.get_password(connection_name, account).is_ok()
    }
}

#[cfg(target_os = "macos")]
pub use macos::KeychainSecretStore;

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{PasswordOptions, set_generic_password_options};

    /// Direct SecItem-backed store. Every write goes through a fresh item
    /// with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (implied by the
    /// access control) so secrets never leave this device; reads find
    /// pre-existing entries regardless of their attributes.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct KeychainSecretStore;

    impl KeychainSecretStore {
        fn service(&self, connection_name: &str) -> String {
            paths::keychain_service_name(connection_name)
        }
    }

    impl SecretStore for KeychainSecretStore {
        fn set_password(
            &self,
            connection_name: &str,
            account: &str,
            password: &str,
        ) -> Result<(), SecretStoreError> {
            let service = self.service(connection_name);
            let _ = security_framework::passwords::delete_generic_password(&service, account);
            let ac = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                0,
            )
            .map_err(|e| SecretStoreError::Keychain(e.to_string()))?;
            let mut options = PasswordOptions::new_generic_password(&service, account);
            options.set_access_control(ac);
            set_generic_password_options(password.as_bytes(), options)
                .map_err(|e| SecretStoreError::Keychain(e.to_string()))
        }

        fn get_password(
            &self,
            connection_name: &str,
            account: &str,
        ) -> Result<Zeroizing<String>, SecretStoreError> {
            let service = self.service(connection_name);
            match security_framework::passwords::get_generic_password(&service, account) {
                Ok(bytes) => Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned())),
                Err(e) => match e.code() {
                    -25300 => Err(SecretStoreError::NotFound),
                    _ => Err(SecretStoreError::Keychain(e.to_string())),
                },
            }
        }

        fn delete_password(
            &self,
            connection_name: &str,
            account: &str,
        ) -> Result<bool, SecretStoreError> {
            let service = self.service(connection_name);
            match security_framework::passwords::delete_generic_password(&service, account) {
                Ok(()) => Ok(true),
                Err(e) => match e.code() {
                    -25300 => Ok(false),
                    _ => Err(SecretStoreError::Keychain(e.to_string())),
                },
            }
        }
    }
}

/// Non-macOS: no secure storage exists; explicit unsupported error, never
/// a plaintext file.
#[cfg(not(target_os = "macos"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedSecretStore;

#[cfg(not(target_os = "macos"))]
impl SecretStore for UnsupportedSecretStore {
    fn set_password(
        &self,
        _connection_name: &str,
        _account: &str,
        _password: &str,
    ) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Unsupported)
    }
    fn get_password(
        &self,
        _connection_name: &str,
        _account: &str,
    ) -> Result<Zeroizing<String>, SecretStoreError> {
        Err(SecretStoreError::Unsupported)
    }
    fn delete_password(
        &self,
        _connection_name: &str,
        _account: &str,
    ) -> Result<bool, SecretStoreError> {
        Err(SecretStoreError::Unsupported)
    }
}

/// Platform default store: macOS Keychain, explicit unsupported
/// elsewhere. In test mode the production Keychain is unavailable — an
/// in-memory store (optionally seeded from `SEQUEL_MCP_TEST_SECRETS`)
/// is used instead, so tests and benchmarks can never read or write the
/// developer's real Keychain entries.
pub fn default_store() -> std::sync::Arc<dyn SecretStore> {
    if crate::app::test_mode::is_active() {
        return crate::app::test_mode::secret_store();
    }
    #[cfg(target_os = "macos")]
    {
        std::sync::Arc::new(KeychainSecretStore)
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::sync::Arc::new(UnsupportedSecretStore)
    }
}

/// In-memory store for tests and tooling. Never touches the real Keychain
/// and therefore never triggers a consent dialog.
#[derive(Default)]
pub struct InMemorySecretStore {
    entries:
        std::sync::Mutex<std::collections::HashMap<(String, String), zeroize::Zeroizing<String>>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn set_password(
        &self,
        connection_name: &str,
        account: &str,
        password: &str,
    ) -> Result<(), SecretStoreError> {
        self.entries.lock().unwrap().insert(
            (connection_name.to_string(), account.to_string()),
            Zeroizing::new(password.to_string()),
        );
        Ok(())
    }

    fn get_password(
        &self,
        connection_name: &str,
        account: &str,
    ) -> Result<Zeroizing<String>, SecretStoreError> {
        self.entries
            .lock()
            .unwrap()
            .get(&(connection_name.to_string(), account.to_string()))
            .map(|v| Zeroizing::new(v.to_string()))
            .ok_or(SecretStoreError::NotFound)
    }

    fn delete_password(
        &self,
        connection_name: &str,
        account: &str,
    ) -> Result<bool, SecretStoreError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .remove(&(connection_name.to_string(), account.to_string()))
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    // Only the non-macOS fallback test needs parent items; importing
    // them unconditionally would be an unused import on macOS.
    #[cfg(not(target_os = "macos"))]
    use super::{SecretStore, SecretStoreError, UnsupportedSecretStore};

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_platform_fails_explicitly() {
        let s = UnsupportedSecretStore;
        assert!(matches!(
            s.set_password("c", "a", "p"),
            Err(SecretStoreError::Unsupported)
        ));
        assert!(matches!(
            s.get_password("c", "a"),
            Err(SecretStoreError::Unsupported)
        ));
    }

    #[test]
    fn service_names_match_legacy() {
        assert_eq!(
            crate::app::paths::keychain_service_name("prod"),
            "sequel-mcp : prod"
        );
    }
}
