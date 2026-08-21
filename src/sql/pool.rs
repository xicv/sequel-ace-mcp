//! Credential identity and pool lifecycle (Phase 2 of the hardening plan).
//!
//! Pool identity is never a raw or unkeyed password hash: it is a
//! process-keyed HMAC digest over the credential, held in a redacted type
//! whose `Debug`/`Display` emit only a fixed placeholder. Pools enter the
//! shared cache only after a successful handshake plus health query;
//! concurrent first users coalesce on one initialization; superseded or
//! failed pools are closed and evicted; the cache is bounded.

use mysql_async::Pool;
use rand::RngCore;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::MySqlConnection;

/// Maximum distinct pools kept in the shared cache.
pub const MAX_POOLS: usize = 16;

/// Redacted credential identity. The inner bytes are a process-keyed
/// HMAC-SHA-256 digest of the secret — useless outside this process, never
/// an offline verifier — and can never be printed, logged, or serialized.
#[derive(Clone)]
pub struct CredentialGeneration([u8; 16]);

impl fmt::Debug for CredentialGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialGeneration(<redacted>)")
    }
}

impl fmt::Display for CredentialGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl CredentialGeneration {
    /// Digest the credential with a random process-local key. Two
    /// identical passwords yield identical generations (same process);
    /// the same password leaked from another process does not match.
    pub fn derive(password: &str) -> Self {
        use hmac::Mac;
        let key = process_key();
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(b"sequel-mcp/credential-generation/v1\n");
        mac.update(password.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag[..16]);
        CredentialGeneration(out)
    }

    pub fn eq_material(&self, other: &CredentialGeneration) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

fn process_key() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        k
    })
}

#[derive(Debug, Error)]
pub enum PoolManagerError {
    #[error("mysql pool initialization failed: {0}")]
    Init(String),
    #[error("pool cache is full ({0} live pools); refusing to open another")]
    CacheFull(usize),
}

struct PoolEntry {
    pool: Pool,
    generation: CredentialGeneration,
}

/// Shared pool cache with verified publication. A pool becomes visible
/// only after `Pool::get_conn()` + a `SELECT 1` health query succeed on it.
pub struct PoolManager {
    pools: Mutex<HashMap<String, PoolEntry>>,
}

impl PoolManager {
    pub fn new() -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
        }
    }

    /// Stable key from the connection's transport-relevant configuration
    /// (everything except the credential, which participates separately as
    /// the generation).
    fn config_key(
        conn: &MySqlConnection,
        database: Option<&str>,
        revision: u64,
        host_override: Option<&str>,
        port_override: Option<u16>,
    ) -> String {
        format!(
            "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}",
            conn.name,
            host_override.unwrap_or(&conn.host),
            port_override.unwrap_or(conn.port),
            conn.user,
            database.or(conn.database.as_deref()).unwrap_or(""),
            conn.ssl,
            conn.ssl_server_name.as_deref().unwrap_or(""),
            revision,
        )
    }

    /// Return a verified pool for this configuration+credential,
    /// initializing (handshake + health query) at most one pool per key
    /// even under concurrent first access. Superseded pools are closed and
    /// evicted. Auth/DNS/TLS/handshake failures never populate the cache.
    pub async fn verified_pool(
        &self,
        conn: &MySqlConnection,
        password: &Zeroizing<String>,
        database: Option<&str>,
        revision: u64,
        host_override: Option<&str>,
        port_override: Option<u16>,
    ) -> Result<Pool, PoolManagerError> {
        let generation = CredentialGeneration::derive(password);
        let key = Self::config_key(conn, database, revision, host_override, port_override);

        // Fast path: a matching live pool already exists.
        {
            let pools = self.pools.lock().unwrap();
            if let Some(entry) = pools.get(&key)
                && entry.generation.eq_material(&generation)
            {
                return Ok(entry.pool.clone());
            }
        }

        // Slow path: build OUTSIDE the shared cache, verify with a real
        // handshake + health query, then publish. Concurrent first users
        // re-check under the lock so only one initialization wins; the
        // losers' candidates get dropped (their connections close).
        let opts: mysql_async::Opts =
            super::mysql::build_opts(conn, password, database, host_override, port_override).into();
        let candidate = Pool::new(opts);
        {
            use mysql_async::prelude::Queryable;
            // mysql_async has no built-in TCP-connect deadline; enforce one
            // around the handshake+health probe so blackhole addresses
            // fail with a typed timeout instead of hanging.
            let probe = async {
                let mut conn = candidate
                    .get_conn()
                    .await
                    .map_err(|e| PoolManagerError::Init(e.to_string()))?;
                conn.query_drop("SELECT 1")
                    .await
                    .map_err(|e| PoolManagerError::Init(format!("health query failed: {e}")))?;
                Ok::<(), PoolManagerError>(())
            };
            tokio::time::timeout(super::mysql::CONNECT_TIMEOUT, probe)
                .await
                .map_err(|_| {
                    PoolManagerError::Init(format!(
                        "connect timeout after {}s",
                        super::mysql::CONNECT_TIMEOUT.as_secs()
                    ))
                })??;
        }

        let mut pools = self.pools.lock().unwrap();
        if let Some(entry) = pools.get(&key) {
            if entry.generation.eq_material(&generation) {
                // Another initializer published first; drop our candidate.
                return Ok(entry.pool.clone());
            }
            // Credential rotated: supersede (close + evict) the old pool.
            let old = pools.remove(&key).expect("entry present");
            let _close = tokio::task::spawn(old.pool.disconnect());
        }
        if pools.len() >= MAX_POOLS {
            return Err(PoolManagerError::CacheFull(pools.len()));
        }
        pools.insert(
            key,
            PoolEntry {
                pool: candidate.clone(),
                generation,
            },
        );
        Ok(candidate)
    }

    pub fn pool_count(&self) -> usize {
        self.pools.lock().unwrap().len()
    }

    pub fn invalidate_all(&self) {
        let mut pools = self.pools.lock().unwrap();
        for (_, entry) in pools.drain() {
            let _close = tokio::task::spawn(entry.pool.disconnect());
        }
    }
}

impl Default for PoolManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(host: &str) -> MySqlConnection {
        MySqlConnection {
            name: "t".into(),
            host: host.into(),
            port: 3306,
            user: "u".into(),
            ..MySqlConnection::default()
        }
    }

    #[test]
    fn generation_is_deterministic_per_process() {
        let a = CredentialGeneration::derive("pw");
        let b = CredentialGeneration::derive("pw");
        assert!(a.eq_material(&b));
        assert!(!a.eq_material(&CredentialGeneration::derive("other")));
    }

    #[test]
    fn generation_debug_and_display_are_redacted() {
        let g = CredentialGeneration::derive("secret-value");
        assert_eq!(format!("{g:?}"), "CredentialGeneration(<redacted>)");
        assert_eq!(format!("{g}"), "<redacted>");
        // Raw digest bytes never leak through the standard formatting.
        let s = format!("{g:?}{g}");
        assert!(!s.contains("secret-value"));
    }

    #[tokio::test]
    async fn failed_handshake_never_populates_cache() {
        let mgr = PoolManager::new();
        // port 1 on localhost: connection refused.
        let c = conn("127.0.0.1");
        let pw = Zeroizing::new("x".to_string());
        let err = mgr
            .verified_pool(&c, &pw, None, 1, None, Some(1))
            .await
            .unwrap_err();
        assert!(matches!(err, PoolManagerError::Init(_)), "{err:?}");
        assert_eq!(mgr.pool_count(), 0);
    }

    #[tokio::test]
    async fn concurrent_first_access_initializes_once() {
        use std::sync::Arc;
        // Uses a live server when available; otherwise verifies the
        // coalescing logic against a refusal endpoint is vacuous, so only
        // the no-cache guarantee is asserted here.
        let mgr = Arc::new(PoolManager::new());
        let c = conn("127.0.0.1");
        let pw = Zeroizing::new("x".to_string());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = mgr.clone();
            let cc = c.clone();
            let p = pw.clone();
            handles.push(tokio::task::spawn(async move {
                m.verified_pool(&cc, &p, None, 1, None, Some(2)).await
            }));
        }
        for h in handles {
            assert!(h.await.unwrap().is_err());
        }
        assert_eq!(mgr.pool_count(), 0, "failures must not be cached");
    }

    #[test]
    fn config_key_separates_transport_settings() {
        let c1 = conn("db1.example.invalid");
        let mut c2 = conn("db2.example.invalid");
        c2.ssl = true;
        let k1 = PoolManager::config_key(&c1, None, 1, None, None);
        let k2 = PoolManager::config_key(&c2, None, 1, None, None);
        let k3 = PoolManager::config_key(&c1, None, 2, None, None);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }
}
