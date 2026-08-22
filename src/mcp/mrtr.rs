//! Modern-era (2026-07-28) MRTR approval state.
//!
//! Design: **server-side opaque handles** (the MCP migration guidance's
//! recommended shape for state that round-trips through the client). The
//! wire `requestState` is only a base64url-encoded 256-bit random token;
//! every binding — tool, connection, operation digest, policy revision,
//! DDL plan targets, expiry — lives in the in-process pending store.
//! Nothing on the wire is trusted on retry: a client-crafted or
//! client-modified state is simply an unknown token, so unforgeability
//! does not depend on any offline secret. Tokens are single-use with
//! atomic consumption, strictly expiring, bounded in number, redacted in
//! `Debug` output, and invalidated by process exit.

use crate::approval::ConfirmOutcome;
use rand::RngCore;
use sha2::Digest;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Approval lifetime (absolute; checked at consumption).
pub const TTL: Duration = Duration::from_secs(120);
/// Bounded pending capacity; issuing beyond this evicts the oldest.
pub const MAX_PENDING: usize = 32;
/// Consumed-token tombstones so a replay reports `already_consumed`
/// instead of a generic unknown state (bounded, oldest first).
pub const MAX_TOMBSTONES: usize = 256;

/// Server-side record for one pending approval. Never serialized to the
/// wire; `Debug` never exposes the digest or target set.
pub struct PendingApproval {
    pub tool: &'static str,
    pub connection: String,
    pub operation_digest: String,
    pub policy_revision: u64,
    /// Plan-time confirmed-existing DDL targets for DROP statements. The
    /// retry must not execute anything outside this set: a target created
    /// between plan and execution fails closed (DdlPreconditionChanged).
    pub approved_ddl_targets: Option<Vec<(String, String)>>,
    pub expires_at: Instant,
}

impl std::fmt::Debug for PendingApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingApproval")
            .field("tool", &self.tool)
            .field("connection", &self.connection)
            .field("policy_revision", &self.policy_revision)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Typed MRTR retry failures. `code()` is the machine-readable wire
/// discriminator; retries must fail with one of these, never as an
/// ordinary SQL error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MrtrError {
    /// Unknown, malformed, truncated, oversized, foreign, or mismatched
    /// state — includes the "operation changed after approval" digest
    /// mismatch (a different operation was approved).
    InvalidState(&'static str),
    Expired,
    PolicyChanged,
    AlreadyConsumed,
}

impl MrtrError {
    pub fn code(&self) -> &'static str {
        match self {
            MrtrError::InvalidState(_) => "mrtr_invalid_state",
            MrtrError::Expired => "mrtr_expired",
            MrtrError::PolicyChanged => "mrtr_policy_changed",
            MrtrError::AlreadyConsumed => "mrtr_already_consumed",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            MrtrError::InvalidState(d) => d,
            MrtrError::Expired => "approval expired before the retry",
            MrtrError::PolicyChanged => "policy revision changed after approval",
            MrtrError::AlreadyConsumed => "approval already consumed (single use)",
        }
    }

    pub fn message(&self) -> String {
        format!("[{}] {}", self.code(), self.detail())
    }
}

/// Digest binding the approved operation: connection + statement text +
/// policy revision. A retry with a different statement (including a
/// reordered table set) produces a different digest.
pub fn operation_digest(sql: &str, connection: &str, revision: u64) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"sequel-mcp/mrtr/v2\n");
    h.update(connection.as_bytes());
    h.update(b"\n");
    h.update(sql.as_bytes());
    h.update(b"\n");
    h.update(revision.to_le_bytes());
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

type Token = [u8; 32];

struct Store {
    pending: VecDeque<(Token, PendingApproval)>,
    tombstones: VecDeque<Token>,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

fn encode(token: &Token) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
}

fn decode(state: &str) -> Option<Token> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(state)
        .ok()?;
    let token: Token = raw.try_into().ok()?;
    Some(token)
}

/// Issue a new opaque one-shot state for `p`; returns the wire token.
pub fn issue(p: PendingApproval) -> String {
    let mut token = [0u8; 32];
    rand::rng().fill_bytes(&mut token);
    let mut guard = STORE.lock().unwrap();
    let s = guard.get_or_insert_with(|| Store {
        pending: VecDeque::new(),
        tombstones: VecDeque::new(),
    });
    s.pending.push_back((token, p));
    while s.pending.len() > MAX_PENDING {
        s.pending.pop_front();
    }
    encode(&token)
}

/// Number of outstanding pending approvals (diagnostics/tests).
pub fn pending_count() -> usize {
    STORE
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.pending.len())
        .unwrap_or(0)
}

/// Atomically consume the state and validate every binding. The token is
/// consumed whenever it is FOUND, even if validation then fails — one
/// echo, one attempt. Validation order: tool, connection, policy
/// revision, operation digest, expiry — so a policy change after approval
/// reports `policy_changed` rather than a digest mismatch, and a mutated
/// statement (same revision) reports `invalid_state`.
pub fn take(
    state: &str,
    tool: &'static str,
    connection: &str,
    digest: &str,
    policy_revision: u64,
) -> Result<PendingApproval, MrtrError> {
    let token = decode(state).ok_or(MrtrError::InvalidState("malformed requestState token"))?;
    let mut guard = STORE.lock().unwrap();
    let Some(s) = guard.as_mut() else {
        return Err(MrtrError::InvalidState(
            "unknown or expired requestState (no pending approvals in this process)",
        ));
    };
    let now = Instant::now();
    let pos = s.pending.iter().position(|(t, _)| *t == token);
    let Some(pos) = pos else {
        // Reap expired entries, then classify.
        s.pending.retain(|(_, p)| p.expires_at > now);
        if s.tombstones.iter().any(|t| *t == token) {
            return Err(MrtrError::AlreadyConsumed);
        }
        return Err(MrtrError::InvalidState(
            "unknown or expired requestState (fresh process or wrong operation)",
        ));
    };
    let (_, p) = s.pending.remove(pos).expect("position checked above");
    s.tombstones.push_back(token);
    while s.tombstones.len() > MAX_TOMBSTONES {
        s.tombstones.pop_front();
    }
    if p.expires_at <= now {
        return Err(MrtrError::Expired);
    }
    if p.tool != tool {
        return Err(MrtrError::InvalidState(
            "state was issued for a different tool",
        ));
    }
    if p.connection != connection {
        return Err(MrtrError::InvalidState(
            "state was issued for a different connection",
        ));
    }
    if p.policy_revision != policy_revision {
        return Err(MrtrError::PolicyChanged);
    }
    if p.operation_digest != digest {
        return Err(MrtrError::InvalidState("operation changed after approval"));
    }
    Ok(p)
}

/// Parse an inputResponses entry into a ConfirmOutcome.
pub fn parse_response(value: &serde_json::Value) -> ConfirmOutcome {
    let action = value["action"].as_str().unwrap_or("");
    match action {
        "accept" => {
            let choice = value["content"]["choice"].as_str().unwrap_or("");
            match choice {
                "once" => ConfirmOutcome::Chosen(crate::approval::GrantChoice::Once),
                "session" => ConfirmOutcome::Chosen(crate::approval::GrantChoice::Session),
                _ => ConfirmOutcome::Unavailable {
                    reason: "client accepted without a valid choice".into(),
                },
            }
        }
        "decline" => ConfirmOutcome::Chosen(crate::approval::GrantChoice::Decline),
        "cancel" => ConfirmOutcome::Unavailable {
            reason: "client dismissed the input request".into(),
        },
        _ => ConfirmOutcome::Unavailable {
            reason: format!("unexpected inputResponse action {action:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pending store is a process-global static shared by every unit
    // test in this binary; serialize tests that issue/consume tokens.
    static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[allow(dead_code)]
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        STORE_LOCK.lock().unwrap()
    }

    fn pending(expires_at: Instant) -> PendingApproval {
        PendingApproval {
            tool: "execute",
            connection: "c1".into(),
            operation_digest: operation_digest("DROP TABLE x", "c1", 1),
            policy_revision: 1,
            approved_ddl_targets: None,
            expires_at,
        }
    }

    fn take_ok(state: &str) -> Result<PendingApproval, MrtrError> {
        take(
            state,
            "execute",
            "c1",
            &operation_digest("DROP TABLE x", "c1", 1),
            1,
        )
    }

    #[test]
    fn issue_take_and_single_use() {
        let _store = lock();
        let state = issue(pending(Instant::now() + TTL));
        assert!(take_ok(&state).is_ok());
        assert_eq!(take_ok(&state).unwrap_err(), MrtrError::AlreadyConsumed);
    }

    #[test]
    fn wrong_tool_connection_revision_and_digest_are_typed() {
        let _store = lock();
        let state = issue(pending(Instant::now() + TTL));
        let digest = operation_digest("DROP TABLE x", "c1", 1);
        let err = take(&state, "query", "c1", &digest, 1).unwrap_err();
        assert_eq!(err.code(), "mrtr_invalid_state");
        assert!(err.detail().contains("different tool"));

        let state = issue(pending(Instant::now() + TTL));
        let err = take(&state, "execute", "c2", &digest, 1).unwrap_err();
        assert_eq!(err.code(), "mrtr_invalid_state");
        assert!(err.detail().contains("different connection"));

        let state = issue(pending(Instant::now() + TTL));
        let err = take(&state, "execute", "c1", &digest, 2).unwrap_err();
        assert_eq!(err.code(), "mrtr_policy_changed");

        // Same revision, mutated statement (reordered table set included):
        // digest mismatch is invalid_state, and the token is consumed.
        let state = issue(pending(Instant::now() + TTL));
        let err = take(
            &state,
            "execute",
            "c1",
            &operation_digest("DROP TABLE y", "c1", 1),
            1,
        )
        .unwrap_err();
        assert_eq!(err.code(), "mrtr_invalid_state");
        assert!(err.detail().contains("operation changed"));
        assert_eq!(take_ok(&state).unwrap_err(), MrtrError::AlreadyConsumed);
    }

    #[test]
    fn expired_state_is_typed_expired() {
        let _store = lock();
        let state = issue(pending(Instant::now() - Duration::from_secs(1)));
        assert_eq!(take_ok(&state).unwrap_err().code(), "mrtr_expired");
    }

    #[test]
    fn malformed_truncated_and_foreign_states_are_invalid() {
        let _store = lock();
        let state = issue(pending(Instant::now() + TTL));
        // Single-bit-ish corruption: swap the first base64 character.
        let first = state.chars().next().unwrap();
        let swapped = if first == 'A' { 'B' } else { 'A' };
        let corrupt = format!("{swapped}{}", &state[1..]);
        assert_eq!(take_ok(&corrupt).unwrap_err().code(), "mrtr_invalid_state");
        // Truncated.
        let truncated = state[..state.len() - 6].to_string();
        assert_eq!(
            take_ok(&truncated).unwrap_err().code(),
            "mrtr_invalid_state"
        );
        // Oversized.
        let oversized = "A".repeat(64 * 1024);
        assert_eq!(
            take_ok(&oversized).unwrap_err().code(),
            "mrtr_invalid_state"
        );
        // A foreign token never issued here.
        let foreign = encode(&[7u8; 32]);
        assert_eq!(take_ok(&foreign).unwrap_err().code(), "mrtr_invalid_state");
    }

    #[test]
    fn pending_store_is_bounded() {
        let _store = lock();
        for _ in 0..(MAX_PENDING + 8) {
            let _ = issue(pending(Instant::now() + TTL));
        }
        assert_eq!(pending_count(), MAX_PENDING);
    }

    #[test]
    fn debug_never_exposes_digest_or_targets() {
        let _store = lock();
        let p = PendingApproval {
            tool: "execute",
            connection: "c1".into(),
            operation_digest: "deadbeef".into(),
            policy_revision: 1,
            approved_ddl_targets: Some(vec![("app".into(), "t".into())]),
            expires_at: Instant::now(),
        };
        let s = format!("{p:?}");
        assert!(!s.contains("deadbeef"));
        assert!(!s.contains("app"));
    }
}
