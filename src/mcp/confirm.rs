//! Elicitation bridge: connects the sync gate (run on the blocking pool)
//! to the async rmcp elicitation round trip.

use crate::approval::{ConfirmOutcome, GrantChoice};
use rmcp::schemars;
use std::sync::mpsc as std_mpsc;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ChoiceForm {
    /// How to authorize the statement: once, session, or decline.
    choice: GrantChoice,
}

rmcp::elicit_safe!(ChoiceForm);

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PasswordForm {
    /// The MySQL/MariaDB password. Stored locally in the macOS Keychain;
    /// never in tool arguments, logs, or the audit DB.
    password: String,
}

rmcp::elicit_safe!(PasswordForm);

/// A sink whose `confirm` blocks on a channel that the async side answers
/// via elicitation. Built per request.
pub struct ElicitationSink {
    tx: std_mpsc::SyncSender<ElicitAsk>,
}

pub enum ElicitAsk {
    Request {
        message: String,
        reply: tokio::sync::oneshot::Sender<ConfirmOutcome>,
    },
}

impl ElicitationSink {
    pub fn new(tx: std_mpsc::SyncSender<ElicitAsk>) -> Self {
        Self { tx }
    }
}

impl crate::app::gate::ApprovalSink for ElicitationSink {
    fn confirm(&self, request: crate::app::gate::ApprovalRequest) -> ConfirmOutcome {
        use crate::policy::model::SqlCategory;
        let label = match request.category {
            SqlCategory::Read => "read",
            SqlCategory::Write => "WRITE",
            SqlCategory::Ddl => "DDL (schema-changing)",
            SqlCategory::Admin => "ADMIN",
            SqlCategory::TxCtrl => "transaction control",
        };
        let target = match &request.database {
            Some(db) => format!("{} · {}", request.connection_name, db),
            None => request.connection_name.clone(),
        };
        let tables: Vec<String> = request
            .tables
            .iter()
            .map(|t| format!("{}.{}", t.database, t.table))
            .collect();
        let session_scope = if request.database.is_some() {
            format!(
                "all {label} statements on {} until the MCP server restarts",
                request.database.clone().unwrap_or_default()
            )
        } else {
            format!("all {label} statements on this connection until the MCP server restarts")
        };
        let message = format!(
            "About to run a {label} statement on {target}.\n\n--- SQL ---\n{}\n--- end ---\n\nAffected tables: {}\n\nPick an authorization scope. \"Allow for session\" skips the prompt for {session_scope}. To make this permanent, use the set_table_policy tool.",
            request.statement_snippet,
            if tables.is_empty() {
                "(statement scope)".to_string()
            } else {
                tables.join(", ")
            }
        );
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .tx
            .send(ElicitAsk::Request {
                message,
                reply: reply_tx,
            })
            .is_err()
        {
            return ConfirmOutcome::Unavailable {
                reason: "approval channel closed".into(),
            };
        }
        // Block until the async side resolves (this runs on the blocking
        // pool, not the async runtime).
        match reply_rx.blocking_recv() {
            Ok(outcome) => outcome,
            Err(_) => ConfirmOutcome::Unavailable {
                reason: "approval channel dropped".into(),
            },
        }
    }
}

/// Drive one password-capture elicitation round trip for
/// `add_connection`. Accept-with-nonempty-string ⇒ `Ok(password)`
/// (zeroized on drop); decline/cancel/unavailable ⇒ `Err(reason)` — the
/// caller must NOT save the connection in that case.
pub async fn run_password_elicitation(
    peer: &rmcp::service::Peer<rmcp::RoleServer>,
    message: String,
) -> Result<zeroize::Zeroizing<String>, String> {
    match peer.elicit::<PasswordForm>(message).await {
        Ok(Some(form)) if !form.password.is_empty() => Ok(zeroize::Zeroizing::new(form.password)),
        Ok(Some(_)) => Err("the client accepted but returned an empty password".into()),
        Ok(None) => Err("the client accepted but returned no password content".into()),
        Err(rmcp::service::ElicitationError::UserDeclined) => {
            Err("password capture declined".into())
        }
        Err(rmcp::service::ElicitationError::UserCancelled) => {
            Err("password capture cancelled".into())
        }
        Err(e) => Err(format!("elicitation unavailable: {e}")),
    }
}

/// Drive one elicitation round trip on the async side. Mirrors the legacy
/// semantics exactly: cancel and empty/malformed content are `unavailable`,
/// never a decline.
pub async fn run_elicitation(
    peer: &rmcp::service::Peer<rmcp::RoleServer>,
    message: String,
) -> ConfirmOutcome {
    match peer.elicit::<ChoiceForm>(message).await {
        Ok(Some(form)) => ConfirmOutcome::Chosen(form.choice),
        Ok(None) => ConfirmOutcome::Unavailable {
            reason: "the client accepted but returned no choice content".into(),
        },
        Err(rmcp::service::ElicitationError::UserDeclined) => {
            ConfirmOutcome::Chosen(GrantChoice::Decline)
        }
        Err(rmcp::service::ElicitationError::UserCancelled) => ConfirmOutcome::Unavailable {
            reason: "the client dismissed the prompt without an explicit choice".into(),
        },
        Err(e) => ConfirmOutcome::Unavailable {
            reason: format!("elicitation failed: {e}"),
        },
    }
}
