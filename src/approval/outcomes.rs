//! Audit-facing approval outcome vocabulary. An unavailable prompt is not a
//! decline; a cancelled dialog is not a refusal; expiry is neither.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Approved,
    Declined,
    Cancelled,
    Unavailable,
    Expired,
    Denied,
    ExecutionError,
}

impl ApprovalOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalOutcome::Approved => "approved",
            ApprovalOutcome::Declined => "declined",
            ApprovalOutcome::Cancelled => "cancelled",
            ApprovalOutcome::Unavailable => "unavailable",
            ApprovalOutcome::Expired => "expired",
            ApprovalOutcome::Denied => "denied",
            ApprovalOutcome::ExecutionError => "execution_error",
        }
    }
}
