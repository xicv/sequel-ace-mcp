//! The GUI's plain-data view state and its event reducer — deliberately
//! free of egui types so the mapping from companion events to what the
//! user sees is unit-testable without a window system. The egui layer
//! above this (`ApprovalsApp`) only renders `ViewState` and forwards
//! button clicks as `GrantChoice`s.

use super::companion::CompanionEvent;
use crate::approval::GrantChoice;
use crate::approval::ipc::ApprovalRequest;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Instant;

/// Recent-history bound (most recent first).
const HISTORY_CAP: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Connecting,
    Waiting,
    Disconnected(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingView {
    pub request: ApprovalRequest,
    pub arrived: Instant,
    /// Some(choice) once sent, until the ack (or loss) resolves it.
    pub answering: Option<GrantChoice>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    pub ts: String,
    pub connection: String,
    pub choice: String,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ViewState {
    pub socket: PathBuf,
    pub status: Status,
    pub pending: Option<PendingView>,
    pub history: VecDeque<HistoryEntry>,
    pub answered_total: u32,
}

impl ViewState {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            status: Status::Connecting,
            pending: None,
            history: VecDeque::new(),
            answered_total: 0,
        }
    }
}

fn utc_hms() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::macros::format_description!(
            "[hour]:[minute]:[second]"
        ))
        .unwrap_or_else(|_| "??:??:??".into())
}

fn choice_str(choice: GrantChoice) -> &'static str {
    match choice {
        GrantChoice::Once => "once",
        GrantChoice::Session => "session",
        GrantChoice::Decline => "decline",
    }
}

/// Fold one companion event into the view state.
pub fn apply_event(state: &mut ViewState, event: CompanionEvent) {
    match event {
        CompanionEvent::Connected { .. } | CompanionEvent::Waiting => {
            state.status = Status::Waiting;
        }
        CompanionEvent::Empty => {
            // Window ended with nothing pending; the companion reconnects
            // on its own. Status stays Waiting.
        }
        CompanionEvent::Request { request } => {
            state.status = Status::Waiting;
            state.pending = Some(PendingView {
                request,
                arrived: Instant::now(),
                answering: None,
            });
        }
        CompanionEvent::Acked { id, choice } => {
            state.answered_total += 1;
            let connection = state
                .pending
                .as_ref()
                .filter(|p| p.request.id == id)
                .map(|p| p.request.connection.clone())
                .unwrap_or_default();
            state.history.push_front(HistoryEntry {
                ts: utc_hms(),
                connection,
                choice: choice_str(choice).into(),
                result: "ok".into(),
            });
            state.pending = None;
            truncate_history(state);
        }
        CompanionEvent::Stale { id } => {
            let connection = state
                .pending
                .as_ref()
                .filter(|p| p.request.id == id)
                .map(|p| p.request.connection.clone())
                .unwrap_or_default();
            state.history.push_front(HistoryEntry {
                ts: utc_hms(),
                connection,
                choice: "—".into(),
                result: "stale (expired or answered elsewhere)".into(),
            });
            state.pending = None;
            truncate_history(state);
        }
        CompanionEvent::BadChoice { id } => {
            let connection = state
                .pending
                .as_ref()
                .filter(|p| p.request.id == id)
                .map(|p| p.request.connection.clone())
                .unwrap_or_default();
            state.history.push_front(HistoryEntry {
                ts: utc_hms(),
                connection,
                choice: "—".into(),
                result: "bad-choice (protocol misuse)".into(),
            });
            state.pending = None;
            truncate_history(state);
        }
        CompanionEvent::Disconnected { reason } => {
            // A request that was still showing can no longer be answered
            // through the dead connection: record it as lost.
            if let Some(p) = state.pending.take() {
                state.history.push_front(HistoryEntry {
                    ts: utc_hms(),
                    connection: p.request.connection.clone(),
                    choice: "—".into(),
                    result: format!("connection lost ({reason})"),
                });
                truncate_history(state);
            }
            state.status = Status::Disconnected(reason);
        }
    }
}

/// Record a choice the UI tried to send but could not deliver (the
/// companion loop is gone): the request stays unanswered, fail-closed.
pub fn apply_not_delivered(state: &mut ViewState, choice: GrantChoice) {
    if let Some(p) = state.pending.take() {
        state.history.push_front(HistoryEntry {
            ts: utc_hms(),
            connection: p.request.connection.clone(),
            choice: choice_str(choice).into(),
            result: "not delivered".into(),
        });
        truncate_history(state);
    }
}

fn truncate_history(state: &mut ViewState) {
    while state.history.len() > HISTORY_CAP {
        state.history.pop_back();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: id.into(),
            category: "ddl".into(),
            connection: "conn-a".into(),
            database: None,
            tables: vec![],
            snippet: "DROP TABLE x".into(),
        }
    }

    fn view() -> ViewState {
        ViewState::new(PathBuf::from("/tmp/approval.sock"))
    }

    fn connected() -> CompanionEvent {
        CompanionEvent::Connected {
            socket: PathBuf::from("/tmp/approval.sock"),
        }
    }

    #[test]
    fn request_sets_pending_then_ack_clears_and_counts() {
        let mut v = view();
        apply_event(&mut v, connected());
        apply_event(&mut v, CompanionEvent::Waiting);
        assert_eq!(v.status, Status::Waiting);
        apply_event(
            &mut v,
            CompanionEvent::Request {
                request: request("r1"),
            },
        );
        let pending = v.pending.as_ref().unwrap();
        assert_eq!(pending.request.id, "r1");
        assert!(pending.answering.is_none());
        apply_event(
            &mut v,
            CompanionEvent::Acked {
                id: "r1".into(),
                choice: GrantChoice::Once,
            },
        );
        assert!(v.pending.is_none());
        assert_eq!(v.answered_total, 1);
        assert_eq!(v.history[0].choice, "once");
        assert_eq!(v.history[0].connection, "conn-a");
        assert_eq!(v.history[0].result, "ok");
    }

    #[test]
    fn stale_and_bad_choice_clear_pending_without_counting() {
        let mut v = view();
        apply_event(
            &mut v,
            CompanionEvent::Request {
                request: request("r2"),
            },
        );
        apply_event(&mut v, CompanionEvent::Stale { id: "r2".into() });
        assert!(v.pending.is_none());
        assert_eq!(v.answered_total, 0);
        assert!(v.history[0].result.starts_with("stale"));

        apply_event(
            &mut v,
            CompanionEvent::Request {
                request: request("r3"),
            },
        );
        apply_event(&mut v, CompanionEvent::BadChoice { id: "r3".into() });
        assert!(v.pending.is_none());
        assert_eq!(v.answered_total, 0);
        assert!(v.history[0].result.starts_with("bad-choice"));
    }

    #[test]
    fn disconnect_records_lost_request_and_status() {
        let mut v = view();
        apply_event(
            &mut v,
            CompanionEvent::Request {
                request: request("r4"),
            },
        );
        apply_event(
            &mut v,
            CompanionEvent::Disconnected {
                reason: "connect: gone".into(),
            },
        );
        assert!(v.pending.is_none());
        assert_eq!(v.status, Status::Disconnected("connect: gone".into()));
        assert!(v.history[0].result.starts_with("connection lost"));

        // A disconnect with nothing pending must not invent history.
        let before = v.history.len();
        apply_event(
            &mut v,
            CompanionEvent::Disconnected {
                reason: "again".into(),
            },
        );
        assert_eq!(v.history.len(), before);
    }

    #[test]
    fn ack_with_wrong_id_does_not_steal_a_different_connection_label() {
        let mut v = view();
        apply_event(
            &mut v,
            CompanionEvent::Request {
                request: request("real"),
            },
        );
        apply_event(
            &mut v,
            CompanionEvent::Acked {
                id: "other".into(),
                choice: GrantChoice::Session,
            },
        );
        // The pending request is still superseded (single slot), but the
        // history row must not misattribute the connection.
        assert!(v.pending.is_none());
        assert_eq!(v.history[0].connection, "");
        assert_eq!(v.history[0].choice, "session");
    }

    #[test]
    fn history_is_bounded() {
        let mut v = view();
        for i in 0..(HISTORY_CAP as u32 + 25) {
            apply_event(
                &mut v,
                CompanionEvent::Acked {
                    id: format!("r{i}"),
                    choice: GrantChoice::Decline,
                },
            );
        }
        assert_eq!(v.history.len(), HISTORY_CAP);
        assert_eq!(v.answered_total, HISTORY_CAP as u32 + 25);
    }

    #[test]
    fn not_delivered_records_fail_closed() {
        let mut v = view();
        apply_event(
            &mut v,
            CompanionEvent::Request {
                request: request("r9"),
            },
        );
        apply_not_delivered(&mut v, GrantChoice::Once);
        assert!(v.pending.is_none());
        assert_eq!(v.history[0].choice, "once");
        assert_eq!(v.history[0].result, "not delivered");
        assert_eq!(v.answered_total, 0);
    }
}
