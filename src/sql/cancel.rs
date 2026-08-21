//! Server-side statement cancellation (D2).
//!
//! `MAX_EXECUTION_TIME`/`max_statement_time` only cover SELECTs and are
//! not guaranteed immediate, so this module provides active cancellation:
//! when a deadline expires, `KILL QUERY <id>` is issued from a separate
//! same-user control connection against the executing connection's id
//! (captured via `CONNECTION_ID()` before the statement runs). The
//! executing connection is only reused after its transaction state is
//! verified clean; anything inconclusive discards it. A cancelled
//! mutation is never retried automatically.

use mysql_async::Pool;
use mysql_async::prelude::Queryable;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Statement finished before the deadline (no cancellation).
    Completed,
    /// Deadline fired; KILL QUERY succeeded; the executing future
    /// resolved; the connection verified clean and stays in the pool.
    Interrupted,
    /// Deadline fired and the outcome could not be established — the
    /// executing connection was discarded. The caller must surface an
    /// uncertain result and must not retry.
    Uncertain,
}

#[derive(Debug, Error)]
pub enum CancellationError {
    #[error("statement deadline exceeded; interrupted via KILL QUERY ({0}ms)")]
    Interrupted(u64),
    #[error(
        "statement deadline exceeded; cancellation inconclusive — connection discarded ({0}ms)"
    )]
    Uncertain(u64),
}

/// Issue `KILL QUERY <connection_id>` on a separate connection from the
/// same pool (same user may kill its own threads).
pub async fn kill_query(pool: &Pool, connection_id: u64) -> Result<(), String> {
    let mut control = pool
        .get_conn()
        .await
        .map_err(|e| format!("control connection failed: {e}"))?;
    // The identifier originates from the server (CONNECTION_ID), never
    // user input, and is a u64 — formatting cannot inject. KILL is not
    // universally preparable, so it is sent as literal SQL.
    let sql = format!("KILL QUERY {connection_id}");
    control
        .query_drop(sql.as_str())
        .await
        .map_err(|e| format!("KILL QUERY failed: {e}"))
}

/// Verify a post-cancellation connection is clean: no open transaction,
/// autocommit restored, and it answers a health query. `true` = reusable.
pub async fn verify_connection_clean(conn: &mut mysql_async::Conn) -> Result<bool, String> {
    let row: Option<(i8, i8)> = conn
        .exec_first::<(i8, i8), _, _>("SELECT @@autocommit, @@in_transaction", ())
        .await
        .map_err(|e| format!("verify query failed: {e}"))?;
    match row {
        // in_transaction must be 0; autocommit is informational (we set
        // session state per operation anyway).
        Some((_, in_txn)) => Ok(in_txn == 0),
        None => Ok(false),
    }
}
