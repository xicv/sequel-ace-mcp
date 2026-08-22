//! MCP server layer: registration, framing, result mapping.
//!
//! stdout carries protocol frames only; logs go to stderr. Tool handlers
//! call the shared library services — no policy or SQL logic lives here.

pub mod confirm;
pub mod limits;
pub mod mrtr;
pub mod tools;

use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use std::sync::Arc;

use crate::approval::ApprovalEngine;
use crate::audit::AuditDb;
use crate::config::ConfigStore;
use crate::vault::keychain::SecretStore;
use crate::vault::touchid::SessionAuthenticator;

/// Shared state handed to every tool handler.
#[derive(Clone)]
pub struct AppCtx {
    pub config: Arc<ConfigStore>,
    pub audit: Arc<AuditDb>,
    pub approvals: Arc<ApprovalEngine>,
    pub auth: Arc<SessionAuthenticator>,
    pub secrets: Arc<dyn SecretStore>,
    /// Approval IPC hub (companion approvals). `None` when the runtime
    /// socket could not be bound — approvals then rely on elicitation
    /// alone and fail closed without a client prompt.
    pub approval_ipc: Option<Arc<crate::approval::ipc::ApprovalIpc>>,
}

pub fn build_server_info() -> ServerInfo {
    let mut info = ServerInfo::default();
    info.capabilities = ServerCapabilities::builder()
        .enable_tools()
        .enable_prompts()
        .enable_resources()
        .build();
    info.server_info = Implementation::new(crate::PACKAGE_NAME, crate::PACKAGE_VERSION);
    info.instructions = Some(
        "Policy-gated MySQL/MariaDB and SQLite access. Reads are allowed by default; \
         writes require policy + user confirmation; ambiguous statements fail closed. \
         Prefer `query` for reads; `execute` for everything else."
            .into(),
    );
    info
}

#[derive(Clone)]
pub struct SequelServer {
    ctx: AppCtx,
}

impl SequelServer {
    pub fn new(ctx: AppCtx) -> Self {
        Self { ctx }
    }

    pub fn with_defaults() -> Self {
        Self {
            ctx: AppCtx {
                config: Arc::new(ConfigStore::new()),
                audit: AuditDb::shared(),
                approvals: Arc::new(ApprovalEngine::new()),
                auth: Arc::new(SessionAuthenticator::new(
                    crate::vault::touchid::system_touch_id(),
                )),
                secrets: crate::vault::keychain::default_store(),
                approval_ipc: None,
            },
        }
    }

    /// `with_defaults` plus the approval IPC hub: binds the runtime
    /// socket for companion approvals (the `approve` CLI now, the GUI
    /// later) and runs the boot-time retention auto-cleanup when due.
    pub fn with_approval_ipc() -> Self {
        let mut server = Self::with_defaults();
        match crate::approval::ipc::ApprovalIpc::start() {
            Ok(hub) => {
                server.ctx.approval_ipc = Some(hub);
            }
            Err(e) => {
                eprintln!(
                    "[sequel-mcp] approval IPC unavailable ({}); elicitation-only approvals",
                    e
                );
            }
        }
        // Boot retention: runs only when the configured interval elapsed
        // since the last recorded cleanup.
        if let Ok(cfg) = server.ctx.config.load()
            && let Some(report) =
                crate::audit::retention::maybe_auto_cleanup(&server.ctx.audit, &cfg.retention)
        {
            eprintln!(
                "[sequel-mcp] auto-cleanup: pruned {} audit row(s), {} backup(s), reclaimed {} byte(s)",
                report.audit_deleted, report.backup_deleted, report.bytes_reclaimed
            );
        }
        server
    }
}

/// A single JSON-returning tool result: structuredContent plus the
/// spec-recommended text fallback (legacy `jsonResult`).
pub fn json_tool_result(value: serde_json::Value) -> CallToolResult {
    CallToolResult::structured(value)
}

/// Error result with `isError: true` and a text block (legacy `toolError`).
pub fn error_tool_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

/// Plain text success result (legacy `textResult`).
pub fn text_tool_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text)])
}
