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
            },
        }
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
