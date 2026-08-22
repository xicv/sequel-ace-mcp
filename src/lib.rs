//! sequel-mcp library: shared core for the MCP server, CLI and GUI.
//!
//! Every SQL-bearing surface funnels through the same policy gate and
//! execution pipeline; there is exactly one implementation of connection,
//! policy, approval and SQL behaviour in this crate.

pub mod app;
pub mod approval;
pub mod audit;
pub mod backup;
pub mod config;
pub mod importer;
pub mod mcp;
pub mod policy;
pub mod sql;
pub mod vault;

pub const PACKAGE_NAME: &str = "sequel-mcp";
pub const PACKAGE_VERSION: &str = "0.10.0";
