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
pub mod gui;
pub mod importer;
pub mod mcp;
pub mod policy;
pub mod sql;
pub mod vault;

// RSA SSH keys are supported, not optional. russh with
// `default-features = false` (we select the `ring` backend) silently
// drops its `rsa` feature, and an RSA keypair then negotiates
// correctly — even earns USERAUTH_PK_OK — but the follow-up signature
// cannot be produced (ssh-key: `AlgorithmUnsupported { algorithm:
// Rsa { hash: None } }`), which used to surface as a misleading
// "authentication failed" (0.10.2 incident). The default `rsa` feature
// forwards to russh; without it the build fails HERE, at compile time,
// instead of at runtime against a customer's bastion.
#[cfg(not(feature = "rsa"))]
compile_error!(
    "sequel-mcp requires the `rsa` feature (forwards to russh's `rsa`): without it, RSA SSH \
     keys negotiate correctly but their signature cannot be produced, failing at runtime as a \
     misleading 'authentication failed'. Build with default features, or add --features rsa."
);

pub const PACKAGE_NAME: &str = "sequel-mcp";
pub const PACKAGE_VERSION: &str = "0.10.3";
