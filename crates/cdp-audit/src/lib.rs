//! CDP audit crate — tamper-evident, hash-chained audit logging.
//!
//! Each audit entry contains a SHA-256 hash that covers the entry's content
//! and the previous entry's hash, forming an append-only chain that detects
//! any post-write modification.

pub mod integrity;
pub mod logger;

use thiserror::Error;

/// Errors produced by the cdp-audit crate.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The hash chain is broken at the given sequence number.
    #[error("audit chain broken at sequence {0}")]
    ChainBroken(u64),

    /// An individual entry is malformed.
    #[error("invalid audit entry at line {0}: {1}")]
    InvalidEntry(u64, String),
}

// Re-export key public types.
pub use integrity::{ChainStatus, verify_chain};
pub use logger::{AuditEntry, AuditEventType, AuditFields, AuditLogger};
