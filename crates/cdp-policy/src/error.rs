use thiserror::Error;

/// Errors produced by the cdp-policy crate.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error in {file}: {reason}")]
    Parse { file: String, reason: String },

    #[error("policy validation error in {policy_name}: {reason}")]
    Validation { policy_name: String, reason: String },

    #[error("policy directory not found: {0}")]
    DirectoryNotFound(String),

    #[error("approval timeout after {0} seconds")]
    ApprovalTimeout(u64),

    #[error("approval command failed: {0}")]
    ApprovalCommand(String),

    #[error("watcher error: {0}")]
    Watcher(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("glob pattern error: {0}")]
    GlobPattern(String),
}
