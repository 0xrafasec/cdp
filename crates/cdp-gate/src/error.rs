use thiserror::Error;

/// Errors produced by the cdp-gate crate.
#[derive(Debug, Error)]
pub enum GateError {
    #[error("config error: {0}")]
    Config(String),

    #[error("listener error: {0}")]
    Listener(String),

    #[error("agent verification failed: {0}")]
    AgentVerification(String),

    #[error("fingerprint file error: {0}")]
    Fingerprint(String),

    #[error("JSON-RPC error ({code}): {message}")]
    JsonRpc { code: i32, message: String },

    #[error("replay detected: {0}")]
    Replay(String),

    #[error("session invalid: {0}")]
    SessionInvalid(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("system call failed: {0}")]
    Syscall(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] cdp_crypto::CryptoError),
}

// Standard JSON-RPC 2.0 error codes.
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;

// CDP-specific error codes.
pub const REPLAY_DETECTED: i32 = -32010;
pub const REGISTRATION_REQUIRED: i32 = -32011;
pub const SESSION_INVALID: i32 = -32013;
pub const AGENT_VERIFICATION_FAILED: i32 = -32020;
