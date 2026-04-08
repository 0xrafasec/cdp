//! CDP browser crate — browser sandbox, login automation, and cookie management.
//!
//! This crate provides:
//! - [`sandbox`]: spawns headless Chromium in a sandboxed subprocess with bubblewrap/unshare.
//! - [`snapshot`]: orchestrates the full login flow (navigate → fill → submit → 2FA → extract).
//! - [`cookies`]: filters, transforms, and stores session cookies for use by the MITM proxy.
//!
//! The browser subprocess is always SIGKILL'd after cookie extraction — it is never left running.
//! Credentials are passed to the subprocess and never logged or written to disk.

pub mod cookies;
pub mod sandbox;
pub mod snapshot;

use thiserror::Error;

/// Errors produced by the cdp-browser crate.
#[derive(Debug, Error)]
pub enum BrowserError {
    /// Sandbox setup or bubblewrap/unshare failure.
    #[error("sandbox error: {0}")]
    Sandbox(String),

    /// Subprocess spawn, communication, or lifecycle failure.
    #[error("subprocess error: {0}")]
    Subprocess(String),

    /// Login automation failed (could not fill credentials, wrong selectors, etc.).
    #[error("login failed: {0}")]
    Login(String),

    /// Cookie extraction returned no usable cookies.
    #[error("cookie extraction failed: {0}")]
    CookieExtraction(String),

    /// Two-factor authentication handling failed or was not configured.
    #[error("two-factor auth error: {0}")]
    TwoFactor(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// IPC protocol error (malformed frame, unexpected command, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] cdp_crypto::CryptoError),
}

/// Configuration for the browser sandbox.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// Path to the bubblewrap (`bwrap`) binary. Defaults to `/usr/bin/bwrap`.
    pub bwrap_path: String,
    /// Path to the headless Chromium binary. Defaults to `/usr/bin/chromium`.
    pub chromium_path: String,
    /// Enable seccomp filtering in the sandbox.
    pub enable_seccomp: bool,
    /// Enable PID namespace isolation.
    pub enable_pid_namespace: bool,
    /// Enable network namespace isolation (loopback only).
    pub enable_net_namespace: bool,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            bwrap_path: "/usr/bin/bwrap".to_string(),
            chromium_path: "/usr/bin/chromium".to_string(),
            enable_seccomp: true,
            enable_pid_namespace: true,
            enable_net_namespace: false,
        }
    }
}

// Re-export key types for ergonomic use.
pub use cookies::{Cookie, CookieFilter, CookieStore};
pub use sandbox::{BrowserSandbox, SandboxConfig, SandboxedProcess};
pub use snapshot::{LoginCredential, SessionSnapshot, SnapshotConfig, SuccessIndicator};
