//! CDP vault crate — secure credential storage and subprocess isolation.
//!
//! This crate provides the `VaultBackend` trait and concrete implementations:
//! - [`SubprocessManager`]: spawns a sandboxed child process running Bitwarden CLI.
//! - [`FileBackend`]: file-based dev backend encrypted with Argon2id + ChaCha20-Poly1305.
//!
//! In production, the Gate spawns a vault subprocess with seccomp filtering,
//! `PR_SET_DUMPABLE=0`, and an optional PID namespace. Credentials are encrypted
//! over a Unix socket IPC channel using a randomly-generated 32-byte session key.

pub mod bitwarden;
pub mod child_main;
pub mod file;
pub mod protocol;
pub mod sandbox;
pub mod subprocess;

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by the cdp-vault crate.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Vault is locked and needs re-authentication.
    #[error("vault locked: {0}")]
    Locked(String),

    /// Credential not found in vault.
    #[error("credential not found: {0}")]
    NotFound(String),

    /// Subprocess communication error.
    #[error("subprocess error: {0}")]
    Subprocess(String),

    /// IPC protocol error (e.g. message too large, malformed frame).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Bitwarden CLI returned an error.
    #[error("bw CLI error: {0}")]
    BitwardenCli(String),

    /// Decryption failed (authentication tag mismatch or wrong key).
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Sandbox setup error.
    #[error("sandbox error: {0}")]
    Sandbox(String),

    /// Underlying crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] cdp_crypto::CryptoError),
}

/// An opaque reference to a credential stored in a vault backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRef {
    /// Vault-internal unique identifier (used in `fetch` calls).
    pub id: String,
    /// Human-readable name for display / audit purposes.
    pub name: String,
    /// Type discriminator (e.g. `"login"`, `"note"`, `"file"`).
    pub vault_type: String,
}

/// An encrypted credential blob returned by [`VaultBackend::fetch`].
///
/// The data is encrypted with ChaCha20-Poly1305 using the backend's IPC key.
/// Callers must decrypt it with the key returned by [`SubprocessManager::ipc_key`]
/// or [`file::FileBackend::ipc_key`] before use.
#[derive(Debug, Clone)]
pub struct EncryptedCredential {
    /// Ciphertext (with 16-byte Poly1305 tag appended by the AEAD implementation).
    pub data: Vec<u8>,
    /// 96-bit random nonce used for encryption.
    pub nonce: [u8; 12],
}

/// A stream of [`CredentialRef`] values indicating that a credential has been
/// rotated in the vault. Receivers should re-fetch the credential promptly.
pub type RotationStream = tokio::sync::mpsc::Receiver<CredentialRef>;

/// Abstraction over vault backends.
///
/// Uses `Pin<Box<dyn Future>>` return types (instead of `async_trait`) for
/// consistency with the `CredentialProvider` pattern in `cdp-proxy`.
pub trait VaultBackend: Send + Sync {
    /// List all credentials accessible in the vault.
    fn list_credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CredentialRef>, VaultError>> + Send + '_>>;

    /// Fetch and encrypt a credential by its vault-internal `ref_id`.
    ///
    /// Returns an [`EncryptedCredential`] encrypted with the backend's IPC key.
    fn fetch(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<EncryptedCredential, VaultError>> + Send + '_>>;

    /// Check whether a credential with the given `ref_id` exists.
    fn exists(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, VaultError>> + Send + '_>>;

    /// Watch for rotation events on the credential identified by `ref_id`.
    ///
    /// Returns a channel receiver; each received [`CredentialRef`] indicates
    /// that the credential has been rotated and should be re-fetched.
    fn watch_rotation(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<RotationStream, VaultError>> + Send + '_>>;
}

// Re-export key types for ergonomic use by downstream crates.
pub use bitwarden::BitwardenBackend;
pub use file::FileBackend;
pub use subprocess::SubprocessManager;
