//! CDP crypto crate — encryption, key derivation, HMAC tokens, and secure memory.

pub mod cipher;
pub mod hkdf_ops;
pub mod hmac_ops;
pub mod mempool;
pub mod zeroize_utils;

use thiserror::Error;

/// Errors produced by the cdp-crypto crate.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: authentication or data error")]
    Decryption,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("HMAC verification failed")]
    HmacVerification,
    #[error("system call failed: {0}")]
    SystemCall(String),
    #[error("invalid token format")]
    InvalidTokenFormat,
}

// Re-export public types and functions.
pub use cipher::{decrypt, encrypt};
pub use hkdf_ops::derive_credential_key;
pub use hmac_ops::{
    generate_lease_token, generate_session_token, verify_lease_token, verify_session_token,
};
pub use mempool::{EncryptedBlob, SecureBuffer, SecurePool};
pub use zeroize::{Zeroize, ZeroizeOnDrop};
pub use zeroize_utils::disable_core_dumps;
