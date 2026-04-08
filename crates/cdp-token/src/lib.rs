//! CDP token crate — JWT issuance, attestation verification, and revocation.
//!
//! This crate implements AI-to-AI token issuance for the Credential Delegation
//! Protocol. It provides:
//!
//! - [`issuer`]: Ed25519-based JWT issuer and verifier with secure key storage.
//! - [`validator`]: Multi-mode attestation verification (mTLS, OIDC, Enclave, SignedCode).
//! - [`revocation`]: In-memory token revocation list with background cleanup.

pub mod issuer;
pub mod revocation;
pub mod validator;

use thiserror::Error;

/// Errors produced by the cdp-token crate.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("signing key error: {0}")]
    SigningKey(String),

    #[error("invalid claims: {0}")]
    InvalidClaims(String),

    #[error("token expired")]
    Expired,

    #[error("token revoked")]
    Revoked,

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("OIDC verification error: {0}")]
    OidcVerification(String),

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type alias for cdp-token operations.
pub type Result<T> = std::result::Result<T, TokenError>;

// Re-exports for convenience.
pub use issuer::{TokenClaims, TokenIssuer};
pub use revocation::RevocationList;
pub use validator::{AttestationResult, AttestationType, OidcConfig, TrustedIssuer};
