//! CDP Client SDK — gate discovery, registration, lease management, and authenticated HTTP.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use cdp_sdk::CdpClient;
//!
//! #[tokio::main]
//! async fn main() -> cdp_sdk::Result<()> {
//!     let client = CdpClient::discover().await?;
//!     let mut session = client
//!         .register("my-agent", "0.1.0", &["api:read"])
//!         .await?;
//!     let lease = session
//!         .request_lease(cdp_sdk::LeaseRequest {
//!             credential_ref: "acme-api-key".to_string(),
//!             scope: cdp_sdk::Scope {
//!                 hosts: vec!["api.acme.com".to_string()],
//!                 methods: vec!["GET".to_string()],
//!                 paths: vec!["/v1/*".to_string()],
//!                 ttl_seconds: Some(300),
//!                 max_requests: Some(100),
//!             },
//!             reason: "Fetching data".to_string(),
//!         })
//!         .await?;
//!     let response = lease
//!         .fetch("https://api.acme.com/v1/data", Default::default())
//!         .await?;
//!     println!("status: {}", response.status);
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod discovery;
pub mod lease;
pub mod session;
pub mod transport;
pub mod types;

pub use client::CdpClient;
pub use lease::{FetchOptions, Lease, Response as LeaseResponse};
pub use session::Session;
pub use types::{GrantedScope, LeaseRequest, Scope};

use thiserror::Error;

/// Unified error type for the CDP SDK.
#[derive(Debug, Error)]
pub enum CdpError {
    /// Gate fingerprint file could not be found or read.
    #[error("gate not found: {0}")]
    GateNotFound(String),

    /// Gate identity verification failed (SO_PEERCRED mismatch).
    #[error("gate identity verification failed: {0}")]
    IdentityVerification(String),

    /// Connection to the Unix socket failed.
    #[error("connection failed: {0}")]
    Connection(String),

    /// JSON serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error communicating with the gate.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The gate returned a JSON-RPC error response.
    #[error("gate error {code}: {message}")]
    GateError { code: i64, message: String },

    /// The response from the gate was malformed.
    #[error("malformed response: {0}")]
    MalformedResponse(String),

    /// The lease has expired.
    #[error("lease expired")]
    LeaseExpired,

    /// HTTP proxy request failed.
    #[error("proxy request failed: {0}")]
    ProxyRequest(String),

    /// A required environment variable or config value is missing.
    #[error("configuration error: {0}")]
    Config(String),
}

/// Convenience alias for `Result<T, CdpError>`.
pub type Result<T> = std::result::Result<T, CdpError>;
