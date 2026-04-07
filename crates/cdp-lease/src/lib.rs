//! CDP lease crate — lease lifecycle, DNS pinning, and channel binding.

pub mod channel_bind;
pub mod delegation;
pub mod dns_pin;
pub mod liveness;
pub mod manager;
pub mod types;

use thiserror::Error;

/// Errors produced by the cdp-lease crate.
#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("lease not found: {0}")]
    NotFound(String),

    #[error("lease expired: {0}")]
    Expired(String),

    #[error("lease revoked: {0}")]
    Revoked(String),

    #[error("max renewals exceeded (limit: {0})")]
    MaxRenewalsExceeded(u32),

    #[error("max cumulative TTL exceeded (limit: {0}s)")]
    MaxCumulativeTtlExceeded(u64),

    #[error("max requests exceeded (limit: {0})")]
    MaxRequestsExceeded(u64),

    #[error("delegation depth exceeded (max: {0})")]
    DelegationDepthExceeded(u32),

    #[error("delegation not allowed by policy")]
    DelegationNotAllowed,

    #[error("child scope is not a subset of parent scope")]
    ScopeNotSubset,

    #[error("child TTL exceeds parent remaining TTL")]
    TtlExceedsParent,

    #[error("target agent is not registered or not alive")]
    TargetAgentNotAlive,

    #[error("DNS resolution failed for host {host}: {reason}")]
    DnsResolution { host: String, reason: String },

    #[error("agent not alive")]
    AgentNotAlive,

    #[error("renewal not allowed by policy")]
    NotRenewable,

    #[error("lease is not active")]
    NotActive,

    #[error("crypto error: {0}")]
    Crypto(#[from] cdp_crypto::CryptoError),
}

// Re-export primary types.
pub use manager::LeaseManager;
pub use types::{Lease, LeaseId, LeaseStatus};
