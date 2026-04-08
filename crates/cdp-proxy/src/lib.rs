//! CDP proxy crate — HTTP proxy with triple authentication and credential injection.
//!
//! Each lease gets a dedicated per-port listener. The proxy verifies the
//! lease token (HMAC), channel binding nonce, and OS-level peer identity
//! on every request before injecting credentials and forwarding upstream.

pub mod auth;
pub mod credential;
pub mod dns;
pub mod http;
pub mod manager;
pub mod redirect;
pub mod sanitizer;
pub mod scope;

use thiserror::Error;

/// Errors produced by the cdp-proxy crate.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("scope violation: {0}")]
    ScopeViolation(String),

    #[error("DNS pin mismatch: host {host} resolved to {resolved} but pinned IPs are {pinned:?}")]
    DnsPinMismatch {
        host: String,
        resolved: std::net::IpAddr,
        pinned: Vec<std::net::IpAddr>,
    },

    #[error("redirect blocked: {0}")]
    RedirectBlocked(String),

    #[error("credential injection error: {0}")]
    CredentialInjection(String),

    #[error("port exhausted: {0}")]
    PortExhausted(String),

    #[error("listener error: {0}")]
    Listener(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("body too large: size {size} exceeds limit {limit}")]
    BodyTooLarge { size: u64, limit: u64 },

    #[error("forbidden field in request body: {0}")]
    ForbiddenField(String),

    #[error("content type not allowed: {0}")]
    ContentTypeNotAllowed(String),

    #[error("lease error: {0}")]
    Lease(#[from] cdp_lease::LeaseError),

    #[error("crypto error: {0}")]
    Crypto(#[from] cdp_crypto::CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hyper error: {0}")]
    Hyper(String),
}

/// Configuration for the CDP proxy listener pool.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// IP address to bind proxy listeners on (default: 127.0.0.1).
    pub bind_address: std::net::IpAddr,
    /// First port in the ephemeral port range for per-lease listeners.
    pub port_range_start: u16,
    /// Last port in the ephemeral port range (inclusive).
    pub port_range_end: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port_range_start: 19000,
            port_range_end: 19999,
        }
    }
}

/// Parse a port range string of the form `"start-end"` (e.g. `"19000-19999"`).
///
/// Returns `Err(ProxyError::Listener(...))` if the string is malformed or
/// the start port is greater than the end port.
pub fn parse_port_range(range_str: &str) -> Result<(u16, u16), ProxyError> {
    let parts: Vec<&str> = range_str.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(ProxyError::Listener(format!(
            "invalid port range format: {range_str:?}; expected \"start-end\""
        )));
    }

    let start = parts[0].trim().parse::<u16>().map_err(|_| {
        ProxyError::Listener(format!(
            "invalid start port in range {range_str:?}: {:?}",
            parts[0]
        ))
    })?;

    let end = parts[1].trim().parse::<u16>().map_err(|_| {
        ProxyError::Listener(format!(
            "invalid end port in range {range_str:?}: {:?}",
            parts[1]
        ))
    })?;

    if start > end {
        return Err(ProxyError::Listener(format!(
            "port range start ({start}) must be ≤ end ({end})"
        )));
    }

    Ok((start, end))
}

// Re-export key types.
pub use credential::CredentialProvider;
pub use manager::ProxyManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range_valid() {
        let (start, end) = parse_port_range("19000-19999").expect("valid range");
        assert_eq!(start, 19000);
        assert_eq!(end, 19999);
    }

    #[test]
    fn test_parse_port_range_single_port() {
        let (start, end) = parse_port_range("8080-8080").expect("single port range");
        assert_eq!(start, 8080);
        assert_eq!(end, 8080);
    }

    #[test]
    fn test_parse_port_range_with_spaces() {
        let (start, end) = parse_port_range("1000 - 2000").expect("spaces allowed");
        assert_eq!(start, 1000);
        assert_eq!(end, 2000);
    }

    #[test]
    fn test_parse_port_range_inverted_fails() {
        let err = parse_port_range("9999-1000").expect_err("inverted range must fail");
        assert!(matches!(err, ProxyError::Listener(_)));
    }

    #[test]
    fn test_parse_port_range_bad_format_fails() {
        let err = parse_port_range("notarange").expect_err("bad format must fail");
        assert!(matches!(err, ProxyError::Listener(_)));
    }

    #[test]
    fn test_parse_port_range_non_numeric_fails() {
        let err = parse_port_range("abc-def").expect_err("non-numeric must fail");
        assert!(matches!(err, ProxyError::Listener(_)));
    }

    #[test]
    fn test_proxy_config_default() {
        let cfg = ProxyConfig::default();
        assert_eq!(
            cfg.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(cfg.port_range_start, 19000);
        assert_eq!(cfg.port_range_end, 19999);
    }
}
