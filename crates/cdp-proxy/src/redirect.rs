//! Redirect handling — decide whether to follow, pass through, or block
//! HTTP 3xx responses received from upstream.
//!
//! Per the threat model, redirect following is disabled by default and must
//! be explicitly enabled in the lease scope.  When enabled, the redirect
//! target host must be in the lease's allowed hosts list.

use crate::ProxyError;

// ---------------------------------------------------------------------------
// RedirectAction
// ---------------------------------------------------------------------------

/// The action the proxy should take when it receives a 3xx response.
#[derive(Debug, PartialEq)]
pub enum RedirectAction {
    /// Return the response as-is after stripping credential headers.
    ///
    /// Used when `follow_redirects` is disabled in the lease scope.
    PassThrough,

    /// Follow the redirect to `location`, after DNS-pin verification.
    ///
    /// Used when the redirect target is allowed.
    Follow {
        /// The full Location URI.
        location: http::Uri,
        /// The hostname extracted from the URI (used for DNS-pin lookup).
        host: String,
    },

    /// Block the redirect; the proxy returns an error to the agent.
    ///
    /// Used when the redirect target host is not in the allowed set.
    Block {
        /// Human-readable reason for the block.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// evaluate_redirect
// ---------------------------------------------------------------------------

/// Determine what to do with a 3xx response.
///
/// # Arguments
///
/// * `status`           — the HTTP status code of the upstream response
/// * `headers`          — the response headers (for the `Location` field)
/// * `follow_redirects` — whether the lease permits redirect following
/// * `allowed_hosts`    — the hosts allowed by the lease scope
///
/// # Returns
///
/// * `Ok(PassThrough)` — when `follow_redirects` is `false`, or when the
///   status is not a redirect code (handled gracefully)
/// * `Ok(Follow { .. })` — when following is enabled and the target is allowed
/// * `Ok(Block { .. })` — when following is enabled but the target is not allowed
/// * `Err(ProxyError::RedirectBlocked)` — when the `Location` header is absent
///   or unparseable while in follow mode
pub fn evaluate_redirect(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    follow_redirects: bool,
    allowed_hosts: &[String],
) -> Result<RedirectAction, ProxyError> {
    // Non-3xx responses should not be passed here, but handle gracefully.
    if !status.is_redirection() {
        return Ok(RedirectAction::PassThrough);
    }

    // Redirect following is disabled — return the response as-is.
    if !follow_redirects {
        return Ok(RedirectAction::PassThrough);
    }

    // Following is enabled: parse Location header.
    let location_header = headers.get(http::header::LOCATION).ok_or_else(|| {
        ProxyError::RedirectBlocked(format!(
            "3xx response (status {status}) has no Location header"
        ))
    })?;

    let location_str = location_header.to_str().map_err(|_| {
        ProxyError::RedirectBlocked("Location header contains non-ASCII characters".to_string())
    })?;

    let uri = location_str.parse::<http::Uri>().map_err(|e| {
        ProxyError::RedirectBlocked(format!("Location header is not a valid URI: {e}"))
    })?;

    let host = extract_host(&uri).ok_or_else(|| {
        ProxyError::RedirectBlocked(format!(
            "Location URI has no host component: {location_str}"
        ))
    })?;

    // Check host against the allowed list.
    if allowed_hosts.is_empty() || allowed_hosts.iter().any(|h| h == &host) {
        Ok(RedirectAction::Follow {
            location: uri,
            host,
        })
    } else {
        Ok(RedirectAction::Block {
            reason: format!("redirect target {host:?} is not in the allowed hosts list"),
        })
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Extract the host component from a URI, stripping any port number.
fn extract_host(uri: &http::Uri) -> Option<String> {
    uri.host().map(|h| h.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    fn make_headers_with_location(location: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::LOCATION,
            location.parse().expect("valid header value"),
        );
        headers
    }

    // --- follow_redirects = false ---

    #[test]
    fn test_follow_disabled_returns_pass_through() {
        let headers = make_headers_with_location("https://api.example.com/new-path");
        let action = evaluate_redirect(
            StatusCode::MOVED_PERMANENTLY,
            &headers,
            false, // follow disabled
            &["api.example.com".to_string()],
        )
        .expect("should not error");
        assert_eq!(action, RedirectAction::PassThrough);
    }

    #[test]
    fn test_follow_disabled_302_returns_pass_through() {
        let headers = make_headers_with_location("https://other.example.com/");
        let action =
            evaluate_redirect(StatusCode::FOUND, &headers, false, &[]).expect("should not error");
        assert_eq!(action, RedirectAction::PassThrough);
    }

    // --- non-3xx status ---

    #[test]
    fn test_non_redirect_status_returns_pass_through() {
        let headers = make_headers_with_location("https://example.com/");
        let action =
            evaluate_redirect(StatusCode::OK, &headers, true, &[]).expect("should not error");
        assert_eq!(action, RedirectAction::PassThrough);
    }

    // --- follow_redirects = true, allowed host ---

    #[test]
    fn test_follow_enabled_allowed_host_returns_follow() {
        let headers = make_headers_with_location("https://api.example.com/v2/resource");
        let action = evaluate_redirect(
            StatusCode::MOVED_PERMANENTLY,
            &headers,
            true,
            &["api.example.com".to_string()],
        )
        .expect("should not error");
        match action {
            RedirectAction::Follow { host, location } => {
                assert_eq!(host, "api.example.com");
                assert_eq!(location.path(), "/v2/resource");
            }
            other => panic!("expected Follow, got {other:?}"),
        }
    }

    #[test]
    fn test_follow_enabled_empty_allowed_hosts_permits_all() {
        // Empty allowed_hosts = no host restriction.
        let headers = make_headers_with_location("https://any.example.com/path");
        let action =
            evaluate_redirect(StatusCode::FOUND, &headers, true, &[]).expect("should not error");
        assert!(matches!(action, RedirectAction::Follow { .. }));
    }

    // --- follow_redirects = true, disallowed host ---

    #[test]
    fn test_follow_enabled_disallowed_host_returns_block() {
        let headers = make_headers_with_location("https://evil.example.com/steal");
        let action = evaluate_redirect(
            StatusCode::FOUND,
            &headers,
            true,
            &["api.example.com".to_string()],
        )
        .expect("should not error");
        match action {
            RedirectAction::Block { reason } => {
                assert!(reason.contains("evil.example.com"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    // --- missing Location header ---

    #[test]
    fn test_follow_enabled_missing_location_is_error() {
        let headers = http::HeaderMap::new(); // no Location
        let err = evaluate_redirect(StatusCode::FOUND, &headers, true, &[])
            .expect_err("missing Location must be an error");
        assert!(matches!(err, ProxyError::RedirectBlocked(_)));
    }

    // --- various 3xx status codes ---

    #[test]
    fn test_redirect_301() {
        let headers = make_headers_with_location("https://api.example.com/new");
        let action = evaluate_redirect(
            StatusCode::MOVED_PERMANENTLY,
            &headers,
            true,
            &["api.example.com".to_string()],
        )
        .expect("301 should be handled");
        assert!(matches!(action, RedirectAction::Follow { .. }));
    }

    #[test]
    fn test_redirect_307() {
        let headers = make_headers_with_location("https://api.example.com/new");
        let action = evaluate_redirect(
            StatusCode::TEMPORARY_REDIRECT,
            &headers,
            true,
            &["api.example.com".to_string()],
        )
        .expect("307 should be handled");
        assert!(matches!(action, RedirectAction::Follow { .. }));
    }

    #[test]
    fn test_redirect_308() {
        let headers = make_headers_with_location("https://api.example.com/new");
        let action = evaluate_redirect(
            StatusCode::PERMANENT_REDIRECT,
            &headers,
            true,
            &["api.example.com".to_string()],
        )
        .expect("308 should be handled");
        assert!(matches!(action, RedirectAction::Follow { .. }));
    }

    // --- URI host extraction ---

    #[test]
    fn test_follow_strips_port_from_host() {
        let headers = make_headers_with_location("https://api.example.com:8443/path");
        let action = evaluate_redirect(
            StatusCode::FOUND,
            &headers,
            true,
            &["api.example.com".to_string()],
        )
        .expect("should not error");
        match action {
            RedirectAction::Follow { host, .. } => {
                assert_eq!(host, "api.example.com");
            }
            other => panic!("expected Follow, got {other:?}"),
        }
    }
}
