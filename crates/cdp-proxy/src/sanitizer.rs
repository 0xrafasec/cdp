//! Response header sanitizer — strips sensitive headers from proxied responses.
//!
//! The proxy must never forward credential-bearing or authentication-challenge
//! headers to the agent.  These headers are stripped before the response is
//! returned to the caller.

use http::header::{HeaderMap, HeaderName};

// ---------------------------------------------------------------------------
// Sensitive header list
// ---------------------------------------------------------------------------

/// Headers that must be stripped from every proxied response.
///
/// This list covers:
/// - `Authorization` — should never appear in a response, but strip defensively
/// - `Set-Cookie` — agents must never receive session cookies (browser sessions
///   are `proxy_only` by default)
/// - `WWW-Authenticate` — authentication challenge leaks credential type info
/// - `Proxy-Authorization` — must never be forwarded to agents
static SENSITIVE_RESPONSE_HEADERS: &[&str] = &[
    "authorization",
    "set-cookie",
    "www-authenticate",
    "proxy-authorization",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Strip all sensitive authentication/session headers from an HTTP response.
///
/// This must be called on every upstream response before returning it to the
/// agent.  The operation is in-place.
pub fn sanitize_response<B>(response: &mut http::Response<B>) {
    strip_credential_headers(response.headers_mut());
}

/// Remove all sensitive authentication/session headers from a [`HeaderMap`].
///
/// This lower-level function is used both by [`sanitize_response`] and by the
/// redirect pass-through path where only headers (not a full response) are
/// available.
pub fn strip_credential_headers(headers: &mut HeaderMap) {
    for name in SENSITIVE_RESPONSE_HEADERS {
        // `HeaderName::from_static` requires a lowercase compile-time constant.
        // We use `from_bytes` to handle the dynamic iteration safely.
        if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&header_name);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use http::header::{AUTHORIZATION, CONTENT_TYPE, SET_COOKIE};

    fn make_response_with_headers(headers: &[(&str, &str)]) -> Response<()> {
        let mut builder = Response::builder().status(200);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("valid response")
    }

    #[test]
    fn test_strip_authorization_header() {
        let mut resp = make_response_with_headers(&[("Authorization", "Bearer secret-token")]);
        sanitize_response(&mut resp);
        assert!(
            resp.headers().get(AUTHORIZATION).is_none(),
            "Authorization header must be stripped"
        );
    }

    #[test]
    fn test_strip_set_cookie_header() {
        let mut resp =
            make_response_with_headers(&[("Set-Cookie", "session=abc123; HttpOnly; Secure")]);
        sanitize_response(&mut resp);
        assert!(
            resp.headers().get(SET_COOKIE).is_none(),
            "Set-Cookie header must be stripped"
        );
    }

    #[test]
    fn test_strip_www_authenticate_header() {
        let mut resp = make_response_with_headers(&[("WWW-Authenticate", "Basic realm=\"test\"")]);
        sanitize_response(&mut resp);
        assert!(
            resp.headers().get("www-authenticate").is_none(),
            "WWW-Authenticate header must be stripped"
        );
    }

    #[test]
    fn test_strip_proxy_authorization_header() {
        let mut resp = make_response_with_headers(&[("Proxy-Authorization", "Basic dXNlcjpwYXNz")]);
        sanitize_response(&mut resp);
        assert!(
            resp.headers().get("proxy-authorization").is_none(),
            "Proxy-Authorization header must be stripped"
        );
    }

    #[test]
    fn test_non_sensitive_headers_preserved() {
        let mut resp = make_response_with_headers(&[
            ("Content-Type", "application/json"),
            ("X-Request-Id", "abc-123"),
            ("Cache-Control", "no-store"),
        ]);
        sanitize_response(&mut resp);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "Content-Type must be preserved"
        );
        assert_eq!(
            resp.headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some("abc-123"),
            "X-Request-Id must be preserved"
        );
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "Cache-Control must be preserved"
        );
    }

    #[test]
    fn test_strip_is_case_insensitive() {
        // HTTP header names are case-insensitive per RFC 7230.
        // The `http` crate normalises them to lowercase internally.
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            "Bearer secret".parse().expect("valid value"),
        );
        headers.insert(
            HeaderName::from_static("set-cookie"),
            "id=xyz".parse().expect("valid value"),
        );
        strip_credential_headers(&mut headers);
        assert!(headers.get("authorization").is_none());
        assert!(headers.get("set-cookie").is_none());
    }

    #[test]
    fn test_mixed_response_only_sensitive_stripped() {
        let mut resp = make_response_with_headers(&[
            ("Authorization", "Bearer tok"),
            ("Set-Cookie", "sess=abc"),
            ("WWW-Authenticate", "Basic"),
            ("Proxy-Authorization", "Basic xyz"),
            ("Content-Length", "42"),
            ("Server", "nginx"),
        ]);
        sanitize_response(&mut resp);

        assert!(resp.headers().get("authorization").is_none());
        assert!(resp.headers().get("set-cookie").is_none());
        assert!(resp.headers().get("www-authenticate").is_none());
        assert!(resp.headers().get("proxy-authorization").is_none());
        assert!(resp.headers().get("content-length").is_some());
        assert!(resp.headers().get("server").is_some());
    }

    #[test]
    fn test_empty_response_is_fine() {
        let mut resp: Response<()> = Response::builder()
            .status(204)
            .body(())
            .expect("valid response");
        // Should not panic on empty headers.
        sanitize_response(&mut resp);
        assert!(resp.headers().is_empty());
    }
}
