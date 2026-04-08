//! Scope validation — enforce lease-level constraints on proxied HTTP requests.
//!
//! Every request forwarded by the proxy is validated against the [`Scope`]
//! recorded in the lease before the credential is injected.  Violations are
//! hard-rejected with a [`ProxyError::ScopeViolation`].

use cdp_policy::{BodyConstraints, Scope};
use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::ProxyError;

// ---------------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------------

/// Validate an inbound request against the granted lease scope.
///
/// All sub-validations run in order; the first failure returns an error.
///
/// # Arguments
///
/// * `method`       — the HTTP method of the request (e.g. `GET`)
/// * `host`         — the `Host` header value (without port)
/// * `path`         — the request path (e.g. `/api/v1/users`)
/// * `content_type` — the `Content-Type` header value, if present
/// * `body`         — the raw request body bytes, if buffered
/// * `scope`        — the granted scope from the lease
pub fn validate_request(
    method: &http::Method,
    host: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    scope: &Scope,
) -> Result<(), ProxyError> {
    validate_host(host, &scope.hosts)?;
    validate_path(path, &scope.paths, &scope.forbidden_paths)?;
    validate_method(method, &scope.methods)?;

    if let Some(constraints) = &scope.body_constraints {
        validate_body(body, content_type, constraints)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Host validation
// ---------------------------------------------------------------------------

/// Check that `host` is in the `allowed_hosts` list.
///
/// If `allowed_hosts` is empty, all hosts are permitted (open scope).
/// Matching is exact (no glob patterns for hosts — DNS pinning handles
/// the network-level enforcement separately).
pub fn validate_host(host: &str, allowed_hosts: &[String]) -> Result<(), ProxyError> {
    if allowed_hosts.is_empty() {
        return Ok(());
    }
    if allowed_hosts.iter().any(|h| h == host) {
        Ok(())
    } else {
        Err(ProxyError::ScopeViolation(format!(
            "host {host:?} is not in the allowed hosts list"
        )))
    }
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Check that `path` satisfies the allow-list and is not in the deny-list.
///
/// Rules:
/// 1. If `path` matches any `forbidden_paths` glob, reject immediately —
///    forbidden paths always win regardless of allowed_paths.
/// 2. If `allowed_paths` is empty, all paths are permitted (subject to
///    the forbidden check above).
/// 3. If `allowed_paths` is non-empty, `path` must match at least one pattern.
///
/// Patterns use [`globset`] syntax (e.g. `"/api/**"`, `"/v1/users/*"`).
pub fn validate_path(
    path: &str,
    allowed_paths: &[String],
    forbidden_paths: &[String],
) -> Result<(), ProxyError> {
    // Forbidden paths always win.
    if !forbidden_paths.is_empty() {
        let forbidden_set = build_glob_set(forbidden_paths).map_err(|e| {
            ProxyError::ScopeViolation(format!("invalid forbidden path pattern: {e}"))
        })?;
        if forbidden_set.is_match(path) {
            return Err(ProxyError::ScopeViolation(format!(
                "path {path:?} is explicitly forbidden"
            )));
        }
    }

    // Empty allowed_paths → all paths allowed (modulo forbidden check above).
    if allowed_paths.is_empty() {
        return Ok(());
    }

    let allowed_set = build_glob_set(allowed_paths).map_err(|e| {
        ProxyError::ScopeViolation(format!("invalid allowed path pattern: {e}"))
    })?;

    if allowed_set.is_match(path) {
        Ok(())
    } else {
        Err(ProxyError::ScopeViolation(format!(
            "path {path:?} does not match any allowed path pattern"
        )))
    }
}

// ---------------------------------------------------------------------------
// Method validation
// ---------------------------------------------------------------------------

/// Check that `method` is in the `allowed_methods` list.
///
/// If `allowed_methods` is empty, all methods are permitted.
/// Comparison is case-insensitive (methods are normalised to uppercase).
pub fn validate_method(method: &http::Method, allowed_methods: &[String]) -> Result<(), ProxyError> {
    if allowed_methods.is_empty() {
        return Ok(());
    }
    let method_str = method.as_str();
    if allowed_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(method_str))
    {
        Ok(())
    } else {
        Err(ProxyError::ScopeViolation(format!(
            "method {method_str:?} is not in the allowed methods list"
        )))
    }
}

// ---------------------------------------------------------------------------
// Body validation
// ---------------------------------------------------------------------------

/// Validate a request body against [`BodyConstraints`].
///
/// Checks:
/// 1. Body size must not exceed `max_size_bytes` (if set).
/// 2. If `allowed_content_types` is non-empty, `content_type` must match one.
/// 3. If the body is valid JSON, no key at any depth may appear in `forbidden_fields`.
pub fn validate_body(
    body: Option<&[u8]>,
    content_type: Option<&str>,
    constraints: &BodyConstraints,
) -> Result<(), ProxyError> {
    let body_bytes = body.unwrap_or(&[]);

    // 1. Size limit.
    if let Some(max) = constraints.max_size_bytes {
        let size = body_bytes.len() as u64;
        if size > max {
            return Err(ProxyError::BodyTooLarge { size, limit: max });
        }
    }

    // 2. Content-type allow-list.
    if !constraints.allowed_content_types.is_empty() {
        let ct = content_type.unwrap_or("");
        // Content-Type values may include parameters (e.g. `application/json; charset=utf-8`).
        // We compare the media-type portion only (before the first `;`).
        let media_type = ct.split(';').next().unwrap_or("").trim();
        if !constraints
            .allowed_content_types
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(media_type))
        {
            return Err(ProxyError::ContentTypeNotAllowed(format!(
                "content type {ct:?} is not in the allowed list"
            )));
        }
    }

    // 3. Forbidden JSON fields.
    if !constraints.forbidden_fields.is_empty() && !body_bytes.is_empty() {
        // Only inspect JSON bodies (best-effort; non-JSON bodies are left alone).
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body_bytes)
            && let Some(bad_field) = find_forbidden_field(&value, &constraints.forbidden_fields)
        {
            return Err(ProxyError::ForbiddenField(bad_field));
        }
    }

    Ok(())
}

/// Maximum recursion depth for [`find_forbidden_field`].
///
/// Protects against stack overflow from deeply-nested JSON payloads crafted
/// by a malicious agent.
const MAX_JSON_DEPTH: usize = 64;

/// Recursively scan a JSON value for any key that appears in `forbidden`.
///
/// Performs depth-first search over Object keys and Array elements.  Returns
/// the first forbidden key found, or `None` if the value is clean.
///
/// Recursion is bounded to [`MAX_JSON_DEPTH`] levels to prevent stack overflow.
pub fn find_forbidden_field(
    value: &serde_json::Value,
    forbidden: &[String],
) -> Option<String> {
    find_forbidden_field_bounded(value, forbidden, 0)
}

fn find_forbidden_field_bounded(
    value: &serde_json::Value,
    forbidden: &[String],
    depth: usize,
) -> Option<String> {
    if depth >= MAX_JSON_DEPTH {
        return None;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                // Check this key.
                if forbidden.iter().any(|f| f == key) {
                    return Some(key.clone());
                }
                // Recurse into the value.
                if let Some(bad) = find_forbidden_field_bounded(child, forbidden, depth + 1) {
                    return Some(bad);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(bad) = find_forbidden_field_bounded(item, forbidden, depth + 1) {
                    return Some(bad);
                }
            }
            None
        }
        // Primitive values (string, number, bool, null) cannot contain keys.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Build a [`GlobSet`] from a slice of pattern strings.
fn build_glob_set(patterns: &[String]) -> Result<GlobSet, globset::Error> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    builder.build()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cdp_policy::BodyConstraints;

    // --- Host ---

    #[test]
    fn test_host_allowed_exact_match() {
        validate_host("api.example.com", &["api.example.com".to_string()])
            .expect("exact match must pass");
    }

    #[test]
    fn test_host_denied_not_in_list() {
        let err = validate_host(
            "evil.example.com",
            &["api.example.com".to_string()],
        )
        .expect_err("unlisted host must fail");
        assert!(matches!(err, ProxyError::ScopeViolation(_)));
    }

    #[test]
    fn test_host_empty_list_allows_all() {
        validate_host("anything.example.com", &[]).expect("empty list allows all");
    }

    // --- Path ---

    #[test]
    fn test_path_glob_match() {
        validate_path("/api/v1/users", &["/api/**".to_string()], &[])
            .expect("glob must match");
    }

    #[test]
    fn test_path_glob_no_match() {
        let err = validate_path("/admin", &["/api/**".to_string()], &[])
            .expect_err("non-matching path must fail");
        assert!(matches!(err, ProxyError::ScopeViolation(_)));
    }

    #[test]
    fn test_path_empty_allowed_permits_all() {
        validate_path("/anything/goes", &[], &[]).expect("empty allowed list permits all");
    }

    #[test]
    fn test_forbidden_path_overrides_allowed() {
        // Even though /api/** is allowed, /api/admin is forbidden.
        let err = validate_path(
            "/api/admin",
            &["/api/**".to_string()],
            &["/api/admin".to_string()],
        )
        .expect_err("forbidden path must block");
        assert!(matches!(err, ProxyError::ScopeViolation(_)));
    }

    #[test]
    fn test_forbidden_glob_path() {
        let err = validate_path(
            "/api/admin/users",
            &["/api/**".to_string()],
            &["/api/admin/**".to_string()],
        )
        .expect_err("forbidden glob must block");
        assert!(matches!(err, ProxyError::ScopeViolation(_)));
    }

    #[test]
    fn test_non_forbidden_path_passes() {
        validate_path(
            "/api/v1/users",
            &["/api/**".to_string()],
            &["/api/admin/**".to_string()],
        )
        .expect("non-forbidden path must pass");
    }

    // --- Method ---

    #[test]
    fn test_method_allowed() {
        validate_method(&http::Method::GET, &["GET".to_string(), "POST".to_string()])
            .expect("GET must be allowed");
    }

    #[test]
    fn test_method_denied() {
        let err =
            validate_method(&http::Method::DELETE, &["GET".to_string(), "POST".to_string()])
                .expect_err("DELETE must be denied");
        assert!(matches!(err, ProxyError::ScopeViolation(_)));
    }

    #[test]
    fn test_method_empty_list_allows_all() {
        validate_method(&http::Method::PATCH, &[]).expect("empty list allows all methods");
    }

    #[test]
    fn test_method_case_insensitive() {
        validate_method(&http::Method::POST, &["post".to_string()])
            .expect("case-insensitive match must work");
    }

    // --- Body size limit ---

    #[test]
    fn test_body_size_within_limit() {
        let constraints = BodyConstraints {
            max_size_bytes: Some(100),
            ..Default::default()
        };
        validate_body(Some(b"small body"), None, &constraints)
            .expect("body within limit must pass");
    }

    #[test]
    fn test_body_size_exceeds_limit() {
        let constraints = BodyConstraints {
            max_size_bytes: Some(5),
            ..Default::default()
        };
        let err = validate_body(Some(b"this is too large"), None, &constraints)
            .expect_err("body exceeding limit must fail");
        assert!(matches!(err, ProxyError::BodyTooLarge { size: 17, limit: 5 }));
    }

    // --- Content-type validation ---

    #[test]
    fn test_content_type_allowed() {
        let constraints = BodyConstraints {
            allowed_content_types: vec!["application/json".to_string()],
            ..Default::default()
        };
        validate_body(Some(b"{}"), Some("application/json"), &constraints)
            .expect("allowed content type must pass");
    }

    #[test]
    fn test_content_type_with_charset_allowed() {
        let constraints = BodyConstraints {
            allowed_content_types: vec!["application/json".to_string()],
            ..Default::default()
        };
        validate_body(
            Some(b"{}"),
            Some("application/json; charset=utf-8"),
            &constraints,
        )
        .expect("content type with parameters must match media type");
    }

    #[test]
    fn test_content_type_denied() {
        let constraints = BodyConstraints {
            allowed_content_types: vec!["application/json".to_string()],
            ..Default::default()
        };
        let err =
            validate_body(Some(b"data"), Some("text/plain"), &constraints)
                .expect_err("disallowed content type must fail");
        assert!(matches!(err, ProxyError::ContentTypeNotAllowed(_)));
    }

    // --- Forbidden field detection ---

    #[test]
    fn test_forbidden_field_top_level() {
        let constraints = BodyConstraints {
            forbidden_fields: vec!["password".to_string()],
            ..Default::default()
        };
        let body = br#"{"username": "alice", "password": "hunter2"}"#;
        let err = validate_body(Some(body), Some("application/json"), &constraints)
            .expect_err("forbidden top-level field must fail");
        assert!(matches!(err, ProxyError::ForbiddenField(ref f) if f == "password"));
    }

    #[test]
    fn test_forbidden_field_nested_object() {
        let constraints = BodyConstraints {
            forbidden_fields: vec!["secret".to_string()],
            ..Default::default()
        };
        let body = br#"{"user": {"name": "alice", "secret": "topsecret"}}"#;
        let err = validate_body(Some(body), Some("application/json"), &constraints)
            .expect_err("nested forbidden field must fail");
        assert!(matches!(err, ProxyError::ForbiddenField(ref f) if f == "secret"));
    }

    #[test]
    fn test_forbidden_field_inside_array() {
        let constraints = BodyConstraints {
            forbidden_fields: vec!["token".to_string()],
            ..Default::default()
        };
        let body = br#"{"items": [{"name": "x", "token": "abc123"}]}"#;
        let err = validate_body(Some(body), Some("application/json"), &constraints)
            .expect_err("forbidden field inside array must fail");
        assert!(matches!(err, ProxyError::ForbiddenField(ref f) if f == "token"));
    }

    #[test]
    fn test_forbidden_field_deeply_nested() {
        let constraints = BodyConstraints {
            forbidden_fields: vec!["api_key".to_string()],
            ..Default::default()
        };
        let body = br#"{"a": {"b": {"c": {"api_key": "leak"}}}}"#;
        let err = validate_body(Some(body), Some("application/json"), &constraints)
            .expect_err("deeply nested forbidden field must fail");
        assert!(matches!(err, ProxyError::ForbiddenField(ref f) if f == "api_key"));
    }

    #[test]
    fn test_forbidden_field_not_present_passes() {
        let constraints = BodyConstraints {
            forbidden_fields: vec!["password".to_string()],
            ..Default::default()
        };
        let body = br#"{"username": "alice", "action": "read"}"#;
        validate_body(Some(body), Some("application/json"), &constraints)
            .expect("no forbidden field must pass");
    }

    #[test]
    fn test_find_forbidden_field_returns_none_for_primitives() {
        let value = serde_json::Value::String("hello".to_string());
        assert!(find_forbidden_field(&value, &["hello".to_string()]).is_none());
    }

    #[test]
    fn test_non_json_body_ignored_for_field_check() {
        // Non-JSON body should not cause an error for forbidden_fields check.
        let constraints = BodyConstraints {
            forbidden_fields: vec!["password".to_string()],
            allowed_content_types: vec!["text/plain".to_string()],
            ..Default::default()
        };
        let body = b"this is plain text password=secret";
        validate_body(Some(body), Some("text/plain"), &constraints)
            .expect("non-JSON body must not trigger forbidden field check");
    }

    // --- Full validate_request integration ---

    #[test]
    fn test_validate_request_all_pass() {
        let scope = Scope {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["POST".to_string()],
            paths: vec!["/api/**".to_string()],
            forbidden_paths: vec!["/api/admin/**".to_string()],
            body_constraints: Some(BodyConstraints {
                max_size_bytes: Some(1024),
                allowed_content_types: vec!["application/json".to_string()],
                forbidden_fields: vec!["secret".to_string()],
            }),
            ..Default::default()
        };

        let body = br#"{"action": "read", "resource": "users"}"#;
        validate_request(
            &http::Method::POST,
            "api.example.com",
            "/api/v1/users",
            Some("application/json"),
            Some(body),
            &scope,
        )
        .expect("all-passing request must validate");
    }

    #[test]
    fn test_validate_request_host_fail() {
        let scope = Scope {
            hosts: vec!["api.example.com".to_string()],
            ..Default::default()
        };
        validate_request(
            &http::Method::GET,
            "evil.example.com",
            "/",
            None,
            None,
            &scope,
        )
        .expect_err("wrong host must fail");
    }
}
