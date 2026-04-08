//! Cookie management: filtering, transformation, and storage for session cookies.
//!
//! This module provides:
//! - [`Cookie`]: a parsed HTTP cookie with all relevant attributes.
//! - [`CookieFilter`]: configurable allow/deny patterns plus tracking-cookie removal.
//! - [`filter_cookies`]: apply a filter to a cookie list.
//! - [`transform_for_proxy_only`]: keep cookies as-is for proxy-only mode.
//! - [`transform_for_scoped_snapshot`]: strip HttpOnly, restrict domain, set short Max-Age.
//! - [`CookieStore`]: thread-safe per-origin cookie store used by the MITM proxy.
//! - [`CookieManager`]: high-level API combining store operations.

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::BrowserError;

// ---------------------------------------------------------------------------
// Cookie struct
// ---------------------------------------------------------------------------

/// An HTTP cookie with all relevant attributes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value (plaintext; callers are responsible for encryption at rest).
    pub value: String,
    /// Domain the cookie applies to.
    pub domain: String,
    /// Path the cookie applies to.
    pub path: String,
    /// Whether the cookie is Secure (HTTPS only).
    pub secure: bool,
    /// Whether the cookie is HttpOnly (not accessible from JavaScript).
    pub http_only: bool,
    /// SameSite attribute: `"Strict"`, `"Lax"`, `"None"`, or empty.
    pub same_site: String,
    /// Absolute Unix timestamp (seconds) when the cookie expires.
    /// `None` means session cookie (no Max-Age or Expires).
    pub expires: Option<u64>,
    /// Max-Age in seconds. Takes precedence over `expires` when set.
    pub max_age: Option<u64>,
}

impl Cookie {
    /// Create a minimal session cookie (no expiry attributes).
    pub fn session(
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: domain.into(),
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: "Lax".to_string(),
            expires: None,
            max_age: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Known tracking cookie patterns
// ---------------------------------------------------------------------------

/// Cookie name prefixes/patterns considered tracking cookies.
///
/// These are dropped when `CookieFilter::drop_tracking` is `true` (the default).
static TRACKING_PATTERNS: &[&str] = &[
    r"^_ga$",
    r"^_gid$",
    r"^_fbp$",
    r"^_gcl_",
    r"^__utm",
    r"^_hjid$",
    r"^_hjSession",
    r"^_hjIncludedInPageview",
    r"^_hjFirstSeen$",
    r"^_hjAbsoluteSessionInProgress$",
    r"^_ttp$",
    r"^_pin_unauth$",
    r"^MUID$",
    r"^IDE$",
];

// ---------------------------------------------------------------------------
// CookieFilter
// ---------------------------------------------------------------------------

/// Filter configuration for selecting which cookies to keep.
pub struct CookieFilter {
    /// Regexes — only cookies whose name matches at least one pattern are kept.
    /// If empty, all cookies pass the keep-pattern check.
    pub keep_patterns: Vec<Regex>,
    /// Regexes — cookies whose name matches any pattern are dropped.
    pub drop_patterns: Vec<Regex>,
    /// Drop known tracking cookies (analytics, ad-tech). Default: `true`.
    pub drop_tracking: bool,
}

impl Default for CookieFilter {
    fn default() -> Self {
        Self {
            keep_patterns: Vec::new(),
            drop_patterns: Vec::new(),
            drop_tracking: true,
        }
    }
}

impl CookieFilter {
    /// Create a filter that keeps all cookies and drops tracking cookies.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a keep pattern (name must match to be retained).
    pub fn keep(mut self, pattern: &str) -> Result<Self, BrowserError> {
        let re = Regex::new(pattern).map_err(|e| {
            BrowserError::Protocol(format!("invalid keep pattern '{pattern}': {e}"))
        })?;
        self.keep_patterns.push(re);
        Ok(self)
    }

    /// Add a drop pattern (name matching this is removed).
    pub fn drop_pattern(mut self, pattern: &str) -> Result<Self, BrowserError> {
        let re = Regex::new(pattern).map_err(|e| {
            BrowserError::Protocol(format!("invalid drop pattern '{pattern}': {e}"))
        })?;
        self.drop_patterns.push(re);
        Ok(self)
    }

    /// Set whether to drop known tracking cookies.
    pub fn with_drop_tracking(mut self, drop: bool) -> Self {
        self.drop_tracking = drop;
        self
    }

    /// Test whether a cookie name passes the tracking check.
    fn is_tracking(name: &str) -> bool {
        // Lazily compile patterns once per call. In a hot path this would be
        // pre-compiled, but cookie filtering is done at most once per session.
        TRACKING_PATTERNS.iter().any(|pat| {
            Regex::new(pat)
                .ok()
                .map(|re| re.is_match(name))
                .unwrap_or(false)
        })
    }
}

// ---------------------------------------------------------------------------
// filter_cookies
// ---------------------------------------------------------------------------

/// Apply `filter` to `cookies`, returning only the cookies that pass.
///
/// Rules applied in order:
/// 1. If `drop_tracking` is set and the cookie name matches a tracking pattern, drop it.
/// 2. If `drop_patterns` is non-empty and the name matches any, drop it.
/// 3. If `keep_patterns` is non-empty, only keep cookies whose name matches at least one.
pub fn filter_cookies(cookies: Vec<Cookie>, filter: &CookieFilter) -> Vec<Cookie> {
    cookies
        .into_iter()
        .filter(|c| {
            // Step 1: drop tracking cookies.
            if filter.drop_tracking && CookieFilter::is_tracking(&c.name) {
                return false;
            }

            // Step 2: drop explicitly forbidden cookies.
            if filter.drop_patterns.iter().any(|re| re.is_match(&c.name)) {
                return false;
            }

            // Step 3: if keep patterns are specified, require at least one to match.
            if !filter.keep_patterns.is_empty()
                && !filter.keep_patterns.iter().any(|re| re.is_match(&c.name))
            {
                return false;
            }

            true
        })
        .collect()
}

// ---------------------------------------------------------------------------
// transform_for_proxy_only
// ---------------------------------------------------------------------------

/// Keep cookies as-is for `proxy_only` mode.
///
/// In proxy-only mode the cookies live entirely inside the MITM proxy — the
/// agent never sees them. No transformation is needed beyond what the filter
/// already applied.
pub fn transform_for_proxy_only(cookies: Vec<Cookie>) -> Vec<Cookie> {
    cookies
}

// ---------------------------------------------------------------------------
// transform_for_scoped_snapshot
// ---------------------------------------------------------------------------

/// Transform cookies for `scoped_snapshot` mode.
///
/// - Strip `HttpOnly` (callee will read the cookie value).
/// - Restrict domain to `allowed_domain` (prevent scope creep).
/// - Set `Max-Age` to `max_age_seconds` (short-lived; override any baked-in expiry).
/// - Set `Secure = true` (always require HTTPS).
pub fn transform_for_scoped_snapshot(
    cookies: Vec<Cookie>,
    allowed_domain: &str,
    max_age_seconds: u64,
) -> Vec<Cookie> {
    cookies
        .into_iter()
        .map(|mut c| {
            c.http_only = false;
            c.domain = allowed_domain.to_string();
            c.max_age = Some(max_age_seconds);
            c.expires = None; // max_age takes precedence; clear expires.
            c.secure = true;
            c
        })
        .collect()
}

// ---------------------------------------------------------------------------
// CookieStore
// ---------------------------------------------------------------------------

/// Thread-safe per-origin cookie store used by the MITM proxy.
///
/// Keys are origin strings (e.g. `"https://example.com"`). Values are the
/// cookies for that origin. The MITM proxy queries this store to inject
/// `Cookie:` headers into outbound requests.
#[derive(Debug, Default, Clone)]
pub struct CookieStore {
    inner: Arc<RwLock<HashMap<String, Vec<Cookie>>>>,
}

impl CookieStore {
    /// Create an empty cookie store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store cookies for the given origin, replacing any existing cookies.
    pub async fn set(&self, origin: impl Into<String>, cookies: Vec<Cookie>) {
        let mut map = self.inner.write().await;
        map.insert(origin.into(), cookies);
    }

    /// Retrieve cookies for the given origin.
    ///
    /// Returns an empty `Vec` if no cookies are stored for this origin.
    pub async fn get(&self, origin: &str) -> Vec<Cookie> {
        let map = self.inner.read().await;
        map.get(origin).cloned().unwrap_or_default()
    }

    /// Remove all cookies for the given origin.
    pub async fn remove(&self, origin: &str) {
        let mut map = self.inner.write().await;
        map.remove(origin);
    }

    /// Return all stored origins.
    pub async fn origins(&self) -> Vec<String> {
        let map = self.inner.read().await;
        map.keys().cloned().collect()
    }

    /// Total number of stored cookies across all origins.
    pub async fn total_count(&self) -> usize {
        let map = self.inner.read().await;
        map.values().map(|v| v.len()).sum()
    }

    /// Build a `Cookie:` header value for the given origin.
    ///
    /// Returns `None` if no cookies are stored for this origin.
    pub async fn build_cookie_header(&self, origin: &str) -> Option<String> {
        let cookies = self.get(origin).await;
        if cookies.is_empty() {
            return None;
        }
        let header = cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");
        Some(header)
    }
}

// ---------------------------------------------------------------------------
// CookieManager
// ---------------------------------------------------------------------------

/// High-level API combining filtering, transformation, and storage.
pub struct CookieManager {
    store: CookieStore,
}

impl CookieManager {
    /// Create a new cookie manager backed by a fresh store.
    pub fn new() -> Self {
        Self {
            store: CookieStore::new(),
        }
    }

    /// Create a cookie manager backed by the provided shared store.
    pub fn with_store(store: CookieStore) -> Self {
        Self { store }
    }

    /// Filter and store cookies for the given origin in proxy-only mode.
    pub async fn store_proxy_only(
        &self,
        origin: impl Into<String>,
        cookies: Vec<Cookie>,
        filter: &CookieFilter,
    ) {
        let filtered = filter_cookies(cookies, filter);
        let transformed = transform_for_proxy_only(filtered);
        self.store.set(origin, transformed).await;
    }

    /// Filter, transform, and store cookies for scoped-snapshot mode.
    pub async fn store_scoped_snapshot(
        &self,
        origin: impl Into<String>,
        cookies: Vec<Cookie>,
        filter: &CookieFilter,
        allowed_domain: &str,
        max_age_seconds: u64,
    ) {
        let filtered = filter_cookies(cookies, filter);
        let transformed = transform_for_scoped_snapshot(filtered, allowed_domain, max_age_seconds);
        self.store.set(origin, transformed).await;
    }

    /// Access the underlying cookie store (for the MITM proxy to query).
    pub fn store(&self) -> &CookieStore {
        &self.store
    }
}

impl Default for CookieManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cookie(name: &str, value: &str) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: "Lax".to_string(),
            expires: None,
            max_age: None,
        }
    }

    #[test]
    fn test_filter_drops_tracking_cookies() {
        let cookies = vec![
            make_cookie("_ga", "GA1.2.123"),
            make_cookie("session_id", "abc123"),
            make_cookie("_gid", "GA1.2.456"),
            make_cookie("auth_token", "tok"),
        ];

        let filter = CookieFilter::default(); // drop_tracking = true
        let kept = filter_cookies(cookies, &filter);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|c| c.name == "session_id"));
        assert!(kept.iter().any(|c| c.name == "auth_token"));
        assert!(!kept.iter().any(|c| c.name == "_ga"));
        assert!(!kept.iter().any(|c| c.name == "_gid"));
    }

    #[test]
    fn test_filter_keep_tracking_when_disabled() {
        let cookies = vec![make_cookie("_ga", "GA1.2.123"), make_cookie("tok", "x")];
        let filter = CookieFilter::default().with_drop_tracking(false);
        let kept = filter_cookies(cookies, &filter);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn test_filter_keep_patterns() {
        let cookies = vec![
            make_cookie("session_id", "s"),
            make_cookie("auth_token", "a"),
            make_cookie("pref_lang", "en"),
        ];
        let filter = CookieFilter::new()
            .keep("^session_")
            .expect("valid pattern");
        let kept = filter_cookies(cookies, &filter);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "session_id");
    }

    #[test]
    fn test_filter_drop_patterns() {
        let cookies = vec![
            make_cookie("session_id", "s"),
            make_cookie("csrf_token", "c"),
            make_cookie("auth_token", "a"),
        ];
        let filter = CookieFilter::new()
            .drop_pattern("^csrf_")
            .expect("valid pattern");
        let kept = filter_cookies(cookies, &filter);
        assert_eq!(kept.len(), 2);
        assert!(!kept.iter().any(|c| c.name == "csrf_token"));
    }

    #[test]
    fn test_transform_for_proxy_only_unchanged() {
        let cookies = vec![make_cookie("session_id", "s")];
        let result = transform_for_proxy_only(cookies.clone());
        assert_eq!(result, cookies);
    }

    #[test]
    fn test_transform_for_scoped_snapshot() {
        let cookie = Cookie {
            name: "session_id".to_string(),
            value: "xyz".to_string(),
            domain: "auth.example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: true,
            same_site: "Strict".to_string(),
            expires: Some(9999999999),
            max_age: Some(86400),
        };

        let result = transform_for_scoped_snapshot(vec![cookie], "api.example.com", 3600);
        assert_eq!(result.len(), 1);
        let c = &result[0];
        assert!(!c.http_only, "HttpOnly should be stripped");
        assert_eq!(c.domain, "api.example.com", "domain should be restricted");
        assert_eq!(c.max_age, Some(3600), "max_age should be set");
        assert!(c.expires.is_none(), "expires should be cleared");
        assert!(c.secure, "Secure must be true");
    }

    #[tokio::test]
    async fn test_cookie_store_set_get() {
        let store = CookieStore::new();
        let cookies = vec![make_cookie("session_id", "abc")];
        store.set("https://example.com", cookies.clone()).await;

        let retrieved = store.get("https://example.com").await;
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].name, "session_id");
    }

    #[tokio::test]
    async fn test_cookie_store_get_missing_returns_empty() {
        let store = CookieStore::new();
        let result = store.get("https://notexist.com").await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_cookie_store_remove() {
        let store = CookieStore::new();
        store
            .set("https://example.com", vec![make_cookie("s", "x")])
            .await;
        store.remove("https://example.com").await;
        assert!(store.get("https://example.com").await.is_empty());
    }

    #[tokio::test]
    async fn test_cookie_store_build_header() {
        let store = CookieStore::new();
        store
            .set(
                "https://example.com",
                vec![
                    make_cookie("session_id", "abc"),
                    make_cookie("auth_token", "xyz"),
                ],
            )
            .await;

        let header = store
            .build_cookie_header("https://example.com")
            .await
            .expect("should have header");
        assert!(header.contains("session_id=abc"));
        assert!(header.contains("auth_token=xyz"));
        assert!(header.contains("; "));
    }

    #[tokio::test]
    async fn test_cookie_store_build_header_missing() {
        let store = CookieStore::new();
        let header = store.build_cookie_header("https://missing.com").await;
        assert!(header.is_none());
    }

    #[tokio::test]
    async fn test_cookie_store_total_count() {
        let store = CookieStore::new();
        store
            .set(
                "https://a.com",
                vec![make_cookie("s1", "v1"), make_cookie("s2", "v2")],
            )
            .await;
        store
            .set("https://b.com", vec![make_cookie("s3", "v3")])
            .await;
        assert_eq!(store.total_count().await, 3);
    }

    #[tokio::test]
    async fn test_cookie_manager_store_proxy_only() {
        let manager = CookieManager::new();
        let cookies = vec![
            make_cookie("_ga", "tracking"),
            make_cookie("session_id", "s"),
        ];
        let filter = CookieFilter::default();
        manager
            .store_proxy_only("https://example.com", cookies, &filter)
            .await;

        let stored = manager.store().get("https://example.com").await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "session_id");
    }

    #[tokio::test]
    async fn test_cookie_manager_store_scoped_snapshot() {
        let manager = CookieManager::new();
        let cookies = vec![make_cookie("session_id", "s")];
        let filter = CookieFilter::default();
        manager
            .store_scoped_snapshot(
                "https://example.com",
                cookies,
                &filter,
                "api.example.com",
                300,
            )
            .await;

        let stored = manager.store().get("https://example.com").await;
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].http_only);
        assert_eq!(stored[0].max_age, Some(300));
    }

    #[test]
    fn test_cookie_session_constructor() {
        let c = Cookie::session("tok", "val", "example.com");
        assert_eq!(c.name, "tok");
        assert_eq!(c.value, "val");
        assert_eq!(c.domain, "example.com");
        assert!(c.secure);
        assert!(c.http_only);
        assert!(c.expires.is_none());
        assert!(c.max_age.is_none());
    }

    #[test]
    fn test_filter_gcl_tracking_dropped() {
        let cookies = vec![
            make_cookie("_gcl_au", "tracking"),
            make_cookie("session", "s"),
        ];
        let filter = CookieFilter::default();
        let kept = filter_cookies(cookies, &filter);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "session");
    }
}
