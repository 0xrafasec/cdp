//! Core lease types: `LeaseId`, `LeaseStatus`, `Lease`, and scope utilities.

use std::{collections::HashMap, fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

use cdp_policy::{BodyConstraints, Scope};

// ---------------------------------------------------------------------------
// LeaseId
// ---------------------------------------------------------------------------

/// A cryptographically random, globally unique lease identifier.
///
/// Represented as a 64-character lowercase hex string encoding 32 bytes
/// (256 bits) of randomness generated from the OS entropy source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub String);

impl LeaseId {
    /// Generate a new random `LeaseId` using `OsRng`.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let hex = bytes.iter().fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        });
        Self(hex)
    }

    /// Return the inner hex string as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// LeaseStatus
// ---------------------------------------------------------------------------

/// The lifecycle state of a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseStatus {
    /// The lease is active and may be used.
    Active,
    /// The lease has passed its `expires_at` timestamp.
    Expired,
    /// The lease was explicitly revoked, with an operator-supplied reason.
    Revoked { reason: String },
}

// ---------------------------------------------------------------------------
// Lease
// ---------------------------------------------------------------------------

/// A granted credential lease.
///
/// A `Lease` is created by the CDP Gate after policy evaluation and approval.
/// It encodes the granted scope, authentication tokens, DNS pinning state,
/// and all lifecycle limits required by the protocol invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Unique identifier for this lease.
    pub lease_id: LeaseId,

    /// Opaque reference to the credential in the vault.
    pub credential_ref: String,

    /// Name of the policy rule that granted this lease.
    pub policy_name: String,

    /// Human-readable label for how the lease was approved
    /// (e.g. `"auto"`, `"user-approved"`).
    pub approval_method: String,

    // --- Agent identity ---
    /// Composite fingerprint hash of the requesting agent: `SHA-256(uid || pid || binary_hash || start_time)`.
    pub agent_fingerprint_hash: [u8; 32],

    /// Resolved path to the agent binary at registration time.
    pub agent_binary_path: String,

    /// Effective user ID from `SO_PEERCRED`.
    pub agent_uid: u32,

    /// Process ID from `SO_PEERCRED`.
    pub agent_pid: u32,

    // --- Granted scope ---
    /// The scope granted by the policy (intersection of requested and allowed).
    pub granted_scope: Scope,

    // --- Authentication ---
    /// HMAC-SHA256 lease token (hex-encoded) for per-request authentication.
    pub lease_token: String,

    /// Random 32-byte nonce for channel binding; must accompany each proxied request.
    pub channel_binding_nonce: [u8; 32],

    // --- DNS pinning ---
    /// IPs resolved at lease creation time, keyed by hostname.
    /// The proxy must only connect to these IPs for the lifetime of the lease.
    pub dns_pinned_ips: HashMap<String, Vec<IpAddr>>,

    // --- Lifecycle ---
    /// Current lifecycle state.
    pub status: LeaseStatus,

    /// When this lease was created (UTC).
    pub created_at: DateTime<Utc>,

    /// When this lease expires (UTC).
    pub expires_at: DateTime<Utc>,

    /// Requested TTL in seconds.
    pub ttl_seconds: u64,

    /// Cumulative TTL consumed across all renewals, in seconds.
    pub cumulative_ttl_seconds: u64,

    // --- Limits ---
    /// Maximum number of proxied requests permitted; `None` means unlimited.
    pub max_requests: Option<u64>,

    /// Number of proxied requests consumed so far.
    pub requests_used: u64,

    /// Number of times this lease has been renewed.
    pub renewals_used: u32,

    /// Maximum number of renewals permitted by the policy.
    pub max_renewals: u32,

    /// Maximum cumulative TTL in seconds (protocol invariant: ≤ 14 400s / 4h).
    pub max_cumulative_ttl_seconds: u64,

    /// Whether this lease may be renewed at all.
    pub renewable: bool,

    // --- Delegation ---
    /// Parent lease ID if this is a delegated (child) lease.
    pub parent_lease_id: Option<LeaseId>,

    /// IDs of child leases granted via delegation from this lease.
    pub child_lease_ids: Vec<LeaseId>,

    /// Delegation depth: 0 for root leases, increments for each sub-delegation.
    pub delegation_depth: u32,

    /// Whether the agent holding this lease may further delegate it.
    pub delegation_allowed: bool,

    /// Maximum delegation depth permitted by the policy; `None` means no delegation.
    pub delegation_max_depth: Option<u32>,

    // --- Network ---
    /// Whether the proxy may follow HTTP redirects on behalf of this lease.
    pub follow_redirects: bool,
}

impl Lease {
    /// Return `true` if the current wall-clock time is past `expires_at`.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Return `true` if the lease status is `Active` and it has not expired.
    pub fn is_active(&self) -> bool {
        self.status == LeaseStatus::Active && !self.is_expired()
    }

    /// Seconds remaining until expiry.  Negative when the lease is overdue.
    pub fn remaining_ttl_seconds(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds()
    }
}

// ---------------------------------------------------------------------------
// Scope utilities
// ---------------------------------------------------------------------------

/// Produce the intersection of two scopes.
///
/// Used to narrow a requested scope to what a policy actually permits.
/// Rules:
/// - `hosts`: intersection (only hosts present in both)
/// - `methods`: intersection
/// - `paths`: only paths from `requested` that are present in `granted`
/// - `forbidden_paths`: union (the forbidden set always grows)
/// - `ttl_seconds`: minimum of both, or the non-`None` side
/// - `max_requests`: minimum of both, or the non-`None` side
/// - `body_constraints`: merged (forbidden_fields union, max_size_bytes min,
///   allowed_content_types intersection)
/// - `network`: taken from `granted` (policy controls network constraints)
pub fn intersect_scopes(requested: &Scope, granted: &Scope) -> Scope {
    let hosts = intersect_vecs(&requested.hosts, &granted.hosts);
    let methods = intersect_vecs(&requested.methods, &granted.methods);
    let paths = intersect_vecs(&requested.paths, &granted.paths);

    let forbidden_paths = {
        let mut fp = requested.forbidden_paths.clone();
        for p in &granted.forbidden_paths {
            if !fp.contains(p) {
                fp.push(p.clone());
            }
        }
        fp
    };

    let ttl_seconds = min_option(requested.ttl_seconds, granted.ttl_seconds);
    let max_requests = min_option(requested.max_requests, granted.max_requests);

    let body_constraints = merge_body_constraints(
        requested.body_constraints.as_ref(),
        granted.body_constraints.as_ref(),
    );

    let network = granted.network.clone();

    Scope {
        hosts,
        methods,
        paths,
        forbidden_paths,
        ttl_seconds,
        max_requests,
        body_constraints,
        network,
    }
}

/// Return `true` if `child` is a valid subset of `parent` for delegation.
///
/// Every host, method, and path in the child must exist in the parent.
/// Every forbidden path declared by the parent must also appear in the child.
/// Numeric limits in the child must be ≤ those in the parent.
pub fn is_scope_subset(child: &Scope, parent: &Scope) -> bool {
    // Every host in child must be in parent.
    if !child.hosts.iter().all(|h| parent.hosts.contains(h)) {
        return false;
    }

    // Every method in child must be in parent.
    if !child.methods.iter().all(|m| parent.methods.contains(m)) {
        return false;
    }

    // Every path in child must be in parent.
    if !child.paths.iter().all(|p| parent.paths.contains(p)) {
        return false;
    }

    // Child must include every forbidden path from the parent.
    if !parent
        .forbidden_paths
        .iter()
        .all(|fp| child.forbidden_paths.contains(fp))
    {
        return false;
    }

    // Child TTL must be ≤ parent TTL (when both are specified).
    if let (Some(child_ttl), Some(parent_ttl)) = (child.ttl_seconds, parent.ttl_seconds)
        && child_ttl > parent_ttl
    {
        return false;
    }

    // Child max_requests must be ≤ parent max_requests (when both specified).
    if let (Some(child_req), Some(parent_req)) = (child.max_requests, parent.max_requests)
        && child_req > parent_req
    {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Intersection of two string vecs (order follows `a`).
fn intersect_vecs(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| b.contains(x)).cloned().collect()
}

/// Return the minimum of two `Option<u64>` values.
///
/// If one side is `None`, the other is returned (treat `None` as "no limit",
/// so the explicit limit wins).
fn min_option(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Merge two optional `BodyConstraints`:
/// - `forbidden_fields`: union
/// - `max_size_bytes`: minimum (treating `None` as "no limit")
/// - `allowed_content_types`: intersection (if either is empty, use the other)
fn merge_body_constraints(
    a: Option<&BodyConstraints>,
    b: Option<&BodyConstraints>,
) -> Option<BodyConstraints> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) => Some(x.clone()),
        (None, Some(y)) => Some(y.clone()),
        (Some(x), Some(y)) => {
            let mut forbidden_fields = x.forbidden_fields.clone();
            for f in &y.forbidden_fields {
                if !forbidden_fields.contains(f) {
                    forbidden_fields.push(f.clone());
                }
            }

            let max_size_bytes = min_option(x.max_size_bytes, y.max_size_bytes);

            let allowed_content_types = if x.allowed_content_types.is_empty() {
                y.allowed_content_types.clone()
            } else if y.allowed_content_types.is_empty() {
                x.allowed_content_types.clone()
            } else {
                intersect_vecs(&x.allowed_content_types, &y.allowed_content_types)
            };

            Some(BodyConstraints {
                forbidden_fields,
                max_size_bytes,
                allowed_content_types,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_lease(expires_at: DateTime<Utc>) -> Lease {
        Lease {
            lease_id: LeaseId::generate(),
            credential_ref: "cred-001".to_string(),
            policy_name: "test-policy".to_string(),
            approval_method: "auto".to_string(),
            agent_fingerprint_hash: [0u8; 32],
            agent_binary_path: "/usr/bin/agent".to_string(),
            agent_uid: 1000,
            agent_pid: 42,
            granted_scope: Scope::default(),
            lease_token: "deadbeef".to_string(),
            channel_binding_nonce: [0u8; 32],
            dns_pinned_ips: HashMap::new(),
            status: LeaseStatus::Active,
            created_at: Utc::now(),
            expires_at,
            ttl_seconds: 3600,
            cumulative_ttl_seconds: 3600,
            max_requests: None,
            requests_used: 0,
            renewals_used: 0,
            max_renewals: 3,
            max_cumulative_ttl_seconds: 14400,
            renewable: true,
            parent_lease_id: None,
            child_lease_ids: Vec::new(),
            delegation_depth: 0,
            delegation_allowed: false,
            delegation_max_depth: None,
            follow_redirects: false,
        }
    }

    #[test]
    fn test_lease_id_generate_is_64_hex_chars() {
        let id = LeaseId::generate();
        assert_eq!(id.as_str().len(), 64);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_lease_id_generate_is_unique() {
        let a = LeaseId::generate();
        let b = LeaseId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn test_lease_is_expired() {
        let past = Utc::now() - Duration::seconds(10);
        let lease = make_lease(past);
        assert!(lease.is_expired());
        assert!(!lease.is_active());
    }

    #[test]
    fn test_lease_is_active() {
        let future = Utc::now() + Duration::seconds(3600);
        let lease = make_lease(future);
        assert!(!lease.is_expired());
        assert!(lease.is_active());
    }

    #[test]
    fn test_intersect_scopes_hosts() {
        let requested = Scope {
            hosts: vec!["a.example.com".to_string(), "b.example.com".to_string()],
            ..Default::default()
        };
        let granted = Scope {
            hosts: vec!["b.example.com".to_string(), "c.example.com".to_string()],
            ..Default::default()
        };
        let result = intersect_scopes(&requested, &granted);
        assert_eq!(result.hosts, vec!["b.example.com"]);
    }

    #[test]
    fn test_intersect_scopes_methods() {
        let requested = Scope {
            methods: vec!["GET".to_string(), "POST".to_string(), "DELETE".to_string()],
            ..Default::default()
        };
        let granted = Scope {
            methods: vec!["GET".to_string(), "POST".to_string()],
            ..Default::default()
        };
        let result = intersect_scopes(&requested, &granted);
        assert_eq!(result.methods, vec!["GET", "POST"]);
    }

    #[test]
    fn test_intersect_scopes_forbidden_paths_union() {
        let requested = Scope {
            forbidden_paths: vec!["/admin".to_string()],
            ..Default::default()
        };
        let granted = Scope {
            forbidden_paths: vec!["/internal".to_string()],
            ..Default::default()
        };
        let result = intersect_scopes(&requested, &granted);
        assert!(result.forbidden_paths.contains(&"/admin".to_string()));
        assert!(result.forbidden_paths.contains(&"/internal".to_string()));
        assert_eq!(result.forbidden_paths.len(), 2);
    }

    #[test]
    fn test_intersect_scopes_ttl_min() {
        let requested = Scope {
            ttl_seconds: Some(7200),
            ..Default::default()
        };
        let granted = Scope {
            ttl_seconds: Some(3600),
            ..Default::default()
        };
        let result = intersect_scopes(&requested, &granted);
        assert_eq!(result.ttl_seconds, Some(3600));
    }

    #[test]
    fn test_is_scope_subset_valid() {
        let parent = Scope {
            hosts: vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
            methods: vec!["GET".to_string(), "POST".to_string()],
            paths: vec!["/api/v1/".to_string(), "/api/v2/".to_string()],
            forbidden_paths: vec!["/api/v1/admin".to_string()],
            ..Default::default()
        };
        let child = Scope {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/api/v1/".to_string()],
            forbidden_paths: vec!["/api/v1/admin".to_string()],
            ..Default::default()
        };
        assert!(is_scope_subset(&child, &parent));
    }

    #[test]
    fn test_is_scope_subset_extra_host_fails() {
        let parent = Scope {
            hosts: vec!["api.example.com".to_string()],
            ..Default::default()
        };
        let child = Scope {
            hosts: vec![
                "api.example.com".to_string(),
                "evil.example.com".to_string(),
            ],
            ..Default::default()
        };
        assert!(!is_scope_subset(&child, &parent));
    }

    #[test]
    fn test_is_scope_subset_missing_forbidden_path_fails() {
        let parent = Scope {
            hosts: vec!["api.example.com".to_string()],
            forbidden_paths: vec!["/api/admin".to_string()],
            ..Default::default()
        };
        // Child does not include parent's forbidden path.
        let child = Scope {
            hosts: vec!["api.example.com".to_string()],
            forbidden_paths: vec![],
            ..Default::default()
        };
        assert!(!is_scope_subset(&child, &parent));
    }
}
