//! Policy evaluation engine for CDP credential delegation.
//!
//! The evaluator applies a three-tier priority scheme to match an incoming
//! credential request against the loaded policy set:
//!
//! 1. **Binary hash** — cryptographic, strongest signal.
//! 2. **Binary path** — filesystem path, weaker but useful for dev workflows.
//! 3. **Agent ID** — self-declared by the agent; lowest trust tier.
//!
//! Within each tier the first matching entry wins; no cross-policy merging.

use crate::{
    glob::any_glob_matches,
    parser::{PolicyAllow, PolicyDelegation, PolicyEntry},
    types::{AgentInfo, BodyConstraints, PolicyConstraints, PolicyDecision, Scope},
};

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compares two byte slices in constant time with respect to their content.
///
/// Returns `false` immediately if lengths differ (length is not secret).
/// Uses bitwise OR of XOR differences so the comparison time is independent
/// of where the first differing byte is, preventing timing side-channels.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// PolicyEvaluator
// ---------------------------------------------------------------------------

/// Evaluates credential-access requests against a set of loaded policy rules.
///
/// The evaluator is immutable after construction; use [`PolicyEvaluator::reload`]
/// to atomically swap in a new policy set (e.g. after inotify triggers).
pub struct PolicyEvaluator {
    policies: Vec<PolicyEntry>,
}

impl PolicyEvaluator {
    /// Creates a new evaluator with the given policy set.
    pub fn new(policies: Vec<PolicyEntry>) -> Self {
        Self { policies }
    }

    /// Replaces the loaded policy set in-place.
    ///
    /// Callers that need atomic policy reloads across async tasks should wrap
    /// the evaluator in an `Arc<RwLock<PolicyEvaluator>>`.
    pub fn reload(&mut self, policies: Vec<PolicyEntry>) {
        self.policies = policies;
    }

    /// Returns the number of loaded policy entries.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Evaluates a credential-access request.
    ///
    /// The three-pass priority order is:
    /// 1. Binary hash match (cryptographic identity, strongest).
    /// 2. Binary path match (filesystem path, medium trust).
    /// 3. Agent ID match (self-declared, lowest trust).
    ///
    /// Within each pass, the **first** matching policy wins. If no policy
    /// matches at any tier, `PolicyDecision::Denied` is returned.
    pub fn evaluate(
        &self,
        agent: &AgentInfo,
        credential_ref: &str,
        requested_scope: &Scope,
    ) -> PolicyDecision {
        // Pass 1: binary hash match.
        if let Some(entry) = self.find_by_binary_hash(agent, credential_ref) {
            return self.build_decision(entry, requested_scope);
        }

        // Pass 2: binary path match.
        if let Some(entry) = self.find_by_binary_path(agent, credential_ref) {
            return self.build_decision(entry, requested_scope);
        }

        // Pass 3: agent ID match.
        if let Some(entry) = self.find_by_agent_id(agent, credential_ref) {
            return self.build_decision(entry, requested_scope);
        }

        PolicyDecision::Denied {
            reason: "no matching policy".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Pass helpers
    // -----------------------------------------------------------------------

    /// Pass 1: find the first policy whose `agent_binary_hash` is set and
    /// matches the agent's binary hash using a constant-time comparison.
    fn find_by_binary_hash<'a>(
        &'a self,
        agent: &AgentInfo,
        credential_ref: &str,
    ) -> Option<&'a PolicyEntry> {
        self.policies.iter().find(|entry| {
            if !credential_ref_matches(&entry.match_block.credential_ref, credential_ref) {
                return false;
            }
            match &entry.match_block.agent_binary_hash {
                None => false,
                Some(raw_hash) => match crate::parser::parse_binary_hash(raw_hash) {
                    Err(_) => false, // malformed policy hash — skip silently
                    Ok(policy_hash) => constant_time_eq(&policy_hash, &agent.binary_hash),
                },
            }
        })
    }

    /// Pass 2: find the first policy whose `agent_binary_path` is set and
    /// matches the agent's resolved binary path (exact string comparison).
    fn find_by_binary_path<'a>(
        &'a self,
        agent: &AgentInfo,
        credential_ref: &str,
    ) -> Option<&'a PolicyEntry> {
        let agent_path = agent.binary_path.to_string_lossy();
        self.policies.iter().find(|entry| {
            if !credential_ref_matches(&entry.match_block.credential_ref, credential_ref) {
                return false;
            }
            match &entry.match_block.agent_binary_path {
                None => false,
                Some(policy_path) => policy_path.as_str() == agent_path.as_ref(),
            }
        })
    }

    /// Pass 3: find the first policy whose `agent_id` is set and matches the
    /// agent's self-declared agent_id (exact string comparison).
    fn find_by_agent_id<'a>(
        &'a self,
        agent: &AgentInfo,
        credential_ref: &str,
    ) -> Option<&'a PolicyEntry> {
        self.policies.iter().find(|entry| {
            if !credential_ref_matches(&entry.match_block.credential_ref, credential_ref) {
                return false;
            }
            match (&entry.match_block.agent_id, &agent.agent_id) {
                (Some(policy_id), Some(agent_id)) => policy_id == agent_id,
                _ => false,
            }
        })
    }

    // -----------------------------------------------------------------------
    // Decision construction
    // -----------------------------------------------------------------------

    fn build_decision(&self, entry: &PolicyEntry, requested_scope: &Scope) -> PolicyDecision {
        match intersect_scope(requested_scope, &entry.allow) {
            None => PolicyDecision::Denied {
                reason: "scope intersection is empty".to_string(),
            },
            Some(granted_scope) => {
                let constraints = build_constraints(&entry.allow, &entry.delegation);
                let policy_name = entry.name.clone();
                match entry.approval.mode.as_str() {
                    "auto" => PolicyDecision::AutoApprove {
                        granted_scope,
                        policy_name,
                        constraints,
                    },
                    _ => PolicyDecision::RequiresApproval {
                        granted_scope,
                        policy_name,
                        constraints,
                    },
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Credential-ref matching
// ---------------------------------------------------------------------------

/// Returns `true` if the policy's `credential_ref` matches the requested
/// credential reference.
///
/// `"*"` is a wildcard that matches any non-empty credential reference.
#[inline]
fn credential_ref_matches(policy_ref: &str, requested_ref: &str) -> bool {
    policy_ref == "*" || policy_ref == requested_ref
}

// ---------------------------------------------------------------------------
// Scope intersection
// ---------------------------------------------------------------------------

/// Computes the intersection of a *requested* scope and the *allowed* scope
/// from a policy entry.
///
/// Returns `None` when the intersection is empty (i.e., nothing can be
/// granted), which causes the caller to emit a `Denied` decision.
fn intersect_scope(requested: &Scope, allowed: &PolicyAllow) -> Option<Scope> {
    // --- Hosts ---
    let granted_hosts = if allowed.hosts.is_empty() {
        // Policy imposes no host restriction — all requested hosts are allowed.
        requested.hosts.clone()
    } else if requested.hosts.is_empty() {
        // Agent did not restrict hosts; grant everything the policy allows.
        allowed.hosts.clone()
    } else {
        // Both sides named hosts; take the intersection.
        let intersection: Vec<String> = requested
            .hosts
            .iter()
            .filter(|h| allowed.hosts.contains(h))
            .cloned()
            .collect();
        // Empty intersection when both sides had explicit entries → deny.
        if intersection.is_empty() {
            return None;
        }
        intersection
    };

    // --- Methods ---
    let granted_methods = if allowed.methods.is_empty() {
        requested.methods.clone()
    } else if requested.methods.is_empty() {
        allowed.methods.clone()
    } else {
        let intersection: Vec<String> = requested
            .methods
            .iter()
            .filter(|m| allowed.methods.contains(m))
            .cloned()
            .collect();
        if intersection.is_empty() {
            return None;
        }
        intersection
    };

    // --- Paths ---
    // For each requested path, check whether it satisfies at least one
    // allowed-path glob pattern.  If allowed.paths is empty, all requested
    // paths pass.
    let mut granted_paths: Vec<String> = if allowed.paths.is_empty() {
        requested.paths.clone()
    } else {
        requested
            .paths
            .iter()
            .filter(|p| any_glob_matches(p, &allowed.paths))
            .cloned()
            .collect()
    };

    // --- Forbidden paths ---
    // Union of policy forbidden paths and requested forbidden paths (deduplicated).
    let mut all_forbidden = allowed.forbidden_paths.clone();
    for fp in &requested.forbidden_paths {
        if !all_forbidden.contains(fp) {
            all_forbidden.push(fp.clone());
        }
    }
    // Remove any granted path that matches a forbidden glob.
    if !all_forbidden.is_empty() {
        granted_paths.retain(|p| !any_glob_matches(p, &all_forbidden));
    }

    // --- TTL ---
    let ttl_seconds = min_option(requested.ttl_seconds, allowed.max_ttl_seconds);

    // --- Max requests ---
    let max_requests = min_option(requested.max_requests, allowed.max_requests_per_lease);

    // --- Body constraints ---
    let body_constraints = merge_body_constraints(
        requested.body_constraints.as_ref(),
        allowed.body_constraints.as_ref(),
    );

    // --- Network constraints ---
    // Policy always wins; fall back to requested constraints if policy has none.
    let network = allowed
        .network
        .clone()
        .or_else(|| requested.network.clone());

    Some(Scope {
        hosts: granted_hosts,
        methods: granted_methods,
        paths: granted_paths,
        forbidden_paths: all_forbidden,
        ttl_seconds,
        max_requests,
        body_constraints,
        network,
    })
}

/// Returns the minimum of two `Option<u64>` values.
///
/// - `(Some(a), Some(b))` → `Some(min(a, b))`
/// - `(Some(x), None)` or `(None, Some(x))` → `Some(x)` (the constraint that
///   exists is used; absence means "no limit").
/// - `(None, None)` → `None`
#[inline]
fn min_option(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// Merges requested and policy body constraints.
///
/// - `forbidden_fields`: union of both sides (deduplicated).
/// - `max_size_bytes`: minimum of both (most restrictive wins).
/// - `allowed_content_types`: if the policy specifies types, policy wins;
///   otherwise the requested list is used.
/// - If *neither* side has body constraints, returns `None`.
fn merge_body_constraints(
    requested: Option<&BodyConstraints>,
    policy: Option<&BodyConstraints>,
) -> Option<BodyConstraints> {
    match (requested, policy) {
        (None, None) => None,
        (Some(r), None) => Some(r.clone()),
        (None, Some(p)) => Some(p.clone()),
        (Some(r), Some(p)) => {
            // Union of forbidden fields.
            let mut forbidden_fields = r.forbidden_fields.clone();
            for field in &p.forbidden_fields {
                if !forbidden_fields.contains(field) {
                    forbidden_fields.push(field.clone());
                }
            }

            // Most restrictive size limit.
            let max_size_bytes = match (r.max_size_bytes, p.max_size_bytes) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(x), None) | (None, Some(x)) => Some(x),
                (None, None) => None,
            };

            // Policy-wins for content types; fall back to requested.
            let allowed_content_types = if !p.allowed_content_types.is_empty() {
                p.allowed_content_types.clone()
            } else {
                r.allowed_content_types.clone()
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
// PolicyConstraints construction
// ---------------------------------------------------------------------------

/// Builds a [`PolicyConstraints`] value from the allow and delegation blocks
/// of a matched policy entry.
fn build_constraints(allow: &PolicyAllow, delegation: &PolicyDelegation) -> PolicyConstraints {
    PolicyConstraints {
        max_ttl_seconds: allow.max_ttl_seconds,
        max_requests_per_lease: allow.max_requests_per_lease,
        max_renewals: allow.max_renewals,
        max_cumulative_ttl_seconds: allow.max_cumulative_ttl_seconds,
        renewable: allow.renewable,
        delegation_allowed: delegation.allowed,
        delegation_max_depth: delegation.max_depth,
        delegation_require_approval: delegation.require_approval_for_delegate,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        parser::{PolicyApproval, PolicyDelegation, PolicyEntry, PolicyMatch},
        types::{AgentInfo, BodyConstraints, NetworkConstraints, Scope},
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_agent(binary_path: &str, binary_hash: [u8; 32], agent_id: Option<&str>) -> AgentInfo {
        AgentInfo {
            uid: 1000,
            pid: 42,
            binary_path: PathBuf::from(binary_path),
            binary_hash,
            start_time: 1_000_000,
            fingerprint_hash: [0xef; 32],
            agent_id: agent_id.map(str::to_string),
            agent_version: None,
        }
    }

    fn hash_of(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Encode bytes as lowercase hex without an external crate.
    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn hash_str(b: u8) -> String {
        format!("sha256:{}", hex_encode(&[b; 32]))
    }

    fn make_allow(hosts: Vec<&str>, methods: Vec<&str>, paths: Vec<&str>) -> PolicyAllow {
        PolicyAllow {
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            forbidden_paths: vec![],
            max_ttl_seconds: None,
            max_requests_per_lease: None,
            max_renewals: None,
            max_cumulative_ttl_seconds: None,
            renewable: true,
            body_constraints: None,
            network: None,
        }
    }

    fn make_entry(
        name: &str,
        binary_hash: Option<[u8; 32]>,
        binary_path: Option<&str>,
        agent_id: Option<&str>,
        credential_ref: &str,
        approval_mode: &str,
        hosts: Vec<&str>,
        methods: Vec<&str>,
        paths: Vec<&str>,
    ) -> PolicyEntry {
        PolicyEntry {
            name: name.to_string(),
            description: String::new(),
            match_block: PolicyMatch {
                agent_binary_hash: binary_hash.map(|h| hash_str(h[0])),
                agent_binary_path: binary_path.map(str::to_string),
                agent_id: agent_id.map(str::to_string),
                credential_ref: credential_ref.to_string(),
            },
            allow: make_allow(hosts, methods, paths),
            approval: PolicyApproval {
                mode: approval_mode.to_string(),
            },
            delegation: PolicyDelegation {
                allowed: false,
                max_depth: None,
                require_approval_for_delegate: false,
            },
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: binary hash match takes priority over binary path match
    // -----------------------------------------------------------------------
    #[test]
    fn binary_hash_beats_binary_path() {
        let hash_a = hash_of(0xaa);
        let hash_b = hash_of(0xbb);

        let path_entry = make_entry(
            "path-policy",
            None,
            Some("/usr/bin/agent"),
            None,
            "cred",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let hash_entry = make_entry(
            "hash-policy",
            Some(hash_a),
            None,
            None,
            "cred",
            "auto",
            vec![],
            vec![],
            vec![],
        );

        let evaluator = PolicyEvaluator::new(vec![path_entry, hash_entry]);
        let agent = make_agent("/usr/bin/agent", hash_a, None);
        let decision = evaluator.evaluate(&agent, "cred", &Scope::default());

        match decision {
            PolicyDecision::AutoApprove { policy_name, .. } => {
                assert_eq!(
                    policy_name, "hash-policy",
                    "hash tier should win over path tier"
                );
            }
            other => panic!("expected AutoApprove, got {:?}", other),
        }

        // Sanity: agent with different hash but matching path → path-policy.
        let agent2 = make_agent("/usr/bin/agent", hash_b, None);
        let decision2 = evaluator.evaluate(&agent2, "cred", &Scope::default());
        match decision2 {
            PolicyDecision::AutoApprove { policy_name, .. } => {
                assert_eq!(policy_name, "path-policy");
            }
            other => panic!("expected AutoApprove, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: binary path match takes priority over agent_id match
    // -----------------------------------------------------------------------
    #[test]
    fn binary_path_beats_agent_id() {
        let id_entry = make_entry(
            "id-policy",
            None,
            None,
            Some("my-agent"),
            "cred",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let path_entry = make_entry(
            "path-policy",
            None,
            Some("/usr/bin/agent"),
            None,
            "cred",
            "auto",
            vec![],
            vec![],
            vec![],
        );

        let evaluator = PolicyEvaluator::new(vec![id_entry, path_entry]);
        let agent = make_agent("/usr/bin/agent", [0u8; 32], Some("my-agent"));
        let decision = evaluator.evaluate(&agent, "cred", &Scope::default());

        match decision {
            PolicyDecision::AutoApprove { policy_name, .. } => {
                assert_eq!(
                    policy_name, "path-policy",
                    "path tier should win over id tier"
                );
            }
            other => panic!("expected AutoApprove, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: no match returns Denied
    // -----------------------------------------------------------------------
    #[test]
    fn no_match_returns_denied() {
        let entry = make_entry(
            "p1",
            Some(hash_of(0xcc)),
            None,
            None,
            "cred",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let evaluator = PolicyEvaluator::new(vec![entry]);
        let agent = make_agent("/bin/other", hash_of(0xdd), None);
        let decision = evaluator.evaluate(&agent, "cred", &Scope::default());
        assert!(matches!(decision, PolicyDecision::Denied { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 4: credential_ref exact match works
    // -----------------------------------------------------------------------
    #[test]
    fn credential_ref_exact_match() {
        let entry = make_entry(
            "p1",
            Some(hash_of(0x01)),
            None,
            None,
            "github-token",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let evaluator = PolicyEvaluator::new(vec![entry]);
        let agent = make_agent("/bin/agent", hash_of(0x01), None);

        // Correct credential_ref → match.
        assert!(matches!(
            evaluator.evaluate(&agent, "github-token", &Scope::default()),
            PolicyDecision::AutoApprove { .. }
        ));

        // Wrong credential_ref → no match.
        assert!(matches!(
            evaluator.evaluate(&agent, "other-token", &Scope::default()),
            PolicyDecision::Denied { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Test 5: credential_ref wildcard "*" matches any credential
    // -----------------------------------------------------------------------
    #[test]
    fn credential_ref_wildcard_matches_any() {
        let entry = make_entry(
            "wildcard-policy",
            Some(hash_of(0x02)),
            None,
            None,
            "*",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let evaluator = PolicyEvaluator::new(vec![entry]);
        let agent = make_agent("/bin/agent", hash_of(0x02), None);

        for cred in &["github-token", "aws-key", "anything"] {
            assert!(
                matches!(
                    evaluator.evaluate(&agent, cred, &Scope::default()),
                    PolicyDecision::AutoApprove { .. }
                ),
                "wildcard should match credential '{}'",
                cred
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: scope intersection — hosts (both non-empty)
    // -----------------------------------------------------------------------
    #[test]
    fn scope_intersection_hosts_both_nonempty() {
        let mut allow = make_allow(vec!["api.example.com", "cdn.example.com"], vec![], vec![]);
        allow.hosts = vec!["api.example.com".to_string(), "cdn.example.com".to_string()];

        let requested = Scope {
            hosts: vec![
                "api.example.com".to_string(),
                "other.example.com".to_string(),
            ],
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).expect("should not be empty");
        assert_eq!(result.hosts, vec!["api.example.com"]);
    }

    // -----------------------------------------------------------------------
    // Test 7: scope intersection — empty allowed hosts means allow all
    // -----------------------------------------------------------------------
    #[test]
    fn scope_intersection_empty_allowed_hosts_passes_all() {
        let allow = make_allow(vec![], vec![], vec![]);
        let requested = Scope {
            hosts: vec!["anything.io".to_string(), "other.io".to_string()],
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).expect("should produce scope");
        assert_eq!(result.hosts, vec!["anything.io", "other.io"]);
    }

    // -----------------------------------------------------------------------
    // Test 8: scope intersection — methods intersection
    // -----------------------------------------------------------------------
    #[test]
    fn scope_intersection_methods() {
        let allow = make_allow(vec![], vec!["GET", "HEAD"], vec![]);
        let requested = Scope {
            methods: vec!["GET".to_string(), "POST".to_string()],
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).expect("should produce scope");
        assert_eq!(result.methods, vec!["GET"]);
    }

    // -----------------------------------------------------------------------
    // Test 9: scope intersection — paths filtered by allowed globs
    // -----------------------------------------------------------------------
    #[test]
    fn scope_intersection_paths_filtered_by_globs() {
        let allow = make_allow(vec![], vec![], vec!["/api/**"]);
        let requested = Scope {
            paths: vec![
                "/api/v1/users".to_string(),
                "/admin/settings".to_string(),
                "/api/v2/repos".to_string(),
            ],
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).expect("should produce scope");
        assert!(result.paths.contains(&"/api/v1/users".to_string()));
        assert!(result.paths.contains(&"/api/v2/repos".to_string()));
        assert!(!result.paths.contains(&"/admin/settings".to_string()));
    }

    // -----------------------------------------------------------------------
    // Test 10: forbidden_paths removes matching paths from granted scope
    // -----------------------------------------------------------------------
    #[test]
    fn forbidden_paths_removes_matching_granted_paths() {
        let mut allow = make_allow(vec![], vec![], vec!["/api/**"]);
        allow.forbidden_paths = vec!["/api/admin/**".to_string()];

        let requested = Scope {
            paths: vec![
                "/api/v1/users".to_string(),
                "/api/admin/secrets".to_string(),
            ],
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).expect("should produce scope");
        assert!(result.paths.contains(&"/api/v1/users".to_string()));
        assert!(!result.paths.contains(&"/api/admin/secrets".to_string()));
    }

    // -----------------------------------------------------------------------
    // Test 11: forbidden_paths from policy and requested are unioned
    // -----------------------------------------------------------------------
    #[test]
    fn forbidden_paths_union_from_policy_and_requested() {
        let mut allow = make_allow(vec![], vec![], vec![]);
        allow.forbidden_paths = vec!["/api/internal/**".to_string()];

        let requested = Scope {
            paths: vec![
                "/api/v1".to_string(),
                "/api/internal/debug".to_string(),
                "/api/secret/key".to_string(),
            ],
            forbidden_paths: vec!["/api/secret/**".to_string()],
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).expect("should produce scope");

        // Both forbidden patterns should be in the result's forbidden list.
        assert!(
            result
                .forbidden_paths
                .contains(&"/api/internal/**".to_string())
        );
        assert!(
            result
                .forbidden_paths
                .contains(&"/api/secret/**".to_string())
        );

        // Paths matching either forbidden pattern must be excluded.
        assert!(result.paths.contains(&"/api/v1".to_string()));
        assert!(!result.paths.contains(&"/api/internal/debug".to_string()));
        assert!(!result.paths.contains(&"/api/secret/key".to_string()));
    }

    // -----------------------------------------------------------------------
    // Test 12: TTL is min of requested and allowed
    // -----------------------------------------------------------------------
    #[test]
    fn ttl_is_minimum() {
        let mut allow = make_allow(vec![], vec![], vec![]);
        allow.max_ttl_seconds = Some(3600);

        // Requested > allowed → capped to allowed.
        let requested_high = Scope {
            ttl_seconds: Some(7200),
            ..Default::default()
        };
        let r = intersect_scope(&requested_high, &allow).unwrap();
        assert_eq!(r.ttl_seconds, Some(3600));

        // Requested < allowed → use requested.
        let requested_low = Scope {
            ttl_seconds: Some(900),
            ..Default::default()
        };
        let r = intersect_scope(&requested_low, &allow).unwrap();
        assert_eq!(r.ttl_seconds, Some(900));

        // Only allowed has TTL.
        let r = intersect_scope(&Scope::default(), &allow).unwrap();
        assert_eq!(r.ttl_seconds, Some(3600));

        // Only requested has TTL.
        allow.max_ttl_seconds = None;
        let r = intersect_scope(&requested_high, &allow).unwrap();
        assert_eq!(r.ttl_seconds, Some(7200));
    }

    // -----------------------------------------------------------------------
    // Test 13: max_requests is min of requested and allowed
    // -----------------------------------------------------------------------
    #[test]
    fn max_requests_is_minimum() {
        let mut allow = make_allow(vec![], vec![], vec![]);
        allow.max_requests_per_lease = Some(100);

        let requested_high = Scope {
            max_requests: Some(500),
            ..Default::default()
        };
        let r = intersect_scope(&requested_high, &allow).unwrap();
        assert_eq!(r.max_requests, Some(100));

        let requested_low = Scope {
            max_requests: Some(50),
            ..Default::default()
        };
        let r = intersect_scope(&requested_low, &allow).unwrap();
        assert_eq!(r.max_requests, Some(50));
    }

    // -----------------------------------------------------------------------
    // Test 14: auto-approve policy produces AutoApprove decision
    // -----------------------------------------------------------------------
    #[test]
    fn auto_approve_policy_produces_auto_approve() {
        let entry = make_entry(
            "auto-pol",
            Some(hash_of(0x10)),
            None,
            None,
            "*",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let evaluator = PolicyEvaluator::new(vec![entry]);
        let agent = make_agent("/bin/agent", hash_of(0x10), None);
        let decision = evaluator.evaluate(&agent, "cred", &Scope::default());
        assert!(matches!(decision, PolicyDecision::AutoApprove { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 15: prompt policy produces RequiresApproval decision
    // -----------------------------------------------------------------------
    #[test]
    fn prompt_policy_produces_requires_approval() {
        let entry = make_entry(
            "prompt-pol",
            Some(hash_of(0x11)),
            None,
            None,
            "*",
            "prompt",
            vec![],
            vec![],
            vec![],
        );
        let evaluator = PolicyEvaluator::new(vec![entry]);
        let agent = make_agent("/bin/agent", hash_of(0x11), None);
        let decision = evaluator.evaluate(&agent, "cred", &Scope::default());
        assert!(matches!(decision, PolicyDecision::RequiresApproval { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 16: empty scope intersection returns Denied
    // -----------------------------------------------------------------------
    #[test]
    fn empty_scope_intersection_returns_denied() {
        // Policy allows only GET; agent requests only POST.
        let entry = make_entry(
            "narrow",
            Some(hash_of(0x20)),
            None,
            None,
            "*",
            "auto",
            vec![],
            vec!["GET"],
            vec![],
        );
        // make_entry already sets methods from the parameter above.
        let _ = entry.allow.methods.len(); // no-op, just confirming it's set

        let evaluator = PolicyEvaluator::new(vec![entry]);
        let agent = make_agent("/bin/agent", hash_of(0x20), None);
        let requested = Scope {
            methods: vec!["POST".to_string()],
            ..Default::default()
        };
        let decision = evaluator.evaluate(&agent, "cred", &requested);
        match decision {
            PolicyDecision::Denied { reason } => {
                assert!(
                    reason.contains("scope intersection is empty"),
                    "got: {}",
                    reason
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Test 17: constant-time comparison works correctly
    // -----------------------------------------------------------------------
    #[test]
    fn constant_time_eq_correct() {
        let a = [0xabu8; 32];
        let b = [0xabu8; 32];
        let c = [0xcdu8; 32];
        let mut d = [0xabu8; 32];
        d[31] = 0x00; // last byte differs

        assert!(constant_time_eq(&a, &b), "identical arrays must be equal");
        assert!(
            !constant_time_eq(&a, &c),
            "different arrays must not be equal"
        );
        assert!(!constant_time_eq(&a, &d), "off-by-one must not be equal");
        assert!(
            !constant_time_eq(&a, &a[..16]),
            "different lengths must not be equal"
        );
        assert!(constant_time_eq(&[], &[]), "empty slices are equal");
    }

    // -----------------------------------------------------------------------
    // Test 18: body constraints merge works
    // -----------------------------------------------------------------------
    #[test]
    fn body_constraints_merge_test() {
        let requested_bc = BodyConstraints {
            forbidden_fields: vec!["password".to_string()],
            max_size_bytes: Some(65536),
            allowed_content_types: vec!["application/json".to_string()],
        };
        let policy_bc = BodyConstraints {
            forbidden_fields: vec!["secret".to_string(), "password".to_string()],
            max_size_bytes: Some(32768),
            allowed_content_types: vec!["application/json".to_string(), "text/plain".to_string()],
        };

        let merged = merge_body_constraints(Some(&requested_bc), Some(&policy_bc))
            .expect("merge should produce Some");

        // Union of forbidden fields (no duplicates).
        assert!(merged.forbidden_fields.contains(&"password".to_string()));
        assert!(merged.forbidden_fields.contains(&"secret".to_string()));
        assert_eq!(
            merged
                .forbidden_fields
                .iter()
                .filter(|f| *f == "password")
                .count(),
            1,
            "duplicates should be removed"
        );

        // Min of max_size_bytes.
        assert_eq!(merged.max_size_bytes, Some(32768));

        // Policy's content types win when non-empty.
        assert!(
            merged
                .allowed_content_types
                .contains(&"text/plain".to_string())
        );
    }

    #[test]
    fn body_constraints_merge_none_none_is_none() {
        assert!(merge_body_constraints(None, None).is_none());
    }

    #[test]
    fn body_constraints_merge_only_requested() {
        let requested_bc = BodyConstraints {
            forbidden_fields: vec!["token".to_string()],
            max_size_bytes: None,
            allowed_content_types: vec![],
        };
        let result = merge_body_constraints(Some(&requested_bc), None).unwrap();
        assert_eq!(result.forbidden_fields, vec!["token"]);
    }

    #[test]
    fn body_constraints_requested_content_types_used_when_policy_is_empty() {
        let requested_bc = BodyConstraints {
            forbidden_fields: vec![],
            max_size_bytes: None,
            allowed_content_types: vec!["application/json".to_string()],
        };
        let policy_bc = BodyConstraints {
            forbidden_fields: vec![],
            max_size_bytes: None,
            allowed_content_types: vec![], // policy doesn't restrict
        };
        let merged = merge_body_constraints(Some(&requested_bc), Some(&policy_bc)).unwrap();
        assert_eq!(merged.allowed_content_types, vec!["application/json"]);
    }

    // -----------------------------------------------------------------------
    // Test 19: network constraints — policy always wins
    // -----------------------------------------------------------------------
    #[test]
    fn network_constraints_policy_wins() {
        let mut allow = make_allow(vec![], vec![], vec![]);
        allow.network = Some(NetworkConstraints {
            follow_redirects: false,
            dns_resolution: "pinned".to_string(),
            allowed_ip_ranges: vec!["10.0.0.0/8".to_string()],
        });

        let requested = Scope {
            network: Some(NetworkConstraints {
                follow_redirects: true,
                dns_resolution: "system".to_string(),
                allowed_ip_ranges: vec![],
            }),
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).unwrap();
        let nc = result.network.expect("network should be set");
        assert!(!nc.follow_redirects, "policy's follow_redirects should win");
        assert_eq!(
            nc.dns_resolution, "pinned",
            "policy's dns_resolution should win"
        );
        assert_eq!(nc.allowed_ip_ranges, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn network_constraints_falls_back_to_requested_when_policy_has_none() {
        let allow = make_allow(vec![], vec![], vec![]);
        // allow.network is None
        let requested = Scope {
            network: Some(NetworkConstraints {
                follow_redirects: true,
                dns_resolution: "system".to_string(),
                allowed_ip_ranges: vec![],
            }),
            ..Default::default()
        };
        let result = intersect_scope(&requested, &allow).unwrap();
        let nc = result
            .network
            .expect("network should be set from requested");
        assert!(nc.follow_redirects);
        assert_eq!(nc.dns_resolution, "system");
    }

    // -----------------------------------------------------------------------
    // Additional: reload replaces policies
    // -----------------------------------------------------------------------
    #[test]
    fn reload_replaces_policy_set() {
        let old_entry = make_entry(
            "old",
            Some(hash_of(0x30)),
            None,
            None,
            "*",
            "auto",
            vec![],
            vec![],
            vec![],
        );
        let new_entry = make_entry(
            "new",
            Some(hash_of(0x31)),
            None,
            None,
            "*",
            "auto",
            vec![],
            vec![],
            vec![],
        );

        let mut evaluator = PolicyEvaluator::new(vec![old_entry]);
        let agent_old = make_agent("/bin/agent", hash_of(0x30), None);
        let agent_new = make_agent("/bin/agent", hash_of(0x31), None);

        assert!(matches!(
            evaluator.evaluate(&agent_old, "c", &Scope::default()),
            PolicyDecision::AutoApprove { .. }
        ));
        assert!(matches!(
            evaluator.evaluate(&agent_new, "c", &Scope::default()),
            PolicyDecision::Denied { .. }
        ));

        evaluator.reload(vec![new_entry]);

        assert!(matches!(
            evaluator.evaluate(&agent_old, "c", &Scope::default()),
            PolicyDecision::Denied { .. }
        ));
        assert!(matches!(
            evaluator.evaluate(&agent_new, "c", &Scope::default()),
            PolicyDecision::AutoApprove { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Additional: build_constraints maps delegation fields
    // -----------------------------------------------------------------------
    #[test]
    fn build_constraints_maps_fields_correctly() {
        let mut allow = make_allow(vec![], vec![], vec![]);
        allow.max_ttl_seconds = Some(1800);
        allow.max_requests_per_lease = Some(50);
        allow.max_renewals = Some(2);
        allow.max_cumulative_ttl_seconds = Some(7200);
        allow.renewable = false;

        let delegation = PolicyDelegation {
            allowed: true,
            max_depth: Some(2),
            require_approval_for_delegate: true,
        };
        let constraints = build_constraints(&allow, &delegation);
        assert_eq!(constraints.max_ttl_seconds, Some(1800));
        assert_eq!(constraints.max_requests_per_lease, Some(50));
        assert_eq!(constraints.max_renewals, Some(2));
        assert_eq!(constraints.max_cumulative_ttl_seconds, Some(7200));
        assert!(!constraints.renewable);
        assert!(constraints.delegation_allowed);
        assert_eq!(constraints.delegation_max_depth, Some(2));
        assert!(constraints.delegation_require_approval);
    }
}
