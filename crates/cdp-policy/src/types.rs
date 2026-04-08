use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Agent identity (lightweight clone-safe form for policy evaluation)
// ---------------------------------------------------------------------------

/// Lightweight agent identity passed to policy evaluation.
///
/// Unlike `cdp_gate::AgentFingerprint`, this type does not hold a `pidfd`
/// `OwnedFd` so it is freely `Clone + Send` and can cross async task
/// boundaries without restriction.
#[derive(Debug, Clone)]
pub struct AgentInfo {
    /// Effective user ID from `SO_PEERCRED`.
    pub uid: u32,
    /// Process ID from `SO_PEERCRED`.
    pub pid: u32,
    /// Resolved path to the agent binary.
    pub binary_path: PathBuf,
    /// SHA-256 of the agent binary at registration time.
    pub binary_hash: [u8; 32],
    /// Clock-tick start time from `/proc/<pid>/stat` field 22.
    pub start_time: u64,
    /// Composite fingerprint: `SHA-256(uid || pid || binary_hash || start_time)`.
    pub fingerprint_hash: [u8; 32],
    /// Agent-declared identifier, if provided during registration.
    pub agent_id: Option<String>,
    /// Agent-declared version string, if provided during registration.
    pub agent_version: Option<String>,
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Constraints on the hosts/methods/paths an agent may access.
///
/// Used both to represent what an agent *requests* and what a policy
/// *grants*. All fields use `serde(default)` so partial JSON objects are
/// accepted without error.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    /// Allowed hostnames or host:port strings (e.g. `"api.example.com"`).
    #[serde(default)]
    pub hosts: Vec<String>,

    /// Allowed HTTP methods (e.g. `"GET"`, `"POST"`).
    #[serde(default)]
    pub methods: Vec<String>,

    /// Allowed URL path prefixes.
    #[serde(default)]
    pub paths: Vec<String>,

    /// URL paths that are explicitly forbidden even if covered by `paths`.
    #[serde(default)]
    pub forbidden_paths: Vec<String>,

    /// Requested or granted TTL for the lease in seconds.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,

    /// Maximum number of proxied requests permitted per lease.
    #[serde(default)]
    pub max_requests: Option<u64>,

    /// Fine-grained constraints on request bodies.
    #[serde(default)]
    pub body_constraints: Option<BodyConstraints>,

    /// Network-level constraints enforced by the proxy.
    #[serde(default)]
    pub network: Option<NetworkConstraints>,
}

// ---------------------------------------------------------------------------
// BodyConstraints
// ---------------------------------------------------------------------------

/// Constraints applied to HTTP request bodies passing through the proxy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BodyConstraints {
    /// JSON field names that must never appear in request bodies.
    #[serde(default)]
    pub forbidden_fields: Vec<String>,

    /// Maximum allowed body size in bytes; `None` means unlimited.
    #[serde(default)]
    pub max_size_bytes: Option<u64>,

    /// If non-empty, only these `Content-Type` values are allowed.
    #[serde(default)]
    pub allowed_content_types: Vec<String>,
}

// ---------------------------------------------------------------------------
// NetworkConstraints
// ---------------------------------------------------------------------------

/// Network-level constraints enforced by the CDP proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConstraints {
    /// Whether the proxy should follow HTTP redirects (default: `false`).
    #[serde(default)]
    pub follow_redirects: bool,

    /// DNS resolution mode: `"pinned"` (default), `"system"`, or `"none"`.
    ///
    /// `"pinned"` means DNS is resolved once at lease creation time and the
    /// resulting address is pinned for the lifetime of the lease (see
    /// spec/THREAT_MODEL.md, DNS rebinding defence).
    pub dns_resolution: String,

    /// CIDR ranges the proxy is allowed to connect to; empty means
    /// unrestricted (subject to host-level allow-listing).
    #[serde(default)]
    pub allowed_ip_ranges: Vec<String>,
}

impl Default for NetworkConstraints {
    fn default() -> Self {
        Self {
            follow_redirects: false,
            dns_resolution: "pinned".to_string(),
            allowed_ip_ranges: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyConstraints
// ---------------------------------------------------------------------------

/// Hard limits extracted from the matching policy rule, passed to the lease
/// subsystem to bound what a lease may do regardless of what the agent asked.
#[derive(Debug, Clone)]
pub struct PolicyConstraints {
    /// Maximum TTL the lease may be created with.
    pub max_ttl_seconds: Option<u64>,

    /// Maximum number of proxied requests per lease.
    pub max_requests_per_lease: Option<u64>,

    /// Maximum number of times the lease may be renewed.
    pub max_renewals: Option<u32>,

    /// Maximum cumulative TTL across all renewals (protocol invariant: ≤ 4h).
    pub max_cumulative_ttl_seconds: Option<u64>,

    /// Whether the lease may be renewed at all (default: `true`).
    pub renewable: bool,

    /// Whether the agent may sub-delegate this lease to another agent.
    pub delegation_allowed: bool,

    /// Maximum sub-delegation depth; `None` means delegation is forbidden.
    pub delegation_max_depth: Option<u32>,

    /// Whether user approval is required before each delegation.
    pub delegation_require_approval: bool,
}

impl Default for PolicyConstraints {
    /// Returns `PolicyConstraints` with `renewable = true` and all other
    /// fields at their zero/None values.
    ///
    /// The `renewable` field defaults to `true` because refusing renewal
    /// must be an explicit opt-in in policy rules, not the implicit baseline.
    fn default() -> Self {
        Self {
            max_ttl_seconds: None,
            max_requests_per_lease: None,
            max_renewals: None,
            max_cumulative_ttl_seconds: None,
            renewable: true,
            delegation_allowed: false,
            delegation_max_depth: None,
            delegation_require_approval: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyDecision
// ---------------------------------------------------------------------------

/// Result returned by the policy evaluator for a credential-request attempt.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// The request matches an auto-approve rule; the lease may be created
    /// without interactive user approval.
    AutoApprove {
        /// The scope the agent is actually granted (may be a subset of what
        /// was requested after policy narrowing).
        granted_scope: Scope,
        /// Name of the matching policy rule, for audit-log attribution.
        policy_name: String,
        /// Hard limits from the policy, forwarded to the lease subsystem.
        constraints: PolicyConstraints,
    },

    /// The request matches a policy rule that mandates user approval before
    /// the lease is created.
    RequiresApproval {
        /// The scope that *would* be granted if the user approves.
        granted_scope: Scope,
        /// Name of the matching policy rule.
        policy_name: String,
        /// Hard limits from the policy.
        constraints: PolicyConstraints,
    },

    /// No policy rule matches, or a deny rule matched explicitly.
    Denied {
        /// Human-readable reason surfaced to the agent (no secrets).
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// ApprovalConfig
// ---------------------------------------------------------------------------

/// Configuration for the interactive user-approval flow, passed from the
/// `cdp-gate` configuration file into the policy evaluator.
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    /// Shell command (or path to binary) used to present the approval GUI.
    ///
    /// The command receives the request details on stdin as a JSON object and
    /// must write a single `ApprovalResult` token to stdout.
    pub gui_command: String,

    /// Seconds to wait for user response before returning `ApprovalTimeout`.
    pub timeout_seconds: u64,

    /// Whether to include the agent binary SHA-256 hash in the GUI prompt.
    pub show_binary_hash: bool,

    /// When `true`, the UI labels the agent-provided reason as untrusted
    /// (i.e. "Agent claims: …") to prevent social-engineering attacks where a
    /// malicious agent crafts a convincing approval message.
    pub label_reason_untrusted: bool,

    /// Maximum number of bytes accepted from the agent-provided reason string;
    /// longer strings are truncated before display.
    pub max_reason_length: usize,
}

// ---------------------------------------------------------------------------
// ApprovalResult
// ---------------------------------------------------------------------------

/// Decision returned by the user-approval GUI command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalResult {
    /// Grant the request for this single use only.
    AllowOnce,

    /// Grant the request for the specified duration.
    AllowTimed { duration_seconds: u64 },

    /// Reject the request.
    Deny,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_default_is_empty() {
        let s = Scope::default();
        assert!(s.hosts.is_empty());
        assert!(s.methods.is_empty());
        assert!(s.paths.is_empty());
        assert!(s.forbidden_paths.is_empty());
        assert!(s.ttl_seconds.is_none());
        assert!(s.max_requests.is_none());
        assert!(s.body_constraints.is_none());
        assert!(s.network.is_none());
    }

    #[test]
    fn network_constraints_default_is_pinned() {
        let nc = NetworkConstraints::default();
        assert_eq!(nc.dns_resolution, "pinned");
        assert!(!nc.follow_redirects);
        assert!(nc.allowed_ip_ranges.is_empty());
    }

    #[test]
    fn policy_constraints_default_has_renewable_true() {
        let pc = PolicyConstraints::default();
        assert!(pc.renewable);
        assert!(!pc.delegation_allowed);
        assert!(!pc.delegation_require_approval);
        assert!(pc.max_ttl_seconds.is_none());
        assert!(pc.max_renewals.is_none());
        assert!(pc.max_cumulative_ttl_seconds.is_none());
        assert!(pc.delegation_max_depth.is_none());
    }

    #[test]
    fn agent_info_can_be_constructed_and_cloned() {
        let info = AgentInfo {
            uid: 1000,
            pid: 42,
            binary_path: PathBuf::from("/usr/bin/my-agent"),
            binary_hash: [0xab; 32],
            start_time: 123456789,
            fingerprint_hash: [0xcd; 32],
            agent_id: Some("my-agent".to_string()),
            agent_version: Some("1.2.3".to_string()),
        };
        let cloned = info.clone();
        assert_eq!(cloned.uid, 1000);
        assert_eq!(cloned.pid, 42);
        assert_eq!(cloned.binary_hash, [0xab; 32]);
        assert_eq!(cloned.agent_id.as_deref(), Some("my-agent"));
        assert_eq!(cloned.agent_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn agent_info_optional_fields_can_be_none() {
        let info = AgentInfo {
            uid: 0,
            pid: 1,
            binary_path: PathBuf::from("/bin/agent"),
            binary_hash: [0u8; 32],
            start_time: 0,
            fingerprint_hash: [0u8; 32],
            agent_id: None,
            agent_version: None,
        };
        assert!(info.agent_id.is_none());
        assert!(info.agent_version.is_none());
    }

    #[test]
    fn policy_decision_variants_can_be_constructed() {
        let scope = Scope::default();
        let constraints = PolicyConstraints::default();

        let auto = PolicyDecision::AutoApprove {
            granted_scope: scope.clone(),
            policy_name: "allow-readonly".to_string(),
            constraints: constraints.clone(),
        };
        assert!(matches!(auto, PolicyDecision::AutoApprove { .. }));

        let needs_approval = PolicyDecision::RequiresApproval {
            granted_scope: scope.clone(),
            policy_name: "write-ops".to_string(),
            constraints: constraints.clone(),
        };
        assert!(matches!(
            needs_approval,
            PolicyDecision::RequiresApproval { .. }
        ));

        let denied = PolicyDecision::Denied {
            reason: "no matching rule".to_string(),
        };
        if let PolicyDecision::Denied { reason } = denied {
            assert_eq!(reason, "no matching rule");
        } else {
            panic!("expected Denied variant");
        }
    }

    #[test]
    fn policy_decision_auto_approve_fields_accessible() {
        let scope = Scope {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string()],
            ..Default::default()
        };
        let constraints = PolicyConstraints {
            max_ttl_seconds: Some(3600),
            max_renewals: Some(3),
            ..Default::default()
        };
        let decision = PolicyDecision::AutoApprove {
            granted_scope: scope,
            policy_name: "my-policy".to_string(),
            constraints,
        };
        if let PolicyDecision::AutoApprove {
            granted_scope,
            policy_name,
            constraints,
        } = decision
        {
            assert_eq!(granted_scope.hosts, vec!["api.example.com"]);
            assert_eq!(policy_name, "my-policy");
            assert_eq!(constraints.max_ttl_seconds, Some(3600));
            assert_eq!(constraints.max_renewals, Some(3));
        } else {
            panic!("expected AutoApprove variant");
        }
    }

    #[test]
    fn approval_result_equality() {
        assert_eq!(ApprovalResult::AllowOnce, ApprovalResult::AllowOnce);
        assert_eq!(ApprovalResult::Deny, ApprovalResult::Deny);
        assert_eq!(
            ApprovalResult::AllowTimed {
                duration_seconds: 300
            },
            ApprovalResult::AllowTimed {
                duration_seconds: 300
            },
        );
        assert_ne!(
            ApprovalResult::AllowTimed {
                duration_seconds: 300
            },
            ApprovalResult::AllowTimed {
                duration_seconds: 600
            },
        );
        assert_ne!(ApprovalResult::AllowOnce, ApprovalResult::Deny);
        assert_ne!(
            ApprovalResult::AllowOnce,
            ApprovalResult::AllowTimed {
                duration_seconds: 1
            },
        );
    }

    #[test]
    fn scope_serializes_and_deserializes() {
        let original = Scope {
            hosts: vec!["example.com".to_string()],
            methods: vec!["POST".to_string()],
            paths: vec!["/api/".to_string()],
            forbidden_paths: vec!["/api/admin".to_string()],
            ttl_seconds: Some(1800),
            max_requests: Some(100),
            body_constraints: Some(BodyConstraints {
                forbidden_fields: vec!["password".to_string()],
                max_size_bytes: Some(65536),
                allowed_content_types: vec!["application/json".to_string()],
            }),
            network: Some(NetworkConstraints {
                follow_redirects: false,
                dns_resolution: "pinned".to_string(),
                allowed_ip_ranges: vec!["10.0.0.0/8".to_string()],
            }),
        };
        let json = serde_json::to_string(&original).expect("serialization failed");
        let roundtrip: Scope = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(roundtrip.hosts, original.hosts);
        assert_eq!(roundtrip.methods, original.methods);
        assert_eq!(roundtrip.paths, original.paths);
        assert_eq!(roundtrip.forbidden_paths, original.forbidden_paths);
        assert_eq!(roundtrip.ttl_seconds, Some(1800));
        assert_eq!(roundtrip.max_requests, Some(100));

        let bc = roundtrip
            .body_constraints
            .expect("body_constraints missing");
        assert_eq!(bc.forbidden_fields, vec!["password"]);
        assert_eq!(bc.max_size_bytes, Some(65536));

        let nc = roundtrip.network.expect("network missing");
        assert_eq!(nc.dns_resolution, "pinned");
        assert_eq!(nc.allowed_ip_ranges, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn scope_deserializes_from_partial_json() {
        // Only hosts provided — all other fields default.
        let json = r#"{"hosts": ["api.example.com"]}"#;
        let scope: Scope = serde_json::from_str(json).expect("deserialization failed");
        assert_eq!(scope.hosts, vec!["api.example.com"]);
        assert!(scope.methods.is_empty());
        assert!(scope.ttl_seconds.is_none());
        assert!(scope.body_constraints.is_none());
    }

    #[test]
    fn body_constraints_default_is_empty() {
        let bc = BodyConstraints::default();
        assert!(bc.forbidden_fields.is_empty());
        assert!(bc.max_size_bytes.is_none());
        assert!(bc.allowed_content_types.is_empty());
    }

    #[test]
    fn approval_config_fields_accessible() {
        let cfg = ApprovalConfig {
            gui_command: "/usr/lib/cdp/approve-gui".to_string(),
            timeout_seconds: 30,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 512,
        };
        assert_eq!(cfg.timeout_seconds, 30);
        assert!(cfg.show_binary_hash);
        assert!(cfg.label_reason_untrusted);
        assert_eq!(cfg.max_reason_length, 512);

        let cloned = cfg.clone();
        assert_eq!(cloned.gui_command, "/usr/lib/cdp/approve-gui");
    }
}
