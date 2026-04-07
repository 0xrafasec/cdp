//! TOML policy file parser for CDP policy rules.
//!
//! Provides deserialization of `.toml` policy files into typed `PolicyEntry`
//! structures, directory-level batch loading, and validation. Binary hash
//! strings in `"sha256:<hex>"` format are decoded here as well.
//!
//! # File Format
//!
//! Each `.toml` file may contain one or more `[[policy]]` tables:
//!
//! ```toml
//! [[policy]]
//! name = "github-readonly"
//! description = "Allow read-only GitHub API access"
//!
//! [policy.match]
//! agent_binary_hash = "sha256:abc123..."
//! credential_ref = "github_api"
//!
//! [policy.allow]
//! hosts = ["api.github.com"]
//! methods = ["GET"]
//! paths = ["/repos/**", "/users/**"]
//! forbidden_paths = ["/repos/*/keys"]
//! max_ttl_seconds = 3600
//! renewable = true
//!
//! [policy.approval]
//! mode = "auto"
//! ```

use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::PolicyError;
use crate::types::{BodyConstraints, NetworkConstraints};

// ---------------------------------------------------------------------------
// TOML deserialization types
// ---------------------------------------------------------------------------

/// Top-level structure of a CDP policy TOML file.
///
/// A single file may contain multiple `[[policy]]` entries, each of which
/// becomes one `PolicyEntry` after loading.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    /// All policy entries declared in this file (via `[[policy]]` tables).
    #[serde(rename = "policy")]
    pub policies: Vec<PolicyEntry>,
}

/// A single CDP policy rule, corresponding to one `[[policy]]` TOML table.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyEntry {
    /// Unique name used to identify this rule in audit logs.
    pub name: String,

    /// Human-readable description of the rule's intent (optional).
    #[serde(default)]
    pub description: String,

    /// Criteria used to determine whether this rule matches a request.
    #[serde(rename = "match")]
    pub match_block: PolicyMatch,

    /// The scope and constraints granted when this rule matches.
    pub allow: PolicyAllow,

    /// Approval configuration: `"auto"` or `"prompt"` (default: `"prompt"`).
    #[serde(default)]
    pub approval: PolicyApproval,

    /// Whether and how this lease may be sub-delegated to another agent.
    #[serde(default)]
    pub delegation: PolicyDelegation,
}

/// Criteria that determine whether a policy rule matches an incoming request.
///
/// At least `credential_ref` is always required. The identity fields
/// (`agent_binary_hash`, `agent_binary_path`, `agent_id`) are optional but
/// at least one cryptographic field (`agent_binary_hash` or
/// `agent_binary_path`) must be present when `approval.mode = "auto"`.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMatch {
    /// Expected SHA-256 hash of the agent binary, in `"sha256:<hex>"` format.
    pub agent_binary_hash: Option<String>,

    /// Filesystem path to the agent binary (matched against the resolved path
    /// supplied by `SO_PEERCRED`).
    pub agent_binary_path: Option<String>,

    /// Agent-declared identifier string.
    ///
    /// **Not cryptographic** — can be forged by the agent. Must not be used
    /// as the sole identity criterion for auto-approve rules.
    pub agent_id: Option<String>,

    /// Credential reference this policy rule applies to.
    ///
    /// Use `"*"` to match any credential, or a specific credential name.
    pub credential_ref: String,
}

/// The scope and resource constraints granted by a matching policy rule.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyAllow {
    /// Hostnames (or `host:port` strings) the agent may contact.
    #[serde(default)]
    pub hosts: Vec<String>,

    /// HTTP methods the agent may use (e.g. `"GET"`, `"POST"`).
    #[serde(default)]
    pub methods: Vec<String>,

    /// URL path patterns the agent may access (glob syntax; see `glob` module).
    #[serde(default)]
    pub paths: Vec<String>,

    /// URL path patterns that are explicitly forbidden, even if covered by
    /// an entry in `paths`.
    #[serde(default)]
    pub forbidden_paths: Vec<String>,

    /// Maximum TTL the lease may be created or renewed with, in seconds.
    pub max_ttl_seconds: Option<u64>,

    /// Maximum number of proxied HTTP requests per lease lifetime.
    pub max_requests_per_lease: Option<u64>,

    /// Maximum number of renewals permitted (protocol invariant: ≤ 3).
    pub max_renewals: Option<u32>,

    /// Maximum cumulative TTL across all renewals, in seconds
    /// (protocol invariant: ≤ 14 400, i.e. 4 hours).
    pub max_cumulative_ttl_seconds: Option<u64>,

    /// Whether the lease may be renewed (default: `true`).
    #[serde(default = "default_renewable")]
    pub renewable: bool,

    /// Fine-grained constraints on HTTP request bodies.
    #[serde(default)]
    pub body_constraints: Option<BodyConstraints>,

    /// Network-level constraints enforced by the proxy.
    #[serde(default)]
    pub network: Option<NetworkConstraints>,
}

fn default_renewable() -> bool {
    true
}

/// Approval mode configuration for a policy rule.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyApproval {
    /// Either `"auto"` (no user interaction required) or `"prompt"` (the
    /// gate will display an approval dialog before granting the lease).
    ///
    /// Defaults to `"prompt"` when the `[policy.approval]` table is absent.
    #[serde(default = "default_approval_mode")]
    pub mode: String,
}

fn default_approval_mode() -> String {
    "prompt".to_string()
}

impl Default for PolicyApproval {
    fn default() -> Self {
        Self {
            mode: default_approval_mode(),
        }
    }
}

/// Sub-delegation settings for a policy rule.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyDelegation {
    /// Whether the agent may delegate this lease to a sub-agent.
    #[serde(default)]
    pub allowed: bool,

    /// Maximum delegation depth (1 means the first delegate cannot
    /// re-delegate further). `None` means delegation is not allowed
    /// regardless of `allowed`.
    pub max_depth: Option<u32>,

    /// Whether user approval is required before each delegation event.
    #[serde(default)]
    pub require_approval_for_delegate: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load all `.toml` policy files from a directory.
///
/// Every `.toml` file in `dir` is read, parsed as a `PolicyFile`, and its
/// `PolicyEntry` items are accumulated into the returned `Vec`. Each entry is
/// individually validated via [`validate_policy`] before being included.
///
/// # Errors
///
/// - [`PolicyError::DirectoryNotFound`] — `dir` does not exist or is not a
///   directory.
/// - [`PolicyError::Io`] — a filesystem error occurred while reading `dir` or
///   a file inside it.
/// - [`PolicyError::Parse`] — a `.toml` file could not be parsed; the error
///   message includes the filename.
/// - [`PolicyError::Validation`] — a policy entry failed validation; the
///   error message includes the policy name.
///
/// # Notes
///
/// An empty directory returns an empty `Vec` without error.
pub fn load_policies_from_dir(dir: &Path) -> Result<Vec<PolicyEntry>, PolicyError> {
    if !dir.exists() {
        return Err(PolicyError::DirectoryNotFound(
            dir.display().to_string(),
        ));
    }
    if !dir.is_dir() {
        return Err(PolicyError::DirectoryNotFound(
            dir.display().to_string(),
        ));
    }

    let mut entries: Vec<PolicyEntry> = Vec::new();

    let read_dir = fs::read_dir(dir)?;
    let mut paths: Vec<std::path::PathBuf> = read_dir
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    // Sort for deterministic ordering across runs.
    paths.sort();

    for path in paths {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>")
            .to_string();

        let content = fs::read_to_string(&path).map_err(|e| PolicyError::Parse {
            file: file_name.clone(),
            reason: format!("failed to read file: {e}"),
        })?;

        let policy_file: PolicyFile =
            toml::from_str(&content).map_err(|e| PolicyError::Parse {
                file: file_name.clone(),
                reason: e.to_string(),
            })?;

        for entry in policy_file.policies {
            validate_policy(&entry)?;
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Validate a single `PolicyEntry` for correctness.
///
/// # Validation rules
///
/// 1. `credential_ref` must not be empty.
/// 2. `approval.mode` must be either `"auto"` or `"prompt"`.
/// 3. When `mode == "auto"`, the match block must include at least one
///    cryptographic agent identity field (`agent_binary_hash` or
///    `agent_binary_path`). A match block that contains only `agent_id` (a
///    self-declared, non-cryptographic field) is rejected to prevent privilege
///    escalation by a compromised agent.
///
/// # Errors
///
/// Returns [`PolicyError::Validation`] with a descriptive reason on failure.
pub fn validate_policy(entry: &PolicyEntry) -> Result<(), PolicyError> {
    // Rule 1: policy name must be non-empty and reasonably sized.
    if entry.name.trim().is_empty() {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: "policy name must not be empty".to_string(),
        });
    }
    if entry.name.len() > 128 {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: "policy name must not exceed 128 characters".to_string(),
        });
    }

    // Rule 2: credential_ref must not be empty.
    if entry.match_block.credential_ref.trim().is_empty() {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: "credential_ref must not be empty".to_string(),
        });
    }

    // Rule 3: approval mode must be a recognised value.
    let mode = entry.approval.mode.as_str();
    if mode != "auto" && mode != "prompt" {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: format!(
                "approval.mode must be \"auto\" or \"prompt\", got {:?}",
                mode
            ),
        });
    }

    // Rule 4: auto-approve requires agent_binary_hash (cryptographic identity).
    // agent_binary_path alone is not sufficient — filesystem paths are not
    // cryptographically verified and can be controlled via symlinks.
    if mode == "auto" && entry.match_block.agent_binary_hash.is_none() {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: "auto-approve rules must specify agent_binary_hash; \
                     agent_binary_path alone is insufficient for auto-approve \
                     (filesystem paths are not cryptographically verified)"
                .to_string(),
        });
    }

    // Rule 5: max_renewals must not exceed protocol invariant (3).
    if let Some(r) = entry.allow.max_renewals
        && r > 3
    {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: format!("max_renewals ({r}) exceeds protocol maximum of 3"),
        });
    }

    // Rule 6: max_cumulative_ttl_seconds must not exceed protocol invariant (4h = 14400s).
    if let Some(t) = entry.allow.max_cumulative_ttl_seconds
        && t > 14_400
    {
        return Err(PolicyError::Validation {
            policy_name: entry.name.clone(),
            reason: format!(
                "max_cumulative_ttl_seconds ({t}) exceeds protocol maximum of 14400 (4 hours)"
            ),
        });
    }

    Ok(())
}

/// Decode a `"sha256:<hex>"` binary hash string into a 32-byte array.
///
/// The input must:
/// - Begin with the prefix `"sha256:"`.
/// - Be followed by exactly 64 lowercase hexadecimal characters.
///
/// # Errors
///
/// Returns [`PolicyError::Parse`] with `file: "<none>"` when:
/// - The prefix is missing or incorrect.
/// - The hex portion is not valid hexadecimal.
/// - The decoded length is not exactly 32 bytes.
pub fn parse_binary_hash(raw: &str) -> Result<[u8; 32], PolicyError> {
    let hex_str = raw.strip_prefix("sha256:").ok_or_else(|| PolicyError::Parse {
        file: "<none>".to_string(),
        reason: format!(
            "binary hash must start with \"sha256:\", got {:?}",
            raw
        ),
    })?;

    let bytes = decode_hex(hex_str).ok_or_else(|| PolicyError::Parse {
        file: "<none>".to_string(),
        reason: format!(
            "binary hash hex portion is not valid hexadecimal: {:?}",
            hex_str
        ),
    })?;

    bytes.try_into().map_err(|_| PolicyError::Parse {
        file: "<none>".to_string(),
        reason: format!(
            "binary hash must decode to exactly 32 bytes (SHA-256), got {} bytes",
            hex_str.len() / 2
        ),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decode a lowercase or uppercase hexadecimal string into bytes.
///
/// Returns `None` if `s` contains non-hex characters or has an odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a minimal valid TOML policy string with the given approval mode
    /// and match block fields.
    fn make_policy_toml(
        name: &str,
        mode: &str,
        agent_binary_hash: Option<&str>,
        agent_binary_path: Option<&str>,
        agent_id: Option<&str>,
    ) -> String {
        let mut s = format!(
            r#"
[[policy]]
name = "{name}"
description = "Test policy"

[policy.match]
credential_ref = "test_cred"
"#
        );
        if let Some(h) = agent_binary_hash {
            s.push_str(&format!("agent_binary_hash = \"{h}\"\n"));
        }
        if let Some(p) = agent_binary_path {
            s.push_str(&format!("agent_binary_path = \"{p}\"\n"));
        }
        if let Some(id) = agent_id {
            s.push_str(&format!("agent_id = \"{id}\"\n"));
        }
        s.push_str(&format!(
            r#"
[policy.allow]
hosts = ["api.example.com"]
methods = ["GET"]

[policy.approval]
mode = "{mode}"
"#
        ));
        s
    }

    // -----------------------------------------------------------------------
    // Test 1: Full policy with all fields parses correctly
    // -----------------------------------------------------------------------

    #[test]
    fn full_policy_parses_correctly() {
        let toml = r#"
[[policy]]
name = "github-readonly"
description = "Allow MCP GitHub server read-only API access"

[policy.match]
agent_binary_hash = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
credential_ref = "github_api"

[policy.allow]
hosts = ["api.github.com"]
methods = ["GET"]
paths = ["/repos/**", "/users/**"]
forbidden_paths = ["/repos/*/keys", "/repos/*/hooks"]
max_ttl_seconds = 3600
max_requests_per_lease = 100
max_renewals = 3
max_cumulative_ttl_seconds = 7200
renewable = true

[policy.allow.body_constraints]
forbidden_fields = ["admin", "deploy_key", "delete"]
max_size_bytes = 65536

[policy.allow.network]
follow_redirects = false
dns_resolution = "pinned"
allowed_ip_ranges = []

[policy.approval]
mode = "auto"

[policy.delegation]
allowed = true
max_depth = 2
require_approval_for_delegate = false
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        assert_eq!(pf.policies.len(), 1);

        let e = &pf.policies[0];
        assert_eq!(e.name, "github-readonly");
        assert_eq!(e.description, "Allow MCP GitHub server read-only API access");
        assert_eq!(
            e.match_block.agent_binary_hash.as_deref(),
            Some("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        assert_eq!(e.match_block.credential_ref, "github_api");

        let allow = &e.allow;
        assert_eq!(allow.hosts, vec!["api.github.com"]);
        assert_eq!(allow.methods, vec!["GET"]);
        assert_eq!(allow.paths, vec!["/repos/**", "/users/**"]);
        assert_eq!(allow.forbidden_paths, vec!["/repos/*/keys", "/repos/*/hooks"]);
        assert_eq!(allow.max_ttl_seconds, Some(3600));
        assert_eq!(allow.max_requests_per_lease, Some(100));
        assert_eq!(allow.max_renewals, Some(3));
        assert_eq!(allow.max_cumulative_ttl_seconds, Some(7200));
        assert!(allow.renewable);

        let bc = allow.body_constraints.as_ref().expect("body_constraints missing");
        assert_eq!(bc.forbidden_fields, vec!["admin", "deploy_key", "delete"]);
        assert_eq!(bc.max_size_bytes, Some(65536));

        let nc = allow.network.as_ref().expect("network missing");
        assert!(!nc.follow_redirects);
        assert_eq!(nc.dns_resolution, "pinned");
        assert!(nc.allowed_ip_ranges.is_empty());

        assert_eq!(e.approval.mode, "auto");

        assert!(e.delegation.allowed);
        assert_eq!(e.delegation.max_depth, Some(2));
        assert!(!e.delegation.require_approval_for_delegate);

        // Validation must pass.
        validate_policy(e).expect("validation should pass");
    }

    // -----------------------------------------------------------------------
    // Test 2: Auto-approve with only agent_id is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn auto_approve_with_only_agent_id_is_rejected() {
        let toml = make_policy_toml("bad-auto", "auto", None, None, Some("my-agent"));
        let pf: PolicyFile = toml::from_str(&toml).expect("TOML parse failed");
        let e = &pf.policies[0];
        let err = validate_policy(e).expect_err("should fail validation");
        assert!(
            matches!(&err, PolicyError::Validation { policy_name, reason }
                if policy_name == "bad-auto"
                   && reason.contains("agent_binary_hash")),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Auto-approve with agent_binary_hash is accepted
    // -----------------------------------------------------------------------

    #[test]
    fn auto_approve_with_binary_hash_is_accepted() {
        let hash = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let toml = make_policy_toml("hash-auto", "auto", Some(hash), None, None);
        let pf: PolicyFile = toml::from_str(&toml).expect("TOML parse failed");
        validate_policy(&pf.policies[0]).expect("should pass");
    }

    // -----------------------------------------------------------------------
    // Test 4: Auto-approve with only agent_binary_path is rejected (requires hash)
    // -----------------------------------------------------------------------

    #[test]
    fn auto_approve_with_only_binary_path_is_rejected() {
        let toml = make_policy_toml("path-auto", "auto", None, Some("/usr/bin/my-agent"), None);
        let pf: PolicyFile = toml::from_str(&toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).unwrap_err();
        assert!(
            err.to_string().contains("agent_binary_hash"),
            "error should mention agent_binary_hash requirement: {err}"
        );
    }

    #[test]
    fn auto_approve_with_hash_and_path_is_accepted() {
        let hash = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let toml = make_policy_toml("both-auto", "auto", Some(hash), Some("/usr/bin/my-agent"), None);
        let pf: PolicyFile = toml::from_str(&toml).expect("TOML parse failed");
        validate_policy(&pf.policies[0]).expect("should pass");
    }

    // -----------------------------------------------------------------------
    // Test 5: Missing optional fields use correct defaults
    // -----------------------------------------------------------------------

    #[test]
    fn missing_optional_fields_use_defaults() {
        let toml = r#"
[[policy]]
name = "minimal"

[policy.match]
credential_ref = "some_cred"

[policy.allow]
hosts = ["example.com"]
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        let e = &pf.policies[0];

        assert_eq!(e.description, "");
        assert!(e.allow.renewable, "renewable should default to true");
        assert_eq!(e.approval.mode, "prompt", "mode should default to prompt");
        assert!(!e.delegation.allowed, "delegation.allowed should default to false");
        assert!(e.delegation.max_depth.is_none());
        assert!(!e.delegation.require_approval_for_delegate);
        assert!(e.allow.body_constraints.is_none());
        assert!(e.allow.network.is_none());
    }

    // -----------------------------------------------------------------------
    // Test 6: Multiple [[policy]] entries in one file
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_policy_entries_in_one_file() {
        let toml = r#"
[[policy]]
name = "first"

[policy.match]
credential_ref = "cred_a"

[policy.allow]
hosts = ["host-a.example.com"]

[[policy]]
name = "second"

[policy.match]
credential_ref = "cred_b"
agent_binary_hash = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
agent_binary_path = "/usr/bin/agent-b"

[policy.allow]
hosts = ["host-b.example.com"]

[policy.approval]
mode = "auto"
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        assert_eq!(pf.policies.len(), 2);
        assert_eq!(pf.policies[0].name, "first");
        assert_eq!(pf.policies[1].name, "second");
        validate_policy(&pf.policies[0]).expect("first should pass");
        validate_policy(&pf.policies[1]).expect("second should pass");
    }

    // -----------------------------------------------------------------------
    // Test 7: credential_ref = "*" is valid
    // -----------------------------------------------------------------------

    #[test]
    fn wildcard_credential_ref_is_valid() {
        let toml = r#"
[[policy]]
name = "wildcard-cred"

[policy.match]
credential_ref = "*"

[policy.allow]
hosts = ["example.com"]
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        validate_policy(&pf.policies[0]).expect("wildcard credential_ref should be valid");
    }

    // -----------------------------------------------------------------------
    // Test 8: Malformed TOML returns PolicyError::Parse
    // -----------------------------------------------------------------------

    #[test]
    fn malformed_toml_returns_parse_error() {
        let dir = TempDir::new().unwrap();
        let bad_file = dir.path().join("bad.toml");
        fs::write(&bad_file, "this is [[[not valid toml").unwrap();

        let err = load_policies_from_dir(dir.path()).expect_err("should fail");
        assert!(
            matches!(&err, PolicyError::Parse { file, .. } if file == "bad.toml"),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 9: parse_binary_hash with valid hex
    // -----------------------------------------------------------------------

    #[test]
    fn parse_binary_hash_valid() {
        let raw = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let bytes = parse_binary_hash(raw).expect("should succeed");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0xab);
        assert_eq!(bytes[1], 0xcd);
        assert_eq!(bytes[2], 0xef);
    }

    // -----------------------------------------------------------------------
    // Test 10: parse_binary_hash with invalid prefix
    // -----------------------------------------------------------------------

    #[test]
    fn parse_binary_hash_invalid_prefix() {
        let err = parse_binary_hash("md5:abcdef1234567890abcdef1234567890")
            .expect_err("should fail");
        assert!(
            matches!(&err, PolicyError::Parse { reason, .. } if reason.contains("sha256:")),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 11: parse_binary_hash with wrong length
    // -----------------------------------------------------------------------

    #[test]
    fn parse_binary_hash_wrong_length() {
        // Only 16 bytes (32 hex chars) instead of 32 bytes.
        let err = parse_binary_hash("sha256:abcdef1234567890abcdef1234567890")
            .expect_err("should fail");
        assert!(
            matches!(&err, PolicyError::Parse { reason, .. } if reason.contains("32 bytes")),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 12: load_policies_from_dir with multiple files
    // -----------------------------------------------------------------------

    #[test]
    fn load_policies_from_dir_multiple_files() {
        let dir = TempDir::new().unwrap();

        let toml_a = r#"
[[policy]]
name = "policy-a"

[policy.match]
credential_ref = "cred_a"

[policy.allow]
hosts = ["a.example.com"]
"#;
        let toml_b = r#"
[[policy]]
name = "policy-b"

[policy.match]
credential_ref = "cred_b"

[policy.allow]
hosts = ["b.example.com"]

[[policy]]
name = "policy-c"

[policy.match]
credential_ref = "cred_c"

[policy.allow]
hosts = ["c.example.com"]
"#;

        fs::write(dir.path().join("a.toml"), toml_a).unwrap();
        fs::write(dir.path().join("b.toml"), toml_b).unwrap();

        let entries = load_policies_from_dir(dir.path()).expect("should succeed");
        assert_eq!(entries.len(), 3);

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"policy-a"));
        assert!(names.contains(&"policy-b"));
        assert!(names.contains(&"policy-c"));
    }

    // -----------------------------------------------------------------------
    // Test 13: load_policies_from_dir with empty dir returns empty Vec
    // -----------------------------------------------------------------------

    #[test]
    fn load_policies_from_dir_empty_dir_returns_empty_vec() {
        let dir = TempDir::new().unwrap();
        let entries = load_policies_from_dir(dir.path()).expect("should succeed");
        assert!(entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 14: load_policies_from_dir with nonexistent dir returns DirectoryNotFound
    // -----------------------------------------------------------------------

    #[test]
    fn load_policies_from_dir_nonexistent_returns_directory_not_found() {
        let err = load_policies_from_dir(Path::new("/tmp/cdp-policy-nonexistent-dir-abc123"))
            .expect_err("should fail");
        assert!(
            matches!(&err, PolicyError::DirectoryNotFound(_)),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 15: Invalid approval mode is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_approval_mode_is_rejected() {
        // We must craft the TOML manually since PolicyApproval::default gives "prompt".
        let toml = r#"
[[policy]]
name = "bad-mode"

[policy.match]
credential_ref = "some_cred"

[policy.allow]
hosts = ["example.com"]

[policy.approval]
mode = "always"
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).expect_err("should fail validation");
        assert!(
            matches!(&err, PolicyError::Validation { policy_name, reason }
                if policy_name == "bad-mode"
                   && reason.contains("\"auto\" or \"prompt\"")),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 16: load_policies_from_dir ignores non-.toml files
    // -----------------------------------------------------------------------

    #[test]
    fn load_policies_from_dir_ignores_non_toml_files() {
        let dir = TempDir::new().unwrap();

        let valid_toml = r#"
[[policy]]
name = "only-policy"

[policy.match]
credential_ref = "cred"

[policy.allow]
hosts = ["example.com"]
"#;
        fs::write(dir.path().join("policy.toml"), valid_toml).unwrap();
        fs::write(dir.path().join("notes.txt"), "this is not toml").unwrap();
        fs::write(dir.path().join("config.json"), r#"{"not": "toml"}"#).unwrap();

        let entries = load_policies_from_dir(dir.path()).expect("should succeed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "only-policy");
    }

    // -----------------------------------------------------------------------
    // Test 17: Empty credential_ref is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn empty_credential_ref_is_rejected() {
        let toml = r#"
[[policy]]
name = "empty-cred"

[policy.match]
credential_ref = "   "

[policy.allow]
hosts = ["example.com"]
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).expect_err("should fail validation");
        assert!(
            matches!(&err, PolicyError::Validation { policy_name, reason }
                if policy_name == "empty-cred"
                   && reason.contains("credential_ref must not be empty")),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 18: parse_binary_hash with non-hex characters fails
    // -----------------------------------------------------------------------

    #[test]
    fn parse_binary_hash_non_hex_chars() {
        // 64 characters but contains 'g' which is not valid hex.
        let raw = "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        let err = parse_binary_hash(raw).expect_err("should fail");
        assert!(
            matches!(&err, PolicyError::Parse { reason, .. } if reason.contains("not valid hexadecimal")),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 19: All-zeros hash (valid boundary case)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_binary_hash_all_zeros() {
        let raw = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let bytes = parse_binary_hash(raw).expect("should succeed");
        assert_eq!(bytes, [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // Test 20: Uppercase hex is accepted
    // -----------------------------------------------------------------------

    #[test]
    fn parse_binary_hash_uppercase_hex() {
        let raw = "sha256:ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
        let bytes = parse_binary_hash(raw).expect("should succeed uppercase hex");
        assert_eq!(bytes[0], 0xAB);
        assert_eq!(bytes[1], 0xCD);
    }

    // -----------------------------------------------------------------------
    // Test 21: Empty policy name is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn empty_policy_name_is_rejected() {
        let toml = r#"
[[policy]]
name = ""
[policy.match]
credential_ref = "cred"
[policy.allow]
hosts = ["example.com"]
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Test 22: Overly long policy name is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn long_policy_name_is_rejected() {
        let long_name = "a".repeat(200);
        let toml = format!(
            r#"
[[policy]]
name = "{long_name}"
[policy.match]
credential_ref = "cred"
[policy.allow]
hosts = ["example.com"]
"#
        );
        let pf: PolicyFile = toml::from_str(&toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).unwrap_err();
        assert!(err.to_string().contains("128 characters"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Test 23: max_renewals exceeding protocol limit is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn max_renewals_exceeding_protocol_limit_is_rejected() {
        let toml = r#"
[[policy]]
name = "too-many-renewals"
[policy.match]
credential_ref = "cred"
[policy.allow]
hosts = ["example.com"]
max_renewals = 10
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).unwrap_err();
        assert!(err.to_string().contains("exceeds protocol maximum of 3"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Test 24: max_cumulative_ttl_seconds exceeding protocol limit is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn max_cumulative_ttl_exceeding_protocol_limit_is_rejected() {
        let toml = r#"
[[policy]]
name = "too-long-ttl"
[policy.match]
credential_ref = "cred"
[policy.allow]
hosts = ["example.com"]
max_cumulative_ttl_seconds = 99999
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        let err = validate_policy(&pf.policies[0]).unwrap_err();
        assert!(err.to_string().contains("14400"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Test 25: max_renewals at protocol limit is accepted
    // -----------------------------------------------------------------------

    #[test]
    fn max_renewals_at_protocol_limit_is_accepted() {
        let toml = r#"
[[policy]]
name = "ok-renewals"
[policy.match]
credential_ref = "cred"
[policy.allow]
hosts = ["example.com"]
max_renewals = 3
"#;
        let pf: PolicyFile = toml::from_str(toml).expect("TOML parse failed");
        validate_policy(&pf.policies[0]).expect("should pass");
    }
}
