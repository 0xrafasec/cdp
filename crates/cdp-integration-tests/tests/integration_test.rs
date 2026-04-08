//! Workspace-level integration tests for the CDP protocol implementation.
//!
//! These tests exercise the protocol flow end-to-end using the library crates
//! directly. No external processes are spawned.

use std::path::PathBuf;

use cdp_audit::{AuditEventType, AuditFields, AuditLogger, ChainStatus, verify_chain};
use cdp_crypto::{decrypt, derive_credential_key, encrypt};
use cdp_lease::types::{intersect_scopes, is_scope_subset};
use cdp_lease::{LeaseError, LeaseManager, LeaseStatus};
use cdp_policy::parser::{
    PolicyAllow, PolicyApproval, PolicyDelegation, PolicyEntry, PolicyMatch, validate_policy,
};
use cdp_policy::{AgentInfo, PolicyConstraints, Scope};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_agent() -> AgentInfo {
    AgentInfo {
        uid: 1000,
        pid: 42,
        binary_path: PathBuf::from("/usr/bin/test-agent"),
        binary_hash: [0xab; 32],
        start_time: 123_456_789,
        fingerprint_hash: [0xcd; 32],
        agent_id: Some("test-agent".to_string()),
        agent_version: Some("0.1.0".to_string()),
    }
}

fn delegate_agent() -> AgentInfo {
    AgentInfo {
        uid: 1001,
        pid: 99,
        binary_path: PathBuf::from("/usr/bin/child-agent"),
        binary_hash: [0xef; 32],
        start_time: 234_567_890,
        fingerprint_hash: [0x12; 32],
        agent_id: Some("child-agent".to_string()),
        agent_version: Some("0.1.0".to_string()),
    }
}

fn test_constraints() -> PolicyConstraints {
    PolicyConstraints {
        max_ttl_seconds: Some(3600),
        max_requests_per_lease: None,
        max_renewals: Some(3),
        max_cumulative_ttl_seconds: Some(14400),
        renewable: true,
        delegation_allowed: true,
        delegation_max_depth: Some(3),
        delegation_require_approval: false,
    }
}

fn api_scope() -> Scope {
    // Use localhost for DNS pinning in tests — external hostnames may not resolve
    // in sandboxed CI environments.
    Scope {
        hosts: vec!["localhost".to_string()],
        methods: vec!["GET".to_string(), "POST".to_string()],
        paths: vec!["/v1/*".to_string()],
        ttl_seconds: Some(3600),
        ..Default::default()
    }
}

fn make_manager() -> LeaseManager {
    let gate_key = b"integration-test-gate-key-32byte".to_vec();
    LeaseManager::new(gate_key, None)
}

// ---------------------------------------------------------------------------
// test_lease_lifecycle
// ---------------------------------------------------------------------------

/// Verifies the full lifecycle: create → use → renew → revoke.
#[tokio::test]
async fn test_lease_lifecycle() {
    let manager = make_manager();
    let agent = test_agent();
    let constraints = test_constraints();

    // Create a lease.
    let lease = manager
        .create_lease(
            &agent,
            "cred-api-key",
            api_scope(),
            &constraints,
            "api-access-policy",
            "auto",
        )
        .await
        .expect("create_lease should succeed");

    // Verify basic properties.
    assert_eq!(lease.status, LeaseStatus::Active);
    assert_eq!(lease.credential_ref, "cred-api-key");
    assert_eq!(lease.policy_name, "api-access-policy");
    assert_eq!(lease.granted_scope.hosts, vec!["localhost"]);
    assert_eq!(
        lease.granted_scope.methods,
        vec!["GET".to_string(), "POST".to_string()]
    );
    assert_eq!(lease.granted_scope.paths, vec!["/v1/*"]);
    assert!(!lease.dns_pinned_ips.is_empty(), "DNS pins must be present");
    assert!(!lease.lease_token.is_empty(), "lease_token must be set");
    assert_ne!(
        lease.channel_binding_nonce, [0u8; 32],
        "channel_binding_nonce must be random"
    );
    assert!(lease.is_active());

    // Use the lease.
    let used = manager
        .use_lease(&lease.lease_id)
        .await
        .expect("use_lease should succeed");
    assert_eq!(used.requests_used, 1);

    // Renew the lease.
    manager
        .renew_lease(&lease.lease_id, 600)
        .await
        .expect("renew_lease should succeed");

    let renewed = manager.get_lease(&lease.lease_id).await.unwrap();
    assert_eq!(renewed.renewals_used, 1);
    assert!(renewed.expires_at > lease.expires_at);

    // Revoke the lease.
    manager
        .revoke_lease(&lease.lease_id, "integration-test revocation")
        .await
        .expect("revoke_lease should succeed");

    let revoked = manager.get_lease(&lease.lease_id).await.unwrap();
    assert!(
        matches!(revoked.status, LeaseStatus::Revoked { .. }),
        "lease should be revoked"
    );
    assert!(!revoked.is_active());
}

// ---------------------------------------------------------------------------
// test_renewal_limits
// ---------------------------------------------------------------------------

/// Verifies that the 4th renewal is rejected when max_renewals=3.
#[tokio::test]
async fn test_renewal_limits() {
    let manager = make_manager();
    let agent = test_agent();
    let constraints = PolicyConstraints {
        max_renewals: Some(3),
        max_cumulative_ttl_seconds: Some(14400),
        ..test_constraints()
    };

    let lease = manager
        .create_lease(&agent, "cred-x", api_scope(), &constraints, "pol", "auto")
        .await
        .expect("create_lease should succeed");

    // Three renewals should succeed.
    for i in 0..3u32 {
        manager
            .renew_lease(&lease.lease_id, 100)
            .await
            .unwrap_or_else(|e| panic!("renewal {i} failed: {e}"));
    }

    // The fourth renewal must fail.
    let err = manager
        .renew_lease(&lease.lease_id, 100)
        .await
        .expect_err("fourth renewal should be rejected");

    assert!(
        matches!(err, LeaseError::MaxRenewalsExceeded(3)),
        "expected MaxRenewalsExceeded(3), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// test_delegation_cascade
// ---------------------------------------------------------------------------

/// Verifies that revoking the parent also revokes the child lease.
#[tokio::test]
async fn test_delegation_cascade() {
    let manager = make_manager();
    let agent = test_agent();
    let child_agent = delegate_agent();
    let constraints = test_constraints();

    let parent = manager
        .create_lease(&agent, "cred-api", api_scope(), &constraints, "pol", "auto")
        .await
        .expect("parent lease creation should succeed");

    // Delegate to child agent with a narrowed scope (must be a subset of parent).
    let child_scope = Scope {
        hosts: vec!["localhost".to_string()],
        methods: vec!["GET".to_string()],
        paths: vec!["/v1/*".to_string()],
        ..Default::default()
    };
    let child = manager
        .delegate(&parent.lease_id, &child_agent, child_scope, 1800, true)
        .await
        .expect("delegation should succeed");

    assert_eq!(child.status, LeaseStatus::Active);
    assert!(child.is_active());

    // Verify parent links to child.
    let parent_snapshot = manager.get_lease(&parent.lease_id).await.unwrap();
    assert!(
        parent_snapshot.child_lease_ids.contains(&child.lease_id),
        "parent must list the child lease ID"
    );

    // Revoke the parent — cascade must revoke the child too.
    manager
        .revoke_lease(&parent.lease_id, "cascade-test")
        .await
        .expect("revoke_lease should succeed");

    let parent_after = manager.get_lease(&parent.lease_id).await.unwrap();
    let child_after = manager.get_lease(&child.lease_id).await.unwrap();

    assert!(
        matches!(parent_after.status, LeaseStatus::Revoked { .. }),
        "parent must be revoked"
    );
    assert!(
        matches!(child_after.status, LeaseStatus::Revoked { .. }),
        "child must be revoked via cascade"
    );
}

// ---------------------------------------------------------------------------
// test_scope_intersection
// ---------------------------------------------------------------------------

/// Verifies the rules for scope intersection used during lease negotiation.
#[tokio::test]
async fn test_scope_intersection() {
    // hosts: intersection
    let requested = Scope {
        hosts: vec!["a.com".to_string(), "b.com".to_string()],
        ..Default::default()
    };
    let granted = Scope {
        hosts: vec!["b.com".to_string(), "c.com".to_string()],
        ..Default::default()
    };
    let result = intersect_scopes(&requested, &granted);
    assert_eq!(result.hosts, vec!["b.com"], "hosts must be intersected");

    // methods: intersection
    let requested = Scope {
        methods: vec!["GET".to_string(), "POST".to_string()],
        ..Default::default()
    };
    let granted = Scope {
        methods: vec!["GET".to_string()],
        ..Default::default()
    };
    let result = intersect_scopes(&requested, &granted);
    assert_eq!(result.methods, vec!["GET"], "methods must be intersected");

    // forbidden_paths: union
    let requested = Scope {
        forbidden_paths: vec!["/*".to_string()],
        ..Default::default()
    };
    let granted = Scope {
        forbidden_paths: vec!["/admin/*".to_string()],
        ..Default::default()
    };
    let result = intersect_scopes(&requested, &granted);
    assert!(
        result.forbidden_paths.contains(&"/*".to_string()),
        "forbidden_paths must include requested entry"
    );
    assert!(
        result.forbidden_paths.contains(&"/admin/*".to_string()),
        "forbidden_paths must include granted entry"
    );
    assert_eq!(result.forbidden_paths.len(), 2, "union must have 2 entries");

    // ttl_seconds: minimum
    let requested = Scope {
        ttl_seconds: Some(3600),
        ..Default::default()
    };
    let granted = Scope {
        ttl_seconds: Some(1800),
        ..Default::default()
    };
    let result = intersect_scopes(&requested, &granted);
    assert_eq!(
        result.ttl_seconds,
        Some(1800),
        "ttl_seconds must be the minimum"
    );
}

// ---------------------------------------------------------------------------
// test_audit_chain_integrity
// ---------------------------------------------------------------------------

/// Logs several events, verifies the chain, then tampers with an entry and
/// verifies that tampering is detected.
#[tokio::test]
async fn test_audit_chain_integrity() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let log_path = dir.path().join("audit.jsonl");

    let logger = AuditLogger::new(Some(log_path.clone()))
        .await
        .expect("AuditLogger::new should succeed");

    // Log several events.
    logger
        .log(
            AuditEventType::AgentRegistered,
            AuditFields {
                agent_fingerprint: Some("fp-abc123".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("log AgentRegistered");

    logger
        .log(
            AuditEventType::LeaseGranted,
            AuditFields {
                lease_id: Some("lease-001".to_string()),
                credential_ref: Some("cred-api".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("log LeaseGranted");

    logger
        .log(
            AuditEventType::LeaseUsed,
            AuditFields {
                lease_id: Some("lease-001".to_string()),
                detail: Some("request 1".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("log LeaseUsed");

    logger
        .log(
            AuditEventType::LeaseRevoked,
            AuditFields {
                lease_id: Some("lease-001".to_string()),
                detail: Some("user-initiated".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("log LeaseRevoked");

    // Drop the logger to close the file.
    drop(logger);

    // Verify chain is valid.
    let status = verify_chain(&log_path)
        .await
        .expect("verify_chain should not error");
    assert_eq!(
        status,
        ChainStatus::Valid { entries: 4 },
        "chain should be valid with 4 entries"
    );

    // Tamper with entry 2: change the credential_ref.
    let raw = tokio::fs::read_to_string(&log_path).await.unwrap();
    let mut lines: Vec<String> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();

    let mut entry: serde_json::Value = serde_json::from_str(&lines[1]).expect("line 2 must parse");
    entry["credential_ref"] = serde_json::Value::String("TAMPERED_CREDENTIAL".to_string());
    lines[1] = serde_json::to_string(&entry).unwrap();

    tokio::fs::write(&log_path, lines.join("\n") + "\n")
        .await
        .unwrap();

    // Tampering must be detected.
    let tampered_status = verify_chain(&log_path)
        .await
        .expect("verify_chain should not I/O-error");
    assert!(
        matches!(tampered_status, ChainStatus::Broken { .. }),
        "tampered chain should be detected as Broken, got {tampered_status:?}"
    );
}

// ---------------------------------------------------------------------------
// test_scope_subset_validation
// ---------------------------------------------------------------------------

/// Verifies is_scope_subset semantics used for delegation enforcement.
#[tokio::test]
async fn test_scope_subset_validation() {
    let parent = Scope {
        hosts: vec!["a.com".to_string(), "b.com".to_string()],
        methods: vec!["GET".to_string(), "POST".to_string()],
        paths: vec!["/api/".to_string()],
        ..Default::default()
    };

    // Child with host ["a.com"] is subset of parent ["a.com", "b.com"].
    let child_valid = Scope {
        hosts: vec!["a.com".to_string()],
        methods: vec!["GET".to_string()],
        paths: vec!["/api/".to_string()],
        ..Default::default()
    };
    assert!(
        is_scope_subset(&child_valid, &parent),
        "a.com is a subset of {{a.com, b.com}} - should be true"
    );

    // Child with host ["c.com"] is NOT subset of parent ["a.com", "b.com"].
    let child_bad_host = Scope {
        hosts: vec!["c.com".to_string()],
        methods: vec!["GET".to_string()],
        paths: vec!["/api/".to_string()],
        ..Default::default()
    };
    assert!(
        !is_scope_subset(&child_bad_host, &parent),
        "c.com is not a subset of {{a.com, b.com}} - should be false"
    );

    // Child with method ["GET", "POST"] is NOT subset of parent ["GET"].
    let parent_get_only = Scope {
        hosts: vec!["a.com".to_string()],
        methods: vec!["GET".to_string()],
        paths: vec!["/api/".to_string()],
        ..Default::default()
    };
    let child_two_methods = Scope {
        hosts: vec!["a.com".to_string()],
        methods: vec!["GET".to_string(), "POST".to_string()],
        paths: vec!["/api/".to_string()],
        ..Default::default()
    };
    assert!(
        !is_scope_subset(&child_two_methods, &parent_get_only),
        "{{GET, POST}} is not a subset of {{GET}} - should be false"
    );
}

// ---------------------------------------------------------------------------
// test_crypto_encrypt_decrypt_roundtrip
// ---------------------------------------------------------------------------

/// Verifies HKDF key derivation and ChaCha20-Poly1305 encrypt/decrypt roundtrip.
#[tokio::test]
async fn test_crypto_encrypt_decrypt_roundtrip() {
    // Derive a credential key via HKDF.
    let master: &[u8] = b"master-key-material-for-integration-test";
    let salt: &[u8] = b"random-gate-instance-salt-32byte";
    let key = derive_credential_key(master, salt, "cred-api-key", "lease-abc123")
        .expect("key derivation should succeed");

    let plaintext = b"super-secret-api-key-value-12345";

    // Encrypt plaintext.
    let blob = encrypt(&key, plaintext).expect("encrypt should succeed");

    // Decrypt — must match original.
    let decrypted = decrypt(&key, &blob).expect("decrypt should succeed");
    assert_eq!(
        decrypted.as_ref(),
        plaintext,
        "decrypted plaintext must match original"
    );

    // Modify ciphertext — decryption must fail (AEAD authentication).
    let mut tampered = blob.clone();
    if !tampered.ciphertext.is_empty() {
        tampered.ciphertext[0] ^= 0xFF;
    }
    let result = decrypt(&key, &tampered);
    assert!(
        result.is_err(),
        "decryption of tampered ciphertext must fail"
    );
}

// ---------------------------------------------------------------------------
// test_policy_auto_approve_requires_binary_hash
// ---------------------------------------------------------------------------

/// Verifies that auto-approve policies are rejected without agent_binary_hash.
#[tokio::test]
async fn test_policy_auto_approve_requires_binary_hash() {
    // Build an auto-approve policy with only agent_id — must be rejected.
    let bad_entry = PolicyEntry {
        name: "bad-auto-policy".to_string(),
        description: "should fail validation".to_string(),
        match_block: PolicyMatch {
            agent_binary_hash: None,
            agent_binary_path: None,
            agent_id: Some("my-agent".to_string()),
            credential_ref: "some-cred".to_string(),
        },
        allow: PolicyAllow {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/data/**".to_string()],
            forbidden_paths: vec![],
            max_ttl_seconds: Some(3600),
            max_requests_per_lease: None,
            max_renewals: Some(3),
            max_cumulative_ttl_seconds: Some(14400),
            renewable: true,
            body_constraints: None,
            network: None,
        },
        approval: PolicyApproval {
            mode: "auto".to_string(),
        },
        delegation: PolicyDelegation::default(),
    };

    let err = validate_policy(&bad_entry).expect_err("should fail validation");
    let err_string = err.to_string();
    assert!(
        err_string.contains("agent_binary_hash"),
        "error must mention agent_binary_hash, got: {err_string}"
    );

    // Now build a valid auto-approve policy with agent_binary_hash — must succeed.
    let hash_hex = "ab".repeat(32);
    let good_entry = PolicyEntry {
        name: "good-auto-policy".to_string(),
        description: "should pass validation".to_string(),
        match_block: PolicyMatch {
            agent_binary_hash: Some(format!("sha256:{hash_hex}")),
            agent_binary_path: None,
            agent_id: None,
            credential_ref: "some-cred".to_string(),
        },
        allow: PolicyAllow {
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/data/**".to_string()],
            forbidden_paths: vec![],
            max_ttl_seconds: Some(3600),
            max_requests_per_lease: None,
            max_renewals: Some(3),
            max_cumulative_ttl_seconds: Some(14400),
            renewable: true,
            body_constraints: None,
            network: None,
        },
        approval: PolicyApproval {
            mode: "auto".to_string(),
        },
        delegation: PolicyDelegation::default(),
    };

    validate_policy(&good_entry).expect("valid auto policy with binary_hash must pass");
}

// ---------------------------------------------------------------------------
// test_policy_toml_parse
// ---------------------------------------------------------------------------

/// Verifies that TOML policy parsing enforces the auto-approve / binary_hash rule
/// via load_policies_from_dir.
#[tokio::test]
async fn test_policy_toml_parse() {
    use cdp_policy::parser::load_policies_from_dir;

    let dir = tempfile::tempdir().expect("create temp dir");

    // Write a policy with mode=auto and no agent_binary_hash — must fail.
    let bad_toml = r#"
[[policy]]
name = "bad-auto"
[policy.match]
agent_id = "my-agent"
credential_ref = "cred-x"
[policy.allow]
hosts = ["api.example.com"]
[policy.approval]
mode = "auto"
"#;
    tokio::fs::write(dir.path().join("bad.toml"), bad_toml)
        .await
        .unwrap();

    let result = load_policies_from_dir(dir.path());
    assert!(result.is_err(), "auto policy without binary_hash must fail");

    // Remove bad file, write a good policy.
    tokio::fs::remove_file(dir.path().join("bad.toml"))
        .await
        .unwrap();

    let hash_hex = "ab".repeat(32);
    let good_toml = format!(
        r#"
[[policy]]
name = "good-auto"
[policy.match]
agent_binary_hash = "sha256:{hash_hex}"
credential_ref = "cred-x"
[policy.allow]
hosts = ["api.example.com"]
methods = ["GET"]
paths = ["/data/**"]
[policy.approval]
mode = "auto"
"#
    );
    tokio::fs::write(dir.path().join("good.toml"), &good_toml)
        .await
        .unwrap();

    let policies = load_policies_from_dir(dir.path()).expect("good policy must parse");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "good-auto");
    assert_eq!(policies[0].approval.mode, "auto");
}

// ---------------------------------------------------------------------------
// test_multiple_leases_same_agent
// ---------------------------------------------------------------------------

/// Verifies that one agent can hold multiple concurrent leases.
#[tokio::test]
async fn test_multiple_leases_same_agent() {
    let manager = make_manager();
    let agent = test_agent();
    let constraints = test_constraints();

    let lease1 = manager
        .create_lease(&agent, "cred-a", api_scope(), &constraints, "pol1", "auto")
        .await
        .expect("first lease should succeed");

    let lease2 = manager
        .create_lease(&agent, "cred-b", api_scope(), &constraints, "pol2", "auto")
        .await
        .expect("second lease should succeed");

    assert_ne!(lease1.lease_id, lease2.lease_id);
    assert!(lease1.is_active());
    assert!(lease2.is_active());

    // Revoking all agent leases must revoke both.
    let revoked = manager
        .revoke_agent_leases(&agent.fingerprint_hash, "cleanup")
        .await
        .expect("revoke_agent_leases should succeed");

    assert!(revoked.contains(&lease1.lease_id));
    assert!(revoked.contains(&lease2.lease_id));

    let l1 = manager.get_lease(&lease1.lease_id).await.unwrap();
    let l2 = manager.get_lease(&lease2.lease_id).await.unwrap();
    assert!(matches!(l1.status, LeaseStatus::Revoked { .. }));
    assert!(matches!(l2.status, LeaseStatus::Revoked { .. }));
}

// ---------------------------------------------------------------------------
// test_lease_token_and_channel_binding_are_unique
// ---------------------------------------------------------------------------

/// Verifies that each lease has a unique lease_token and channel_binding_nonce.
#[tokio::test]
async fn test_lease_token_and_channel_binding_are_unique() {
    let manager = make_manager();
    let agent = test_agent();
    let constraints = test_constraints();

    let lease1 = manager
        .create_lease(&agent, "cred", api_scope(), &constraints, "pol", "auto")
        .await
        .unwrap();

    let lease2 = manager
        .create_lease(&agent, "cred", api_scope(), &constraints, "pol", "auto")
        .await
        .unwrap();

    assert_ne!(
        lease1.lease_token, lease2.lease_token,
        "lease_token must be unique per lease"
    );
    assert_ne!(
        lease1.channel_binding_nonce, lease2.channel_binding_nonce,
        "channel_binding_nonce must be unique per lease"
    );
}

// ---------------------------------------------------------------------------
// test_hkdf_key_isolation
// ---------------------------------------------------------------------------

/// Verifies that HKDF derives distinct keys for different (credential_ref, lease_id)
/// pairs, preventing one credential's key from being used to decrypt another's data.
#[tokio::test]
async fn test_hkdf_key_isolation() {
    let master = b"shared-master-key-material-value";
    let salt = b"gate-instance-salt-value-32bytez";

    let key_a = derive_credential_key(master, salt, "cred-github", "lease-001").unwrap();
    let key_b = derive_credential_key(master, salt, "cred-aws", "lease-001").unwrap();
    let key_c = derive_credential_key(master, salt, "cred-github", "lease-002").unwrap();

    assert_ne!(
        *key_a, *key_b,
        "different credential_ref must produce different keys"
    );
    assert_ne!(
        *key_a, *key_c,
        "different lease_id must produce different keys"
    );
    assert_ne!(*key_b, *key_c);

    // Encryption with key_a cannot be decrypted with key_b.
    let plaintext = b"github-token-secret-value";
    let blob = encrypt(&key_a, plaintext).expect("encrypt");

    let wrong_key_result = decrypt(&key_b, &blob);
    assert!(
        wrong_key_result.is_err(),
        "decryption with wrong key must fail"
    );

    // Correct key decrypts successfully.
    let correct = decrypt(&key_a, &blob).expect("decrypt with correct key");
    assert_eq!(correct.as_ref(), plaintext);
}
