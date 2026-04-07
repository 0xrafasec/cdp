//! Lease delegation — sub-delegating an existing lease to another agent.
//!
//! Delegation creates a child lease from a parent, constraining the child's
//! scope to be a strict subset of the parent's granted scope. The protocol
//! enforces depth limits so that delegation chains cannot be arbitrarily long.

use chrono::{Duration, Utc};
use tracing::info;

use cdp_audit::{AuditEventType, AuditFields};
use cdp_policy::{AgentInfo, Scope};

use crate::{
    channel_bind, dns_pin,
    manager::{hex_encode, LeaseManager},
    types::{Lease, LeaseId, LeaseStatus},
    LeaseError,
};

impl LeaseManager {
    /// Delegate an existing lease to `target_agent`, creating a child lease.
    ///
    /// ## Protocol invariants enforced
    /// 1. Target agent must be alive (`target_alive == true`).
    /// 2. Parent lease must be `Active` and not expired.
    /// 3. Parent must have `delegation_allowed == true`.
    /// 4. Delegation depth must not exceed `parent.delegation_max_depth`.
    /// 5. Child scope must be a subset of the parent's granted scope.
    /// 6. Child TTL must not exceed the parent's remaining TTL.
    ///
    /// DNS pinning for the child scope is performed **before** any lock is
    /// acquired. The write lock is then acquired, and all invariants are
    /// re-validated while the lock is held to prevent TOCTOU races (e.g. the
    /// parent could be revoked between DNS resolution and insertion).
    pub async fn delegate(
        &self,
        parent_lease_id: &LeaseId,
        target_agent: &AgentInfo,
        child_scope: Scope,
        child_ttl_seconds: u64,
        target_alive: bool,
    ) -> Result<Lease, LeaseError> {
        if !target_alive {
            return Err(LeaseError::TargetAgentNotAlive);
        }

        // Validate the child scope is a subset of the parent's granted scope before
        // performing any I/O.  We need to read the parent scope without the write
        // lock; re-validation happens again under the write lock to prevent races.
        {
            let leases = self.leases.read().await;
            let parent = leases
                .get(parent_lease_id)
                .ok_or_else(|| LeaseError::NotFound(parent_lease_id.to_string()))?;
            if !crate::types::is_scope_subset(&child_scope, &parent.granted_scope) {
                return Err(LeaseError::ScopeNotSubset);
            }
        }

        // Perform DNS pinning before acquiring the write lock to avoid holding
        // the lock across an async I/O await point.
        let dns_pinned_ips = dns_pin::pin_dns(&child_scope.hosts).await?;

        // Generate immutable values we'll need for the new lease.
        let child_id = LeaseId::generate();
        let cb_nonce = channel_bind::generate_nonce();
        let lease_token = cdp_crypto::generate_lease_token(
            &self.gate_key,
            child_id.as_str(),
            &target_agent.fingerprint_hash,
            &cb_nonce,
        );

        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(child_ttl_seconds as i64);

        // Acquire write lock for all validation and mutation.
        let child_lease = {
            let mut leases = self.leases.write().await;

            // Re-validate parent under the lock.
            let parent = leases
                .get(parent_lease_id)
                .ok_or_else(|| LeaseError::NotFound(parent_lease_id.to_string()))?;

            if parent.status != LeaseStatus::Active {
                return Err(LeaseError::NotActive);
            }
            if parent.is_expired() {
                return Err(LeaseError::Expired(parent_lease_id.to_string()));
            }
            if !parent.delegation_allowed {
                return Err(LeaseError::DelegationNotAllowed);
            }

            // Check delegation depth.
            // `delegation_max_depth` is the max allowed depth for the subtree rooted
            // at this lease. The child would be at `parent.delegation_depth + 1`.
            let max_depth = parent.delegation_max_depth.unwrap_or(3);
            let child_depth = parent.delegation_depth + 1;
            if child_depth > max_depth {
                return Err(LeaseError::DelegationDepthExceeded(max_depth));
            }

            // Validate child scope is a subset of parent's granted scope.
            if !crate::types::is_scope_subset(&child_scope, &parent.granted_scope) {
                return Err(LeaseError::ScopeNotSubset);
            }

            // Validate child TTL does not exceed parent's remaining TTL.
            let remaining = parent.remaining_ttl_seconds();
            if remaining < 0 || child_ttl_seconds > remaining as u64 {
                return Err(LeaseError::TtlExceedsParent);
            }

            let child_max_renewals = parent.max_renewals;
            let child_max_cumulative_ttl = parent.max_cumulative_ttl_seconds;
            let child_delegation_allowed = parent.delegation_allowed;
            // Propagate the same max_depth from root so descendants can check
            // against the original policy limit via `delegation_depth`.
            let child_delegation_max_depth = parent.delegation_max_depth;
            let parent_fingerprint = hex_encode(&parent.agent_fingerprint_hash);
            let parent_credential = parent.credential_ref.clone();
            let follow_redirects = parent.follow_redirects;

            let child_lease = Lease {
                lease_id: child_id.clone(),
                credential_ref: parent_credential.clone(),
                policy_name: "delegated".to_string(),
                approval_method: "delegation".to_string(),
                agent_fingerprint_hash: target_agent.fingerprint_hash,
                agent_binary_path: target_agent
                    .binary_path
                    .to_string_lossy()
                    .into_owned(),
                agent_uid: target_agent.uid,
                agent_pid: target_agent.pid,
                granted_scope: child_scope,
                lease_token,
                channel_binding_nonce: cb_nonce,
                dns_pinned_ips,
                status: LeaseStatus::Active,
                created_at,
                expires_at,
                ttl_seconds: child_ttl_seconds,
                cumulative_ttl_seconds: child_ttl_seconds,
                max_requests: None,
                requests_used: 0,
                renewals_used: 0,
                max_renewals: child_max_renewals,
                max_cumulative_ttl_seconds: child_max_cumulative_ttl,
                renewable: true,
                parent_lease_id: Some(parent_lease_id.clone()),
                child_lease_ids: Vec::new(),
                delegation_depth: child_depth,
                delegation_allowed: child_delegation_allowed,
                delegation_max_depth: child_delegation_max_depth,
                follow_redirects,
            };

            // Link child to parent.
            if let Some(parent_mut) = leases.get_mut(parent_lease_id) {
                parent_mut.child_lease_ids.push(child_id.clone());
            }

            leases.insert(child_id.clone(), child_lease.clone());

            self.emit_audit(
                AuditEventType::LeaseDelegated,
                AuditFields {
                    lease_id: Some(child_id.to_string()),
                    agent_fingerprint: Some(parent_fingerprint),
                    credential_ref: Some(parent_credential),
                    detail: Some(format!(
                        "delegated from {} to agent pid={}",
                        parent_lease_id, target_agent.pid
                    )),
                    ..Default::default()
                },
            );

            child_lease
        };

        // Update the agent_leases secondary index outside the lease write lock.
        {
            let mut agent_leases = self.agent_leases.write().await;
            agent_leases
                .entry(target_agent.fingerprint_hash)
                .or_default()
                .push(child_id.clone());
        }

        info!(
            parent_id = %parent_lease_id,
            child_id = %child_id,
            target_pid = target_agent.pid,
            "lease delegated"
        );

        Ok(child_lease)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use cdp_policy::{PolicyConstraints, Scope};
    use crate::Lease;

    const GATE_KEY: &[u8] = b"test-gate-key-for-unit-tests";

    fn test_agent() -> AgentInfo {
        AgentInfo {
            uid: 1000,
            pid: 42,
            binary_path: PathBuf::from("/usr/bin/test-agent"),
            binary_hash: [0xab; 32],
            start_time: 123456789,
            fingerprint_hash: [0xcd; 32],
            agent_id: Some("test-agent".to_string()),
            agent_version: Some("0.1.0".to_string()),
        }
    }

    fn child_agent() -> AgentInfo {
        AgentInfo {
            uid: 1001,
            pid: 99,
            binary_path: PathBuf::from("/usr/bin/child-agent"),
            binary_hash: [0xef; 32],
            start_time: 234567890,
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

    fn parent_scope() -> Scope {
        Scope {
            hosts: vec!["localhost".to_string()],
            methods: vec!["GET".to_string(), "POST".to_string()],
            paths: vec!["/api/".to_string()],
            ttl_seconds: Some(3600),
            ..Default::default()
        }
    }

    fn child_scope() -> Scope {
        Scope {
            hosts: vec!["localhost".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/api/".to_string()],
            ..Default::default()
        }
    }

    fn make_manager() -> Arc<LeaseManager> {
        Arc::new(LeaseManager::new(GATE_KEY.to_vec(), None))
    }

    /// Helper used by manager::tests to create a delegated child lease.
    pub(crate) async fn delegate_child(
        manager: &Arc<LeaseManager>,
        parent: &Lease,
        _parent_agent: &AgentInfo,
    ) -> Lease {
        let child = child_agent();
        manager
            .delegate(&parent.lease_id, &child, child_scope(), 1800, true)
            .await
            .expect("delegation should succeed")
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_delegate_success() {
        let manager = make_manager();
        let agent = test_agent();
        let child = child_agent();

        let parent = manager
            .create_lease(&agent, "cred", parent_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        let child_lease = manager
            .delegate(&parent.lease_id, &child, child_scope(), 1800, true)
            .await
            .unwrap();

        assert_eq!(child_lease.delegation_depth, 1);
        assert_eq!(child_lease.parent_lease_id, Some(parent.lease_id.clone()));
        assert_eq!(child_lease.agent_pid, 99);

        // Verify parent has the child linked.
        let parent_fetched = manager.get_lease(&parent.lease_id).await.unwrap();
        assert!(parent_fetched.child_lease_ids.contains(&child_lease.lease_id));
    }

    #[tokio::test]
    async fn test_delegate_scope_not_subset() {
        let manager = make_manager();
        let agent = test_agent();
        let child = child_agent();

        let parent = manager
            .create_lease(&agent, "cred", parent_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        let bad_scope = Scope {
            hosts: vec!["localhost".to_string(), "evil.example.com".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/api/".to_string()],
            ..Default::default()
        };

        let err = manager
            .delegate(&parent.lease_id, &child, bad_scope, 1800, true)
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::ScopeNotSubset));
    }

    #[tokio::test]
    async fn test_delegate_ttl_exceeds_parent() {
        let manager = make_manager();
        let agent = test_agent();
        let child = child_agent();

        let parent = manager
            .create_lease(&agent, "cred", parent_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        // Request a child TTL of 9999 seconds, which is more than the parent's remaining.
        let err = manager
            .delegate(&parent.lease_id, &child, child_scope(), 9999, true)
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::TtlExceedsParent));
    }

    #[tokio::test]
    async fn test_delegate_depth_exceeded() {
        let manager = make_manager();
        let agent = test_agent();
        let child_a = child_agent();
        let child_b = AgentInfo {
            uid: 1002,
            pid: 100,
            binary_path: PathBuf::from("/usr/bin/child-b"),
            binary_hash: [0xfe; 32],
            start_time: 345678901,
            fingerprint_hash: [0x34; 32],
            agent_id: None,
            agent_version: None,
        };
        let child_c = AgentInfo {
            uid: 1003,
            pid: 101,
            binary_path: PathBuf::from("/usr/bin/child-c"),
            binary_hash: [0xfd; 32],
            start_time: 456789012,
            fingerprint_hash: [0x56; 32],
            agent_id: None,
            agent_version: None,
        };
        let child_d = AgentInfo {
            uid: 1004,
            pid: 102,
            binary_path: PathBuf::from("/usr/bin/child-d"),
            binary_hash: [0xfc; 32],
            start_time: 567890123,
            fingerprint_hash: [0x78; 32],
            agent_id: None,
            agent_version: None,
        };

        // max_depth = 3: depth 1, 2, 3 are allowed; depth 4 should fail.
        let constraints = PolicyConstraints {
            delegation_max_depth: Some(3),
            ..test_constraints()
        };

        let root = manager
            .create_lease(&agent, "cred", parent_scope(), &constraints, "p", "auto")
            .await
            .unwrap();

        let l1 = manager
            .delegate(&root.lease_id, &child_a, child_scope(), 1000, true)
            .await
            .unwrap();
        assert_eq!(l1.delegation_depth, 1);

        let l2 = manager
            .delegate(&l1.lease_id, &child_b, child_scope(), 900, true)
            .await
            .unwrap();
        assert_eq!(l2.delegation_depth, 2);

        let l3 = manager
            .delegate(&l2.lease_id, &child_c, child_scope(), 800, true)
            .await
            .unwrap();
        assert_eq!(l3.delegation_depth, 3);

        // Attempt depth 4 — should fail.
        let err = manager
            .delegate(&l3.lease_id, &child_d, child_scope(), 700, true)
            .await
            .unwrap_err();
        assert!(
            matches!(err, LeaseError::DelegationDepthExceeded(_)),
            "expected DelegationDepthExceeded, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_delegate_not_allowed() {
        let manager = make_manager();
        let agent = test_agent();
        let child = child_agent();

        let constraints = PolicyConstraints {
            delegation_allowed: false,
            ..test_constraints()
        };

        let parent = manager
            .create_lease(&agent, "cred", parent_scope(), &constraints, "p", "auto")
            .await
            .unwrap();

        let err = manager
            .delegate(&parent.lease_id, &child, child_scope(), 1800, true)
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::DelegationNotAllowed));
    }

    #[tokio::test]
    async fn test_delegate_target_not_alive() {
        let manager = make_manager();
        let agent = test_agent();
        let child = child_agent();

        let parent = manager
            .create_lease(&agent, "cred", parent_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        let err = manager
            .delegate(&parent.lease_id, &child, child_scope(), 1800, false)
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::TargetAgentNotAlive));
    }

    #[tokio::test]
    async fn test_revoke_parent_cascades_to_delegated_child() {
        let manager = make_manager();
        let agent = test_agent();
        let child = child_agent();

        let parent = manager
            .create_lease(&agent, "cred", parent_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        let child_lease = manager
            .delegate(&parent.lease_id, &child, child_scope(), 1800, true)
            .await
            .unwrap();

        // Revoke the parent — child should be revoked too.
        manager
            .revoke_lease(&parent.lease_id, "parent revoked")
            .await
            .unwrap();

        let child_fetched = manager.get_lease(&child_lease.lease_id).await.unwrap();
        assert!(
            matches!(child_fetched.status, LeaseStatus::Revoked { .. }),
            "child should be revoked when parent is revoked"
        );
    }
}
