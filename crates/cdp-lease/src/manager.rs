//! Lease lifecycle manager: create, renew, revoke, use, and expire leases.
//!
//! [`LeaseManager`] is the central authority for all lease state. It owns the
//! in-memory lease store and enforces every protocol invariant on mutation:
//! bounded renewals, cumulative-TTL caps, request limits, and cascading
//! revocation of child leases.

use std::{collections::HashMap, sync::Arc};

use chrono::{Duration, Utc};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, warn};

use cdp_audit::{AuditEventType, AuditFields};
use cdp_policy::{AgentInfo, PolicyConstraints, Scope};

use crate::{
    LeaseError, channel_bind, dns_pin,
    types::{Lease, LeaseId, LeaseStatus},
};

// ---------------------------------------------------------------------------
// LeaseManager
// ---------------------------------------------------------------------------

/// Central manager for all lease lifecycle operations.
///
/// Holds the in-memory lease store (`leases`) and a secondary index
/// (`agent_leases`) that maps agent fingerprint hashes to their active lease
/// IDs. Both are protected by independent `RwLock`s so read-heavy workloads
/// (e.g. `get_lease`) do not block each other.
///
/// An optional `audit_tx` channel is used to emit audit events; if `None`,
/// audit events are silently dropped (useful in tests that don't need a log).
pub struct LeaseManager {
    pub(crate) leases: Arc<RwLock<HashMap<LeaseId, Lease>>>,
    pub(crate) agent_leases: Arc<RwLock<HashMap<[u8; 32], Vec<LeaseId>>>>,
    pub(crate) gate_key: Vec<u8>,
    pub(crate) audit_tx: Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
}

impl LeaseManager {
    /// Create a new `LeaseManager` with the given HMAC gate key.
    ///
    /// `audit_tx` may be `None` when the caller does not need audit events
    /// (e.g. unit tests). Production code should always wire up a real sender.
    pub fn new(
        gate_key: Vec<u8>,
        audit_tx: Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
    ) -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
            agent_leases: Arc::new(RwLock::new(HashMap::new())),
            gate_key,
            audit_tx,
        }
    }

    // -----------------------------------------------------------------------
    // create_lease
    // -----------------------------------------------------------------------

    /// Create a new root lease for `agent_info`.
    ///
    /// DNS pinning is performed before any lock is taken so that the async
    /// resolution does not hold a write lock. All computed values are inserted
    /// atomically under a single write lock.
    pub async fn create_lease(
        &self,
        agent_info: &AgentInfo,
        credential_ref: &str,
        granted_scope: Scope,
        constraints: &PolicyConstraints,
        policy_name: &str,
        approval_method: &str,
    ) -> Result<Lease, LeaseError> {
        let lease_id = LeaseId::generate();
        let cb_nonce = channel_bind::generate_nonce();

        // Resolve DNS before acquiring any lock.
        let dns_pinned_ips = dns_pin::pin_dns(&granted_scope.hosts).await?;

        // Compute lease parameters.
        let ttl_seconds = granted_scope
            .ttl_seconds
            .or(constraints.max_ttl_seconds)
            .unwrap_or(3600);

        let max_requests = granted_scope
            .max_requests
            .or(constraints.max_requests_per_lease);

        let max_renewals = constraints.max_renewals.unwrap_or(3);
        let max_cumulative_ttl_seconds = constraints.max_cumulative_ttl_seconds.unwrap_or(14400);

        let follow_redirects = granted_scope
            .network
            .as_ref()
            .map(|n| n.follow_redirects)
            .unwrap_or(false);

        // Generate lease token: covers lease_id, agent fingerprint, and channel-binding nonce.
        let lease_token = cdp_crypto::generate_lease_token(
            &self.gate_key,
            lease_id.as_str(),
            &agent_info.fingerprint_hash,
            &cb_nonce,
        );

        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(ttl_seconds as i64);

        let lease = Lease {
            lease_id: lease_id.clone(),
            credential_ref: credential_ref.to_string(),
            policy_name: policy_name.to_string(),
            approval_method: approval_method.to_string(),
            agent_fingerprint_hash: agent_info.fingerprint_hash,
            agent_binary_path: agent_info.binary_path.to_string_lossy().into_owned(),
            agent_uid: agent_info.uid,
            agent_pid: agent_info.pid,
            granted_scope,
            lease_token,
            channel_binding_nonce: cb_nonce,
            dns_pinned_ips,
            status: LeaseStatus::Active,
            created_at,
            expires_at,
            ttl_seconds,
            cumulative_ttl_seconds: ttl_seconds,
            max_requests,
            requests_used: 0,
            renewals_used: 0,
            max_renewals,
            max_cumulative_ttl_seconds,
            renewable: constraints.renewable,
            parent_lease_id: None,
            child_lease_ids: Vec::new(),
            delegation_depth: 0,
            delegation_allowed: constraints.delegation_allowed,
            delegation_max_depth: constraints.delegation_max_depth,
            follow_redirects,
        };

        // Insert under a write lock.
        {
            let mut leases = self.leases.write().await;
            leases.insert(lease_id.clone(), lease.clone());
        }
        {
            let mut agent_leases = self.agent_leases.write().await;
            agent_leases
                .entry(agent_info.fingerprint_hash)
                .or_default()
                .push(lease_id.clone());
        }

        self.emit_audit(
            AuditEventType::LeaseGranted,
            AuditFields {
                lease_id: Some(lease_id.to_string()),
                agent_fingerprint: Some(hex_encode(&agent_info.fingerprint_hash)),
                agent_binary_path: Some(agent_info.binary_path.to_string_lossy().into_owned()),
                credential_ref: Some(credential_ref.to_string()),
                policy_matched: Some(policy_name.to_string()),
                approval_method: Some(approval_method.to_string()),
                ..Default::default()
            },
        );

        info!(lease_id = %lease_id, agent_pid = agent_info.pid, "lease granted");
        Ok(lease)
    }

    // -----------------------------------------------------------------------
    // renew_lease
    // -----------------------------------------------------------------------

    /// Extend the TTL of an active lease by `extend_seconds`.
    ///
    /// Enforces:
    /// - Lease must be `Active` and not yet expired.
    /// - `renewable` must be `true`.
    /// - `renewals_used < max_renewals`.
    /// - `cumulative_ttl_seconds + extend_seconds <= max_cumulative_ttl_seconds`.
    pub async fn renew_lease(
        &self,
        lease_id: &LeaseId,
        extend_seconds: u64,
    ) -> Result<(), LeaseError> {
        let mut leases = self.leases.write().await;
        let lease = leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::NotFound(lease_id.to_string()))?;

        if lease.status != LeaseStatus::Active {
            return Err(LeaseError::NotActive);
        }
        if lease.is_expired() {
            return Err(LeaseError::Expired(lease_id.to_string()));
        }
        if !lease.renewable {
            return Err(LeaseError::NotRenewable);
        }
        if lease.renewals_used >= lease.max_renewals {
            return Err(LeaseError::MaxRenewalsExceeded(lease.max_renewals));
        }
        if lease.cumulative_ttl_seconds + extend_seconds > lease.max_cumulative_ttl_seconds {
            return Err(LeaseError::MaxCumulativeTtlExceeded(
                lease.max_cumulative_ttl_seconds,
            ));
        }

        lease.expires_at += Duration::seconds(extend_seconds as i64);
        lease.cumulative_ttl_seconds += extend_seconds;
        lease.renewals_used += 1;

        let fingerprint = hex_encode(&lease.agent_fingerprint_hash);
        let credential_ref = lease.credential_ref.clone();
        drop(leases);

        self.emit_audit(
            AuditEventType::LeaseRenewed,
            AuditFields {
                lease_id: Some(lease_id.to_string()),
                agent_fingerprint: Some(fingerprint),
                credential_ref: Some(credential_ref),
                detail: Some(format!("extended by {extend_seconds}s")),
                ..Default::default()
            },
        );

        debug!(lease_id = %lease_id, extend_seconds, "lease renewed");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // revoke_lease
    // -----------------------------------------------------------------------

    /// Revoke a lease and all its descendants (cascading revocation).
    ///
    /// Children are revoked depth-first before the parent so that the audit log
    /// records child revocations first, making forensic reconstruction easier.
    pub async fn revoke_lease(&self, lease_id: &LeaseId, reason: &str) -> Result<(), LeaseError> {
        let mut leases = self.leases.write().await;
        let mut agent_leases = self.agent_leases.write().await;

        if !leases.contains_key(lease_id) {
            return Err(LeaseError::NotFound(lease_id.to_string()));
        }

        // Collect all descendants (children of children, etc.) first.
        let descendants = collect_descendants(&leases, lease_id);

        // Revoke children first (depth-first order from collect_descendants).
        for child_id in &descendants {
            if let Some(child) = leases.get_mut(child_id) {
                let fp = child.agent_fingerprint_hash;
                child.status = LeaseStatus::Revoked {
                    reason: reason.to_string(),
                };
                remove_from_agent_index(&mut agent_leases, &fp, child_id);
                self.emit_audit(
                    AuditEventType::LeaseRevoked,
                    AuditFields {
                        lease_id: Some(child_id.to_string()),
                        agent_fingerprint: Some(hex_encode(&fp)),
                        detail: Some(format!("cascading revocation: {reason}")),
                        ..Default::default()
                    },
                );
                warn!(lease_id = %child_id, reason, "lease revoked (cascade)");
            }
        }

        // Revoke the root lease.
        if let Some(root) = leases.get_mut(lease_id) {
            let fp = root.agent_fingerprint_hash;
            root.status = LeaseStatus::Revoked {
                reason: reason.to_string(),
            };
            remove_from_agent_index(&mut agent_leases, &fp, lease_id);
            self.emit_audit(
                AuditEventType::LeaseRevoked,
                AuditFields {
                    lease_id: Some(lease_id.to_string()),
                    agent_fingerprint: Some(hex_encode(&fp)),
                    detail: Some(reason.to_string()),
                    ..Default::default()
                },
            );
            warn!(lease_id = %lease_id, reason, "lease revoked");
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // use_lease
    // -----------------------------------------------------------------------

    /// Record one proxied-request use against the lease and return a snapshot.
    ///
    /// Fails if:
    /// - The lease is not found.
    /// - The lease is not active or is expired.
    /// - `max_requests` is set and `requests_used >= max_requests`.
    pub async fn use_lease(&self, lease_id: &LeaseId) -> Result<Lease, LeaseError> {
        let mut leases = self.leases.write().await;
        let lease = leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::NotFound(lease_id.to_string()))?;

        if lease.status != LeaseStatus::Active {
            return Err(LeaseError::NotActive);
        }
        if lease.is_expired() {
            return Err(LeaseError::Expired(lease_id.to_string()));
        }
        if let Some(max) = lease.max_requests
            && lease.requests_used >= max
        {
            return Err(LeaseError::MaxRequestsExceeded(max));
        }

        lease.requests_used += 1;
        let snapshot = lease.clone();
        drop(leases);

        self.emit_audit(
            AuditEventType::LeaseUsed,
            AuditFields {
                lease_id: Some(lease_id.to_string()),
                agent_fingerprint: Some(hex_encode(&snapshot.agent_fingerprint_hash)),
                credential_ref: Some(snapshot.credential_ref.clone()),
                detail: Some(format!("request {}", snapshot.requests_used)),
                ..Default::default()
            },
        );

        Ok(snapshot)
    }

    // -----------------------------------------------------------------------
    // get_lease
    // -----------------------------------------------------------------------

    /// Return a clone of the lease without mutating any state.
    pub async fn get_lease(&self, lease_id: &LeaseId) -> Result<Lease, LeaseError> {
        let leases = self.leases.read().await;
        leases
            .get(lease_id)
            .cloned()
            .ok_or_else(|| LeaseError::NotFound(lease_id.to_string()))
    }

    // -----------------------------------------------------------------------
    // revoke_agent_leases
    // -----------------------------------------------------------------------

    /// Revoke all leases belonging to the agent identified by `fingerprint_hash`.
    ///
    /// Returns the list of revoked lease IDs (including cascaded children).
    pub async fn revoke_agent_leases(
        &self,
        fingerprint_hash: &[u8; 32],
        reason: &str,
    ) -> Result<Vec<LeaseId>, LeaseError> {
        // Collect lease IDs under a read lock first.
        let lease_ids: Vec<LeaseId> = {
            let agent_leases = self.agent_leases.read().await;
            agent_leases
                .get(fingerprint_hash)
                .cloned()
                .unwrap_or_default()
        };

        let mut revoked = Vec::new();

        for lease_id in lease_ids {
            // Only revoke root leases here; revoke_lease cascades to children.
            let is_root = {
                let leases = self.leases.read().await;
                leases
                    .get(&lease_id)
                    .map(|l| l.parent_lease_id.is_none())
                    .unwrap_or(false)
            };
            if is_root {
                // Collect descendants before revoking for the return list.
                let descendants = {
                    let leases = self.leases.read().await;
                    collect_descendants(&leases, &lease_id)
                };
                revoked.push(lease_id.clone());
                revoked.extend(descendants);
                self.revoke_lease(&lease_id, reason).await?;
            }
        }

        // Clean up the agent entry from the index.
        {
            let mut agent_leases = self.agent_leases.write().await;
            agent_leases.remove(fingerprint_hash);
        }

        Ok(revoked)
    }

    // -----------------------------------------------------------------------
    // start_expiry_sweep
    // -----------------------------------------------------------------------

    /// Spawn a background task that marks expired leases every 5 seconds.
    ///
    /// The returned `JoinHandle` can be aborted to stop the sweep. The
    /// task holds a clone of the `Arc<Self>` so it does not prevent the
    /// manager from being dropped via any other path.
    pub fn start_expiry_sweep(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                manager.sweep_expired().await;
            }
        })
    }

    /// Inner expiry sweep — separated so it can be called directly in tests.
    pub(crate) async fn sweep_expired(&self) {
        let now = Utc::now();
        let mut leases = self.leases.write().await;
        let mut agent_leases = self.agent_leases.write().await;

        let expired_ids: Vec<LeaseId> = leases
            .iter()
            .filter_map(|(id, lease)| {
                if lease.status == LeaseStatus::Active && lease.expires_at < now {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        for lease_id in expired_ids {
            if let Some(lease) = leases.get_mut(&lease_id) {
                let fp = lease.agent_fingerprint_hash;
                let credential_ref = lease.credential_ref.clone();
                lease.status = LeaseStatus::Expired;
                remove_from_agent_index(&mut agent_leases, &fp, &lease_id);
                self.emit_audit(
                    AuditEventType::LeaseExpired,
                    AuditFields {
                        lease_id: Some(lease_id.to_string()),
                        agent_fingerprint: Some(hex_encode(&fp)),
                        credential_ref: Some(credential_ref),
                        ..Default::default()
                    },
                );
                debug!(lease_id = %lease_id, "lease expired (sweep)");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Send an audit event if the channel is connected.
    ///
    /// Send errors (e.g. receiver dropped) are logged as warnings and silently
    /// ignored — the audit path must not affect correctness of lease operations.
    pub(crate) fn emit_audit(&self, event: AuditEventType, fields: AuditFields) {
        if let Some(tx) = &self.audit_tx
            && tx.send((event, fields)).is_err()
        {
            warn!("audit channel closed; event dropped");
        }
    }
}

// ---------------------------------------------------------------------------
// Module-level helpers (used by delegation.rs too)
// ---------------------------------------------------------------------------

/// Collect all descendant lease IDs of `root` in depth-first order.
///
/// The root itself is **not** included in the result. The traversal uses an
/// explicit stack to avoid recursion-depth issues on deep delegation chains.
pub(crate) fn collect_descendants(
    leases: &HashMap<LeaseId, Lease>,
    root: &LeaseId,
) -> Vec<LeaseId> {
    let mut result = Vec::new();
    let mut stack: Vec<LeaseId> = leases
        .get(root)
        .map(|l| l.child_lease_ids.clone())
        .unwrap_or_default();

    while let Some(id) = stack.pop() {
        if let Some(lease) = leases.get(&id) {
            // Push children so they are visited before siblings.
            for child in lease.child_lease_ids.iter().rev() {
                stack.push(child.clone());
            }
        }
        result.push(id);
    }

    result
}

/// Remove a single `lease_id` from the per-agent secondary index.
pub(crate) fn remove_from_agent_index(
    agent_leases: &mut HashMap<[u8; 32], Vec<LeaseId>>,
    fingerprint: &[u8; 32],
    lease_id: &LeaseId,
) {
    if let Some(ids) = agent_leases.get_mut(fingerprint) {
        ids.retain(|id| id != lease_id);
        if ids.is_empty() {
            agent_leases.remove(fingerprint);
        }
    }
}

/// Encode a byte slice as a lowercase hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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

    fn test_scope() -> Scope {
        Scope {
            hosts: vec!["localhost".to_string()],
            methods: vec!["GET".to_string()],
            paths: vec!["/api/".to_string()],
            ttl_seconds: Some(3600),
            ..Default::default()
        }
    }

    fn make_manager() -> LeaseManager {
        LeaseManager::new(GATE_KEY.to_vec(), None)
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_lease() {
        let manager = make_manager();
        let agent = test_agent();
        let constraints = test_constraints();

        let lease = manager
            .create_lease(
                &agent,
                "cred-001",
                test_scope(),
                &constraints,
                "test-policy",
                "auto",
            )
            .await
            .expect("create_lease should succeed");

        assert_eq!(lease.credential_ref, "cred-001");
        assert_eq!(lease.policy_name, "test-policy");
        assert_eq!(lease.approval_method, "auto");
        assert_eq!(lease.agent_pid, 42);
        assert_eq!(lease.agent_uid, 1000);
        assert_eq!(lease.agent_fingerprint_hash, [0xcd; 32]);
        assert_eq!(lease.status, LeaseStatus::Active);
        assert_eq!(lease.renewals_used, 0);
        assert_eq!(lease.requests_used, 0);
        assert!(!lease.lease_token.is_empty());
        assert!(lease.is_active());

        // Verify it is in the store.
        let fetched = manager.get_lease(&lease.lease_id).await.unwrap();
        assert_eq!(fetched.lease_id, lease.lease_id);
    }

    #[tokio::test]
    async fn test_renew_lease_success() {
        let manager = make_manager();
        let agent = test_agent();
        let lease = manager
            .create_lease(
                &agent,
                "cred-001",
                test_scope(),
                &test_constraints(),
                "p",
                "auto",
            )
            .await
            .unwrap();

        let original_expires = lease.expires_at;
        manager.renew_lease(&lease.lease_id, 600).await.unwrap();

        let renewed = manager.get_lease(&lease.lease_id).await.unwrap();
        assert_eq!(renewed.renewals_used, 1);
        assert_eq!(
            renewed.cumulative_ttl_seconds,
            lease.cumulative_ttl_seconds + 600
        );
        assert!(renewed.expires_at > original_expires);
    }

    #[tokio::test]
    async fn test_renew_three_times_fourth_fails() {
        let manager = make_manager();
        let agent = test_agent();
        let constraints = PolicyConstraints {
            max_renewals: Some(3),
            max_cumulative_ttl_seconds: Some(14400),
            ..test_constraints()
        };
        let lease = manager
            .create_lease(&agent, "cred", test_scope(), &constraints, "p", "auto")
            .await
            .unwrap();

        for _ in 0..3 {
            manager.renew_lease(&lease.lease_id, 100).await.unwrap();
        }

        let err = manager.renew_lease(&lease.lease_id, 100).await.unwrap_err();
        assert!(
            matches!(err, LeaseError::MaxRenewalsExceeded(3)),
            "expected MaxRenewalsExceeded(3), got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_renew_cumulative_ttl_exceeded() {
        let manager = make_manager();
        let agent = test_agent();
        let constraints = PolicyConstraints {
            max_ttl_seconds: Some(100),
            max_cumulative_ttl_seconds: Some(200),
            max_renewals: Some(10),
            ..test_constraints()
        };
        let scope = Scope {
            hosts: vec!["localhost".to_string()],
            ttl_seconds: Some(100),
            ..Default::default()
        };
        let lease = manager
            .create_lease(&agent, "cred", scope, &constraints, "p", "auto")
            .await
            .unwrap();

        // 100 + 150 > 200 → should fail.
        let err = manager.renew_lease(&lease.lease_id, 150).await.unwrap_err();
        assert!(
            matches!(err, LeaseError::MaxCumulativeTtlExceeded(200)),
            "expected MaxCumulativeTtlExceeded(200), got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_renew_not_renewable() {
        let manager = make_manager();
        let agent = test_agent();
        let constraints = PolicyConstraints {
            renewable: false,
            ..test_constraints()
        };
        let lease = manager
            .create_lease(&agent, "cred", test_scope(), &constraints, "p", "auto")
            .await
            .unwrap();

        let err = manager.renew_lease(&lease.lease_id, 100).await.unwrap_err();
        assert!(
            matches!(err, LeaseError::NotRenewable),
            "expected NotRenewable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_use_lease_increments_counter() {
        let manager = make_manager();
        let agent = test_agent();
        let lease = manager
            .create_lease(
                &agent,
                "cred",
                test_scope(),
                &test_constraints(),
                "p",
                "auto",
            )
            .await
            .unwrap();

        let used = manager.use_lease(&lease.lease_id).await.unwrap();
        assert_eq!(used.requests_used, 1);
    }

    #[tokio::test]
    async fn test_use_lease_max_requests_exceeded() {
        let manager = make_manager();
        let agent = test_agent();
        let scope = Scope {
            hosts: vec!["localhost".to_string()],
            max_requests: Some(2),
            ..Default::default()
        };
        let lease = manager
            .create_lease(&agent, "cred", scope, &test_constraints(), "p", "auto")
            .await
            .unwrap();

        manager.use_lease(&lease.lease_id).await.unwrap();
        manager.use_lease(&lease.lease_id).await.unwrap();

        let err = manager.use_lease(&lease.lease_id).await.unwrap_err();
        assert!(
            matches!(err, LeaseError::MaxRequestsExceeded(2)),
            "expected MaxRequestsExceeded(2), got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_revoke_lease() {
        let manager = make_manager();
        let agent = test_agent();
        let lease = manager
            .create_lease(
                &agent,
                "cred",
                test_scope(),
                &test_constraints(),
                "p",
                "auto",
            )
            .await
            .unwrap();

        manager
            .revoke_lease(&lease.lease_id, "test revocation")
            .await
            .unwrap();

        let fetched = manager.get_lease(&lease.lease_id).await.unwrap();
        assert!(
            matches!(fetched.status, LeaseStatus::Revoked { reason } if reason == "test revocation"),
            "expected Revoked status"
        );
    }

    #[tokio::test]
    async fn test_revoke_cascades_to_children() {
        use crate::delegation::tests::delegate_child;

        let manager = Arc::new(make_manager());
        let agent = test_agent();
        let parent = manager
            .create_lease(
                &agent,
                "cred",
                test_scope(),
                &test_constraints(),
                "p",
                "auto",
            )
            .await
            .unwrap();

        let child = delegate_child(&manager, &parent, &agent).await;

        manager
            .revoke_lease(&parent.lease_id, "cascade test")
            .await
            .unwrap();

        let parent_fetched = manager.get_lease(&parent.lease_id).await.unwrap();
        let child_fetched = manager.get_lease(&child.lease_id).await.unwrap();

        assert!(matches!(parent_fetched.status, LeaseStatus::Revoked { .. }));
        assert!(matches!(child_fetched.status, LeaseStatus::Revoked { .. }));
    }

    #[tokio::test]
    async fn test_get_lease() {
        let manager = make_manager();
        let agent = test_agent();
        let lease = manager
            .create_lease(
                &agent,
                "cred-abc",
                test_scope(),
                &test_constraints(),
                "pol",
                "auto",
            )
            .await
            .unwrap();

        let fetched = manager.get_lease(&lease.lease_id).await.unwrap();
        assert_eq!(fetched.credential_ref, "cred-abc");
        assert_eq!(fetched.lease_id, lease.lease_id);
    }

    #[tokio::test]
    async fn test_revoke_agent_leases() {
        let manager = make_manager();
        let agent = test_agent();

        let l1 = manager
            .create_lease(
                &agent,
                "cred-1",
                test_scope(),
                &test_constraints(),
                "p",
                "auto",
            )
            .await
            .unwrap();
        let l2 = manager
            .create_lease(
                &agent,
                "cred-2",
                test_scope(),
                &test_constraints(),
                "p",
                "auto",
            )
            .await
            .unwrap();

        let revoked = manager
            .revoke_agent_leases(&agent.fingerprint_hash, "agent killed")
            .await
            .unwrap();

        assert!(revoked.contains(&l1.lease_id));
        assert!(revoked.contains(&l2.lease_id));

        let f1 = manager.get_lease(&l1.lease_id).await.unwrap();
        let f2 = manager.get_lease(&l2.lease_id).await.unwrap();
        assert!(matches!(f1.status, LeaseStatus::Revoked { .. }));
        assert!(matches!(f2.status, LeaseStatus::Revoked { .. }));
    }

    #[tokio::test]
    async fn test_expiry_sweep() {
        let manager = Arc::new(make_manager());
        let agent = test_agent();
        // Create a lease that expires in 1 second.
        let scope = Scope {
            hosts: vec!["localhost".to_string()],
            ttl_seconds: Some(1),
            ..Default::default()
        };
        let constraints = PolicyConstraints {
            max_ttl_seconds: Some(1),
            max_cumulative_ttl_seconds: Some(14400),
            ..test_constraints()
        };
        let lease = manager
            .create_lease(&agent, "cred", scope, &constraints, "p", "auto")
            .await
            .unwrap();

        // Wait for the lease to expire, then trigger a sweep directly.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        manager.sweep_expired().await;

        let fetched = manager.get_lease(&lease.lease_id).await.unwrap();
        assert_eq!(fetched.status, LeaseStatus::Expired);
    }
}
