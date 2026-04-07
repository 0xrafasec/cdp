//! Agent liveness monitoring — revoke leases when an agent process dies.
//!
//! [`spawn_liveness_handler`] drives the integration between the process
//! death detector (typically a `pidfd`-based watcher in `cdp-gate`) and the
//! lease manager. When a death notice arrives, all leases for the dead agent
//! are revoked via [`LeaseManager::revoke_agent_leases`], which cascades to
//! any delegated children.
//!
//! `cdp-lease` cannot depend on `cdp-gate` (that would be circular), so the
//! death notification type is defined locally here. `cdp-gate` creates its own
//! channel and converts its internal type to [`AgentDeathNotice`] before sending.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::manager::LeaseManager;

// ---------------------------------------------------------------------------
// AgentDeathNotice
// ---------------------------------------------------------------------------

/// Notification sent by the process-death watcher when an agent exits.
///
/// Contains enough information for the lease manager to locate and revoke all
/// leases owned by the dead agent without needing to communicate with the gate.
#[derive(Debug, Clone)]
pub struct AgentDeathNotice {
    /// The OS process ID of the dead agent.
    pub pid: u32,
    /// Composite fingerprint hash used as the agent's primary key in the lease
    /// index: `SHA-256(uid || pid || binary_hash || start_time)`.
    pub fingerprint_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// spawn_liveness_handler
// ---------------------------------------------------------------------------

/// Spawn a task that revokes leases whenever an agent death notice arrives.
///
/// The caller owns the sending end of `rx`'s companion channel; when all
/// senders are dropped the task exits cleanly.
///
/// ## Example wiring (in `cdp-gate`)
/// ```ignore
/// let (death_tx, death_rx) = mpsc::unbounded_channel::<AgentDeathNotice>();
/// let _handle = spawn_liveness_handler(Arc::clone(&lease_manager), death_rx);
/// // Later, on pidfd-triggered event:
/// let _ = death_tx.send(AgentDeathNotice { pid, fingerprint_hash });
/// ```
pub fn spawn_liveness_handler(
    manager: Arc<LeaseManager>,
    mut rx: mpsc::UnboundedReceiver<AgentDeathNotice>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("liveness handler started");
        while let Some(notice) = rx.recv().await {
            info!(
                pid = notice.pid,
                "agent death notice received; revoking leases"
            );
            match manager
                .revoke_agent_leases(&notice.fingerprint_hash, "agent process died")
                .await
            {
                Ok(revoked) => {
                    if revoked.is_empty() {
                        info!(pid = notice.pid, "no active leases to revoke for dead agent");
                    } else {
                        info!(
                            pid = notice.pid,
                            count = revoked.len(),
                            "revoked leases for dead agent"
                        );
                    }
                }
                Err(e) => {
                    error!(
                        pid = notice.pid,
                        error = %e,
                        "failed to revoke leases for dead agent"
                    );
                }
            }
        }
        warn!("liveness handler exiting: all senders dropped");
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use cdp_policy::{AgentInfo, PolicyConstraints, Scope};

    use crate::{manager::LeaseManager, types::LeaseStatus};

    const GATE_KEY: &[u8] = b"test-gate-key-for-unit-tests";

    fn make_manager() -> Arc<LeaseManager> {
        Arc::new(LeaseManager::new(GATE_KEY.to_vec(), None))
    }

    fn agent_with_fingerprint(fingerprint: [u8; 32], pid: u32) -> AgentInfo {
        AgentInfo {
            uid: 1000,
            pid,
            binary_path: PathBuf::from("/usr/bin/test-agent"),
            binary_hash: [0xab; 32],
            start_time: 123456789,
            fingerprint_hash: fingerprint,
            agent_id: None,
            agent_version: None,
        }
    }

    fn test_scope() -> Scope {
        Scope {
            hosts: vec!["localhost".to_string()],
            methods: vec!["GET".to_string()],
            ttl_seconds: Some(3600),
            ..Default::default()
        }
    }

    fn test_constraints() -> PolicyConstraints {
        PolicyConstraints {
            max_ttl_seconds: Some(3600),
            max_renewals: Some(3),
            max_cumulative_ttl_seconds: Some(14400),
            renewable: true,
            delegation_allowed: false,
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_agent_death_revokes_leases() {
        let manager = make_manager();
        let fingerprint = [0xaa; 32];
        let agent = agent_with_fingerprint(fingerprint, 100);

        let l1 = manager
            .create_lease(&agent, "cred-1", test_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();
        let l2 = manager
            .create_lease(&agent, "cred-2", test_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        let (tx, rx) = mpsc::unbounded_channel::<AgentDeathNotice>();
        let handle = spawn_liveness_handler(Arc::clone(&manager), rx);

        tx.send(AgentDeathNotice {
            pid: 100,
            fingerprint_hash: fingerprint,
        })
        .unwrap();

        // Drop the sender so the handler exits cleanly.
        drop(tx);
        handle.await.unwrap();

        let f1 = manager.get_lease(&l1.lease_id).await.unwrap();
        let f2 = manager.get_lease(&l2.lease_id).await.unwrap();
        assert!(
            matches!(f1.status, LeaseStatus::Revoked { .. }),
            "lease 1 should be revoked after agent death"
        );
        assert!(
            matches!(f2.status, LeaseStatus::Revoked { .. }),
            "lease 2 should be revoked after agent death"
        );
    }

    #[tokio::test]
    async fn test_death_notice_only_affects_target_agent() {
        let manager = make_manager();
        let fp_a = [0xaa; 32];
        let fp_b = [0xbb; 32];

        let agent_a = agent_with_fingerprint(fp_a, 100);
        let agent_b = agent_with_fingerprint(fp_b, 200);

        let la = manager
            .create_lease(&agent_a, "cred-a", test_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();
        let lb = manager
            .create_lease(&agent_b, "cred-b", test_scope(), &test_constraints(), "p", "auto")
            .await
            .unwrap();

        let (tx, rx) = mpsc::unbounded_channel::<AgentDeathNotice>();
        let handle = spawn_liveness_handler(Arc::clone(&manager), rx);

        // Only kill agent A.
        tx.send(AgentDeathNotice {
            pid: 100,
            fingerprint_hash: fp_a,
        })
        .unwrap();

        drop(tx);
        handle.await.unwrap();

        let fa = manager.get_lease(&la.lease_id).await.unwrap();
        let fb = manager.get_lease(&lb.lease_id).await.unwrap();

        assert!(
            matches!(fa.status, LeaseStatus::Revoked { .. }),
            "agent A's lease should be revoked"
        );
        assert_eq!(
            fb.status,
            LeaseStatus::Active,
            "agent B's lease should remain active"
        );
    }
}
