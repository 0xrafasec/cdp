//! Proxy manager — owns the per-lease listener lifecycle.
//!
//! [`ProxyManager`] allocates a port from the configured range for each new
//! lease, starts a per-lease TCP listener, and tears it down when the lease
//! is revoked or expires.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use zeroize::Zeroizing;

use cdp_audit::{AuditEventType, AuditFields};
use cdp_lease::{LeaseId, LeaseManager};

use crate::credential::CredentialProvider;
use crate::http::ProxyServer;
use crate::{ProxyConfig, ProxyError};

// ---------------------------------------------------------------------------
// ListenerHandle
// ---------------------------------------------------------------------------

/// A running per-lease proxy listener.
#[derive(Debug)]
pub struct ListenerHandle {
    /// The local address the listener is bound to.
    pub bind_addr: SocketAddr,
    /// Cancellation token — send `()` or drop to stop the listener task.
    cancel: tokio::sync::oneshot::Sender<()>,
}

impl ListenerHandle {
    /// Stop the listener task.
    pub fn stop(self) {
        // Dropping the sender signals the receiver in the listener task.
        drop(self.cancel);
    }
}

// ---------------------------------------------------------------------------
// ProxyManager
// ---------------------------------------------------------------------------

/// Manages the pool of per-lease proxy listeners.
///
/// Each lease gets exactly one TCP port from the configured range.  The
/// manager tracks which ports are in use and reclaims them when a lease is
/// removed.
pub struct ProxyManager {
    config: ProxyConfig,
    /// Map from LeaseId → (port, handle).
    listeners: Arc<Mutex<HashMap<String, (u16, ListenerHandle)>>>,
    /// Lease store shared with the gate router.
    lease_manager: Arc<LeaseManager>,
    /// Credential back-end; injected into every per-lease proxy server.
    credential_provider: Arc<dyn CredentialProvider>,
    /// Gate HMAC key for lease-token verification.  Zeroized on drop.
    gate_key: Zeroizing<Vec<u8>>,
    /// Optional audit sink forwarded to each proxy server.
    audit_tx: Option<tokio::sync::mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
}

impl ProxyManager {
    /// Create a new manager with the given configuration and shared state.
    pub fn new(
        config: ProxyConfig,
        lease_manager: Arc<LeaseManager>,
        credential_provider: Arc<dyn CredentialProvider>,
        gate_key: Zeroizing<Vec<u8>>,
        audit_tx: Option<tokio::sync::mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
    ) -> Self {
        Self {
            config,
            listeners: Arc::new(Mutex::new(HashMap::new())),
            lease_manager,
            credential_provider,
            gate_key,
            audit_tx,
        }
    }

    /// Start a proxy server for `lease_id`.
    ///
    /// Allocates a port from the configured range, creates a [`ProxyServer`],
    /// spawns it in a Tokio task and stores the shutdown sender so the
    /// listener can be stopped later via [`release_lease`] or [`stop_all`].
    ///
    /// Returns the allocated port number on success.
    pub async fn start_proxy(&self, lease_id: &LeaseId) -> Result<u16, ProxyError> {
        let mut listeners = self.listeners.lock().await;

        // Find a port not currently in use.
        let port = self
            .find_free_port(&listeners)
            .ok_or_else(|| {
                ProxyError::PortExhausted(format!(
                    "all ports in range {}-{} are in use",
                    self.config.port_range_start, self.config.port_range_end
                ))
            })?;

        let bind_addr = SocketAddr::new(self.config.bind_address, port);

        // Create shutdown channel.
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        // Build the proxy server.
        let server = ProxyServer::new(
            lease_id.clone(),
            bind_addr,
            self.gate_key.clone(),
            Arc::clone(&self.lease_manager),
            Arc::clone(&self.credential_provider),
            self.audit_tx.clone(),
        );

        // Spawn the server task.
        let lease_id_str = lease_id.as_str().to_string();
        tokio::spawn(async move {
            if let Err(e) = server.run(cancel_rx).await {
                tracing::error!(
                    lease_id = %lease_id_str,
                    error = %e,
                    "proxy server exited with error"
                );
            }
        });

        let handle = ListenerHandle {
            bind_addr,
            cancel: cancel_tx,
        };
        listeners.insert(lease_id.as_str().to_string(), (port, handle));

        tracing::info!(
            lease_id = %lease_id,
            port,
            "proxy listener started"
        );

        Ok(port)
    }

    /// Allocate a port from the configured range for `lease_id`.
    ///
    /// Inserts a placeholder entry so concurrent calls cannot double-allocate
    /// the same port.  Use [`start_proxy`] for production code which replaces
    /// the placeholder with a real listener.
    ///
    /// Returns the allocated port number, or [`ProxyError::PortExhausted`] if
    /// all ports in the range are in use.
    pub async fn allocate_port(&self, lease_id: &LeaseId) -> Result<u16, ProxyError> {
        let mut listeners = self.listeners.lock().await;

        let port = self
            .find_free_port(&listeners)
            .ok_or_else(|| {
                ProxyError::PortExhausted(format!(
                    "all ports in range {}-{} are in use",
                    self.config.port_range_start, self.config.port_range_end
                ))
            })?;

        let bind_addr = SocketAddr::new(self.config.bind_address, port);
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let handle = ListenerHandle {
            bind_addr,
            cancel: tx,
        };
        listeners.insert(lease_id.as_str().to_string(), (port, handle));
        Ok(port)
    }

    /// Return the port allocated for `lease_id`, or `None` if not found.
    pub async fn port_for_lease(&self, lease_id: &LeaseId) -> Option<u16> {
        let listeners = self.listeners.lock().await;
        listeners.get(lease_id.as_str()).map(|(p, _)| *p)
    }

    /// Release the listener for `lease_id`, freeing the port for reuse.
    ///
    /// Stops the listener task before removing it from the pool.
    pub async fn release_lease(&self, lease_id: &LeaseId) -> bool {
        let mut listeners = self.listeners.lock().await;
        if let Some((_port, handle)) = listeners.remove(lease_id.as_str()) {
            handle.stop();
            true
        } else {
            false
        }
    }

    /// Stop all listeners and clear the pool.
    ///
    /// Each listener's shutdown channel is signalled, causing its task to exit
    /// after finishing any in-flight request.
    pub async fn stop_all(&self) {
        let mut listeners = self.listeners.lock().await;
        let count = listeners.len();
        for (_lease_id, (_port, handle)) in listeners.drain() {
            handle.stop();
        }
        if count > 0 {
            tracing::info!(count, "all proxy listeners stopped");
        }
    }

    /// Return the number of active listeners.
    pub async fn active_count(&self) -> usize {
        self.listeners.lock().await.len()
    }

    /// Bind address for the given lease, or `None` if not allocated.
    pub async fn bind_addr_for_lease(&self, lease_id: &LeaseId) -> Option<SocketAddr> {
        let listeners = self.listeners.lock().await;
        listeners
            .get(lease_id.as_str())
            .map(|(_, h)| h.bind_addr)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Find the first port in the configured range not already in use.
    fn find_free_port(
        &self,
        listeners: &HashMap<String, (u16, ListenerHandle)>,
    ) -> Option<u16> {
        (self.config.port_range_start..=self.config.port_range_end)
            .find(|&port| !listeners.values().any(|(p, _)| *p == port))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the [`SocketAddr`] a proxy listener should bind to for a given lease.
pub fn listener_addr(config: &ProxyConfig, port: u16) -> SocketAddr {
    SocketAddr::new(config.bind_address, port)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::MockCredentialProvider;

    fn test_config() -> ProxyConfig {
        ProxyConfig {
            port_range_start: 20000,
            port_range_end: 20004, // tiny range for testing
            ..Default::default()
        }
    }

    fn make_manager() -> ProxyManager {
        let lease_manager = Arc::new(LeaseManager::new(b"test-key".to_vec(), None));
        let credential_provider = Arc::new(MockCredentialProvider::new());
        ProxyManager::new(
            test_config(),
            lease_manager,
            credential_provider,
            Zeroizing::new(b"test-key".to_vec()),
            None,
        )
    }

    #[tokio::test]
    async fn test_allocate_port_returns_first_available() {
        let mgr = make_manager();
        let lease_id = LeaseId::generate();
        let port = mgr.allocate_port(&lease_id).await.expect("should allocate");
        assert_eq!(port, 20000);
    }

    #[tokio::test]
    async fn test_allocate_different_ports_per_lease() {
        let mgr = make_manager();
        let id1 = LeaseId::generate();
        let id2 = LeaseId::generate();

        let p1 = mgr.allocate_port(&id1).await.expect("port 1");
        let p2 = mgr.allocate_port(&id2).await.expect("port 2");
        assert_ne!(p1, p2);
    }

    #[tokio::test]
    async fn test_port_exhausted() {
        let mgr = make_manager();
        // Allocate all 5 ports (20000-20004).
        for _ in 0..5u16 {
            let id = LeaseId::generate();
            mgr.allocate_port(&id).await.expect("should allocate");
        }
        // Next allocation must fail.
        let id = LeaseId::generate();
        let err = mgr.allocate_port(&id).await.expect_err("must be exhausted");
        assert!(matches!(err, ProxyError::PortExhausted(_)));
    }

    #[tokio::test]
    async fn test_release_frees_port() {
        let mgr = make_manager();
        let id = LeaseId::generate();
        let port = mgr.allocate_port(&id).await.expect("allocate");
        assert_eq!(mgr.active_count().await, 1);

        let released = mgr.release_lease(&id).await;
        assert!(released);
        assert_eq!(mgr.active_count().await, 0);

        // Port should be reusable now.
        let id2 = LeaseId::generate();
        let port2 = mgr.allocate_port(&id2).await.expect("re-allocate");
        assert_eq!(port2, port);
    }

    #[tokio::test]
    async fn test_release_nonexistent_returns_false() {
        let mgr = make_manager();
        let id = LeaseId::generate();
        assert!(!mgr.release_lease(&id).await);
    }

    #[tokio::test]
    async fn test_port_for_lease() {
        let mgr = make_manager();
        let id = LeaseId::generate();
        assert!(mgr.port_for_lease(&id).await.is_none());

        let port = mgr.allocate_port(&id).await.expect("allocate");
        assert_eq!(mgr.port_for_lease(&id).await, Some(port));
    }

    #[test]
    fn test_listener_addr_helper() {
        let cfg = ProxyConfig::default();
        let addr = listener_addr(&cfg, 19500);
        assert_eq!(addr.port(), 19500);
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn test_stop_all_clears_pool() {
        let mgr = make_manager();

        // Allocate a few ports.
        for _ in 0..3 {
            let id = LeaseId::generate();
            mgr.allocate_port(&id).await.expect("allocate");
        }
        assert_eq!(mgr.active_count().await, 3);

        mgr.stop_all().await;
        assert_eq!(mgr.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_stop_all_idempotent_on_empty() {
        let mgr = make_manager();
        // Stopping an empty pool should not panic.
        mgr.stop_all().await;
        assert_eq!(mgr.active_count().await, 0);
    }
}
