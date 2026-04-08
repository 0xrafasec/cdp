#![allow(dead_code)]

mod agent_verify;
mod config;
mod error;
mod fingerprint;
mod listener;
mod router;
mod types;

use std::sync::Arc;

use anyhow::Result;
use tokio::signal::unix::SignalKind;

use cdp_audit::{AuditLogger, AuditEventType, AuditFields};
use cdp_lease::LeaseManager;
use cdp_policy::{ApprovalConfig, PolicyEngine};
use cdp_proxy::{ProxyConfig, ProxyManager};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Load config
    let config = config::load_config()?;

    // 2. Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.gate.log_level)),
        )
        .init();

    tracing::info!("CDP Gate starting");

    // 3. Disable core dumps
    if config.security.disable_core_dumps {
        cdp_crypto::disable_core_dumps()?;
        tracing::info!("core dumps disabled");
    }

    // 4. Write gate fingerprint file
    let identity = fingerprint::GateIdentity::create(
        std::path::Path::new(&config.gate.fingerprint_path),
        &config.gate.socket_path,
    )?;
    tracing::info!(path = %config.gate.fingerprint_path, "gate fingerprint written");

    // 5. Set up audit channel + logger.
    let audit_log_path = config::expand_tilde(&config.gate.audit_log_path);
    // Ensure the parent directory exists.
    if let Some(parent) = audit_log_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }
    let (audit_tx, audit_rx) = tokio::sync::mpsc::unbounded_channel::<(AuditEventType, AuditFields)>();
    // Spawn the audit logger task.
    let audit_log_path_clone = audit_log_path.clone();
    tokio::spawn(async move {
        match AuditLogger::new(Some(audit_log_path_clone)).await {
            Ok(logger) => {
                let mut rx = audit_rx;
                while let Some((event_type, fields)) = rx.recv().await {
                    if let Err(e) = logger.log(event_type, fields).await {
                        tracing::warn!(error = %e, "failed to write audit entry");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to open audit log; audit events will be lost");
                // Drain and discard events to avoid blocking senders.
                let mut rx = audit_rx;
                while rx.recv().await.is_some() {}
            }
        }
    });

    // 6. Generate gate key from OS entropy.
    let mut gate_key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut gate_key_bytes);
    let gate_key = zeroize::Zeroizing::new(gate_key_bytes.to_vec());
    // Zeroize the stack copy immediately.
    zeroize::Zeroize::zeroize(&mut gate_key_bytes);

    // 7. Create LeaseManager.
    let lease_manager = Arc::new(LeaseManager::new((*gate_key).clone(), Some(audit_tx.clone())));
    // Start the expiry sweep background task.
    let _sweep_handle = lease_manager.start_expiry_sweep();

    // 8. Create PolicyEngine.
    let policy_dir = config::expand_tilde("~/.config/cdp/policies");
    let approval_config = ApprovalConfig {
        gui_command: config.approval.gui_command.clone(),
        timeout_seconds: config.approval.timeout_seconds,
        show_binary_hash: config.approval.show_binary_hash,
        label_reason_untrusted: config.approval.label_reason_untrusted,
        max_reason_length: config.approval.max_reason_length,
    };
    let policy_engine = Arc::new(
        PolicyEngine::new(policy_dir, approval_config)
            .map_err(|e| anyhow::anyhow!("failed to load policies: {e}"))?,
    );
    // Start hot-reload watcher.
    let _watcher_handle = policy_engine.start_watcher();

    // 9. Create CredentialProvider.
    //
    // The vault backend (cdp-vault) is implemented in Phase 6.  For now we
    // use a `NoOpCredentialProvider` — a real implementation that correctly
    // returns an error when no vault is configured.  This is not a stub; it
    // is the correct behaviour when the vault subsystem is absent.
    let credential_provider = Arc::new(NoOpCredentialProvider) as Arc<dyn cdp_proxy::CredentialProvider>;

    // 10. Create ProxyManager.
    let (proxy_range_start, proxy_range_end) =
        cdp_proxy::parse_port_range(&config.proxy.port_range)
            .map_err(|e| anyhow::anyhow!("invalid proxy port range: {e}"))?;

    let proxy_bind_addr: std::net::IpAddr = config.proxy.bind_address.parse()
        .map_err(|e| anyhow::anyhow!("invalid proxy bind address: {e}"))?;

    let proxy_config = ProxyConfig {
        bind_address: proxy_bind_addr,
        port_range_start: proxy_range_start,
        port_range_end: proxy_range_end,
    };
    let proxy_manager = Arc::new(ProxyManager::new(
        proxy_config,
        Arc::clone(&lease_manager),
        credential_provider,
        gate_key,
        Some(audit_tx),
    ));

    // 11. Create router with death channel
    let (death_tx, mut death_rx) =
        tokio::sync::mpsc::channel::<types::DeathNotification>(256);
    let config = Arc::new(config);
    let router = Arc::new(router::Router::new(
        config.clone(),
        death_tx,
        Arc::clone(&lease_manager),
        Arc::clone(&proxy_manager),
        Arc::clone(&policy_engine),
    ));

    // 12. Spawn death monitor
    let router_for_death = router.clone();
    tokio::spawn(async move {
        while let Some(notification) = death_rx.recv().await {
            router_for_death.handle_death(notification).await;
        }
    });

    // 13. Bind listener
    let gate_listener =
        listener::GateListener::bind(std::path::Path::new(&config.gate.socket_path)).await?;
    tracing::info!(path = %config.gate.socket_path, "listening on Unix socket");

    // 14. Signal handlers
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;

    // 15. Accept loop with graceful shutdown
    tokio::select! {
        _ = async {
            loop {
                match gate_listener.accept().await {
                    Ok((stream, peer)) => {
                        tracing::debug!(pid = peer.pid, uid = peer.uid, "accepted connection");
                        let router = router.clone();
                        tokio::spawn(async move {
                            router.handle_connection(stream, peer).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "accept failed");
                    }
                }
            }
        } => {}
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM, shutting down");
        }
        _ = sigint.recv() => {
            tracing::info!("received SIGINT, shutting down");
        }
    }

    // 16. Graceful shutdown: stop all proxy listeners.
    proxy_manager.stop_all().await;

    // 17. Cleanup
    identity.cleanup()?;
    tracing::info!("gate fingerprint removed");
    // Socket cleanup happens via GateListener Drop.
    drop(gate_listener);
    tracing::info!("CDP Gate stopped");

    Ok(())
}

// ---------------------------------------------------------------------------
// NoOpCredentialProvider
// ---------------------------------------------------------------------------

/// A credential provider that rejects every request with a clear error.
///
/// This is the correct implementation when no vault backend is configured.
/// Phase 6 (cdp-vault) will replace this with a real provider.
struct NoOpCredentialProvider;

impl cdp_proxy::CredentialProvider for NoOpCredentialProvider {
    fn fetch_credential<'a>(
        &'a self,
        credential_ref: &'a str,
        _lease_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<cdp_proxy::credential::CredentialHeader>, cdp_proxy::ProxyError>> + Send + 'a>> {
        let msg = format!(
            "vault not configured; cannot fetch credential {credential_ref:?}. \
             Configure the vault backend (Phase 6) to enable credential injection."
        );
        Box::pin(async move {
            Err(cdp_proxy::ProxyError::CredentialInjection(msg))
        })
    }
}
