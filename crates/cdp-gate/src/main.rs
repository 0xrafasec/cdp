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

    // 5. Create router with death channel
    let (death_tx, mut death_rx) =
        tokio::sync::mpsc::channel::<types::DeathNotification>(256);
    let config = Arc::new(config);
    let router = Arc::new(router::Router::new(config.clone(), death_tx));

    // 6. Spawn death monitor
    let router_for_death = router.clone();
    tokio::spawn(async move {
        while let Some(notification) = death_rx.recv().await {
            router_for_death.handle_death(notification).await;
        }
    });

    // 7. Bind listener
    let gate_listener =
        listener::GateListener::bind(std::path::Path::new(&config.gate.socket_path)).await?;
    tracing::info!(path = %config.gate.socket_path, "listening on Unix socket");

    // 8. Signal handlers
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;

    // 9. Accept loop with graceful shutdown
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

    // 10. Cleanup
    identity.cleanup()?;
    tracing::info!("gate fingerprint removed");
    // Socket cleanup happens via GateListener Drop.
    drop(gate_listener);
    tracing::info!("CDP Gate stopped");

    Ok(())
}
