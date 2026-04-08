//! Top-level CDP client — gate discovery, connection, and agent registration.

use std::path::Path;

use serde_json::json;
use tracing::instrument;

use crate::discovery::{self, GateFingerprint};
use crate::session::Session;
use crate::transport::Transport;
use crate::types::RegisterResult;
use crate::{CdpError, Result};

/// Entry point for the CDP SDK.
///
/// `CdpClient` handles gate discovery, connection, and registration. After a
/// successful `register()` call the caller receives a [`Session`] that can be
/// used to request credential leases.
#[derive(Debug)]
pub struct CdpClient {
    fingerprint: GateFingerprint,
    transport: Transport,
}

impl CdpClient {
    /// Discover the gate automatically and connect to it.
    ///
    /// Reads `~/.config/cdp/gate.fingerprint` (or `CDP_GATE_SOCKET` env var),
    /// connects to the Unix socket, and verifies gate identity via
    /// `SO_PEERCRED`.
    #[instrument(name = "CdpClient::discover")]
    pub async fn discover() -> Result<Self> {
        let fingerprint = discovery::discover()?;
        Self::connect_with_fingerprint(fingerprint).await
    }

    /// Connect directly to the gate at `socket_path`, skipping automatic
    /// discovery. Identity verification is skipped (gate_pid is set to 0).
    #[instrument(name = "CdpClient::connect", skip(socket_path))]
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let fingerprint = GateFingerprint {
            gate_pid: 0,
            gate_binary_hash: String::new(),
            public_key: String::new(),
            socket_path: socket_path.to_string_lossy().into_owned(),
            started_at: String::new(),
        };
        Self::connect_with_fingerprint(fingerprint).await
    }

    /// Register the calling agent with the gate.
    ///
    /// On success returns a [`Session`] containing the session token and
    /// agent fingerprint.
    ///
    /// # Parameters
    /// - `agent_id` — stable, human-readable identifier for this agent.
    /// - `agent_version` — semver string for the agent binary.
    /// - `capabilities` — list of capability strings the agent intends to use.
    #[instrument(name = "CdpClient::register", skip(self))]
    pub async fn register(
        mut self,
        agent_id: &str,
        agent_version: &str,
        capabilities: &[&str],
    ) -> Result<Session> {
        let params = json!({
            "agent_id": agent_id,
            "agent_version": agent_version,
            "capabilities": capabilities,
        });

        let result_value = self.transport.send("cdp.register", params).await?;
        let result: RegisterResult = serde_json::from_value(result_value)
            .map_err(|e| CdpError::MalformedResponse(format!("invalid register response: {e}")))?;

        if result.status != "registered" {
            return Err(CdpError::MalformedResponse(format!(
                "unexpected register status: {}",
                result.status
            )));
        }

        tracing::info!(
            agent_fingerprint = %result.agent_fingerprint,
            capabilities_granted = ?result.capabilities_granted,
            "registered with gate"
        );

        Ok(Session::new(
            self.transport,
            result.session_token,
            result.agent_fingerprint,
        ))
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    async fn connect_with_fingerprint(fingerprint: GateFingerprint) -> Result<Self> {
        let socket_path = std::path::Path::new(&fingerprint.socket_path);

        // Verify gate identity synchronously before the async connection (we
        // need a blocking UnixStream for SO_PEERCRED, then re-connect async).
        if fingerprint.gate_pid != 0 {
            let blocking_stream = std::os::unix::net::UnixStream::connect(socket_path)
                .map_err(|e| CdpError::Connection(format!("{}: {e}", socket_path.display())))?;
            discovery::verify_gate(&blocking_stream, &fingerprint)?;
        }

        let transport = Transport::connect(socket_path).await?;
        Ok(Self {
            fingerprint,
            transport,
        })
    }

    /// Return the fingerprint of the connected gate.
    pub fn fingerprint(&self) -> &GateFingerprint {
        &self.fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn temp_socket_path() -> std::path::PathBuf {
        let id = uuid::Uuid::new_v4();
        std::env::temp_dir().join(format!("cdp-client-test-{id}.sock"))
    }

    /// Spawns a mock gate that responds to a single `cdp.register` call.
    async fn mock_gate_register(listener: UnixListener) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = json!({
                "jsonrpc": "2.0",
                "result": {
                    "status": "registered",
                    "agent_fingerprint": "fp-abc123",
                    "session_token": "tok-xyz",
                    "capabilities_granted": ["api:read"]
                },
                "id": 1
            });
            write_half
                .write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes())
                .await
                .unwrap();
        })
    }

    #[tokio::test]
    async fn connect_and_register_succeeds() {
        let socket_path = temp_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _gate = mock_gate_register(listener).await;

        let client = CdpClient::connect(&socket_path).await.unwrap();
        let session = client
            .register("test-agent", "0.1.0", &["api:read"])
            .await
            .unwrap();

        assert_eq!(session.session_token(), "tok-xyz");
        assert_eq!(session.agent_fingerprint(), "fp-abc123");

        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn connect_fails_with_nonexistent_socket() {
        let result = CdpClient::connect(Path::new("/tmp/cdp-does-not-exist.sock")).await;
        assert!(
            matches!(result, Err(CdpError::Connection(_))),
            "expected Connection error: {result:?}"
        );
    }

    #[tokio::test]
    async fn register_fails_on_unexpected_status() {
        let socket_path = temp_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let resp = json!({
                "jsonrpc": "2.0",
                "result": {
                    "status": "rejected",
                    "agent_fingerprint": "",
                    "session_token": "",
                    "capabilities_granted": []
                },
                "id": 1
            });
            write_half
                .write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes())
                .await
                .unwrap();
        });

        let client = CdpClient::connect(&socket_path).await.unwrap();
        let result = client.register("test-agent", "0.1.0", &[]).await;
        assert!(
            matches!(result, Err(CdpError::MalformedResponse(_))),
            "expected MalformedResponse: {result:?}"
        );

        std::fs::remove_file(&socket_path).ok();
    }
}
