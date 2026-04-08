//! Post-registration session — holds the session token and issues lease requests.

use serde_json::json;
use tracing::instrument;

use crate::lease::Lease;
use crate::transport::Transport;
use crate::types::{LeaseRequest, RequestCredentialResult};
use crate::{CdpError, Result};

/// An authenticated session with the CDP gate.
///
/// Obtained by calling [`CdpClient::register`](crate::client::CdpClient::register).
/// Use [`request_lease`](Session::request_lease) to obtain credential leases.
#[derive(Debug)]
pub struct Session {
    transport: Transport,
    session_token: String,
    agent_fingerprint: String,
}

impl Session {
    /// Construct a new session. Called internally by `CdpClient::register`.
    pub(crate) fn new(
        transport: Transport,
        session_token: String,
        agent_fingerprint: String,
    ) -> Self {
        Self {
            transport,
            session_token,
            agent_fingerprint,
        }
    }

    /// Return the session token issued by the gate.
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    /// Return the agent fingerprint issued by the gate.
    pub fn agent_fingerprint(&self) -> &str {
        &self.agent_fingerprint
    }

    /// Request a credential lease from the gate.
    ///
    /// On success returns a [`Lease`] that can be used to make authenticated
    /// HTTP requests through the CDP proxy.
    #[instrument(name = "Session::request_lease", skip(self, params))]
    pub async fn request_lease(&mut self, params: LeaseRequest) -> Result<Lease> {
        let request_params = json!({
            "session_token": self.session_token,
            "credential_ref": params.credential_ref,
            "scope": {
                "hosts": params.scope.hosts,
                "methods": params.scope.methods,
                "paths": params.scope.paths,
                "ttl_seconds": params.scope.ttl_seconds,
                "max_requests": params.scope.max_requests,
            },
            "reason": params.reason,
        });

        let result_value = self
            .transport
            .send("cdp.requestCredential", request_params)
            .await?;

        let result: RequestCredentialResult =
            serde_json::from_value(result_value).map_err(|e| {
                CdpError::MalformedResponse(format!("invalid requestCredential response: {e}"))
            })?;

        if result.status != "granted" {
            return Err(CdpError::MalformedResponse(format!(
                "unexpected credential status: {}",
                result.status
            )));
        }

        tracing::info!(
            lease_id = %result.lease_id,
            proxy_port = result.proxy_port,
            ttl_seconds = result.ttl_seconds,
            "credential lease granted"
        );

        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(result.ttl_seconds as i64);

        Ok(Lease::new(
            result.lease_id,
            result.proxy_port,
            result.lease_token,
            result.channel_binding_nonce,
            result.ttl_seconds,
            result.granted_scope,
            expires_at,
            self.session_token.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Scope;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn temp_socket_path() -> std::path::PathBuf {
        let id = uuid::Uuid::new_v4();
        std::env::temp_dir().join(format!("cdp-session-test-{id}.sock"))
    }

    #[tokio::test]
    async fn request_lease_success() {
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
                    "status": "granted",
                    "lease_id": "lease-abc",
                    "proxy_port": 9999,
                    "lease_token": "lt-tok",
                    "channel_binding_nonce": "nonce-xyz",
                    "ttl_seconds": 300,
                    "granted_scope": {
                        "hosts": ["api.example.com"],
                        "methods": ["GET"],
                        "paths": ["/v1/*"],
                        "ttl_seconds": 300,
                        "max_requests": 100
                    }
                },
                "id": 1
            });
            write_half
                .write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes())
                .await
                .unwrap();
        });

        let transport = crate::transport::Transport::connect(&socket_path)
            .await
            .unwrap();
        let mut session = Session::new(transport, "sess-tok".to_string(), "fp".to_string());

        let lease = session
            .request_lease(LeaseRequest {
                credential_ref: "my-cred".to_string(),
                scope: Scope {
                    hosts: vec!["api.example.com".to_string()],
                    methods: vec!["GET".to_string()],
                    paths: vec!["/v1/*".to_string()],
                    ttl_seconds: Some(300),
                    max_requests: Some(100),
                },
                reason: "test".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(lease.lease_id(), "lease-abc");
        assert_eq!(lease.proxy_port(), 9999);
        assert!(!lease.is_expired());

        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn request_lease_rejects_denied_status() {
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
                    "status": "denied",
                    "lease_id": "",
                    "proxy_port": 0,
                    "lease_token": "",
                    "channel_binding_nonce": "",
                    "ttl_seconds": 0,
                    "granted_scope": {
                        "hosts": [], "methods": [], "paths": []
                    }
                },
                "id": 1
            });
            write_half
                .write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes())
                .await
                .unwrap();
        });

        let transport = crate::transport::Transport::connect(&socket_path)
            .await
            .unwrap();
        let mut session = Session::new(transport, "sess-tok".to_string(), "fp".to_string());

        let result = session
            .request_lease(LeaseRequest {
                credential_ref: "my-cred".to_string(),
                scope: Scope {
                    hosts: vec![],
                    methods: vec![],
                    paths: vec![],
                    ttl_seconds: None,
                    max_requests: None,
                },
                reason: "test".to_string(),
            })
            .await;

        assert!(
            matches!(result, Err(CdpError::MalformedResponse(_))),
            "expected MalformedResponse for denied status: {result:?}"
        );

        std::fs::remove_file(&socket_path).ok();
    }
}
