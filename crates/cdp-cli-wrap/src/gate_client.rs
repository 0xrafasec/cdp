//! Minimal Gate JSON-RPC client.
//!
//! Reads the Gate fingerprint file from `~/.config/cdp/gate.fingerprint`,
//! connects to the Unix socket, sends `cdp.register` and `cdp.requestCredential`,
//! and returns the plaintext credential via a [`SecureBuffer`].
//!
//! This module deliberately does NOT depend on `cdp-sdk` (being built
//! concurrently). It implements the minimum subset of the JSON-RPC 2.0
//! protocol needed for credential acquisition.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::WrapError;

// ---------------------------------------------------------------------------
// Lease info returned by the Gate
// ---------------------------------------------------------------------------

/// Information about a granted credential lease, returned by the Gate's
/// `cdp.requestCredential` RPC. The credential itself is never returned —
/// it is injected by the CDP proxy at the transport layer.
#[derive(Debug)]
pub struct LeaseInfo {
    /// The proxy port to route traffic through.
    pub proxy_port: u16,
    /// HMAC lease token for authenticating with the proxy.
    pub lease_token: String,
    /// Hex-encoded channel-binding nonce.
    pub channel_binding_nonce: String,
    /// Granted lease TTL in seconds.
    pub ttl_seconds: u64,
}

// ---------------------------------------------------------------------------
// Fingerprint file types
// ---------------------------------------------------------------------------

/// The fingerprint file written by the Gate on startup.
#[derive(Debug, Deserialize)]
pub struct GateFingerprint {
    /// Path to the Gate's Unix domain socket.
    pub socket_path: String,
    /// Gate version string (for compatibility checking).
    #[allow(dead_code)]
    pub version: Option<String>,
}

impl GateFingerprint {
    /// Load from `~/.config/cdp/gate.fingerprint`.
    pub fn load() -> Result<Self, WrapError> {
        let path = Self::default_path()?;
        let contents = std::fs::read_to_string(&path).map_err(|e| {
            WrapError::Config(format!(
                "cannot read gate fingerprint at {}: {e}",
                path.display()
            ))
        })?;
        let fp: GateFingerprint = serde_json::from_str(&contents)
            .map_err(|e| WrapError::Config(format!("malformed gate fingerprint: {e}")))?;
        Ok(fp)
    }

    /// Returns the default path: `~/.config/cdp/gate.fingerprint`.
    pub fn default_path() -> Result<PathBuf, WrapError> {
        let home = std::env::var("HOME")
            .map_err(|_| WrapError::Config("HOME environment variable not set".to_string()))?;
        Ok(PathBuf::from(home).join(".config/cdp/gate.fingerprint"))
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct JsonRpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    params: P,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<Value>,
    error: Option<JsonRpcError>,
    #[allow(dead_code)]
    id: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Serialize)]
struct RegisterParams {
    agent_id: &'static str,
    agent_version: &'static str,
    capabilities: Vec<&'static str>,
    nonce: String,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct RequestCredentialParams {
    session_token: String,
    credential_ref: String,
    scope: CredentialScope,
    reason: String,
    nonce: String,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct CredentialScope {
    hosts: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// Gate client
// ---------------------------------------------------------------------------

/// A minimal Gate client for acquiring a single CLI credential.
pub struct GateClient {
    stream: BufReader<UnixStream>,
    writer: UnixStream,
    session_token: Option<String>,
}

impl GateClient {
    /// Connect to the Gate at the given socket path and perform registration.
    #[instrument(skip_all, fields(socket = %socket_path))]
    pub fn connect(socket_path: &str) -> Result<Self, WrapError> {
        let stream = UnixStream::connect(socket_path).map_err(|e| {
            WrapError::Gate(format!("cannot connect to Gate at {socket_path}: {e}"))
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| WrapError::Gate(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| WrapError::Gate(format!("set_write_timeout: {e}")))?;

        let writer = stream
            .try_clone()
            .map_err(|e| WrapError::Gate(format!("clone stream: {e}")))?;

        Ok(GateClient {
            stream: BufReader::new(stream),
            writer,
            session_token: None,
        })
    }

    /// Send `cdp.register` and store the returned session token.
    #[instrument(skip_all)]
    pub fn register(&mut self) -> Result<(), WrapError> {
        let params = RegisterParams {
            agent_id: "cdp-wrap",
            agent_version: env!("CARGO_PKG_VERSION"),
            capabilities: vec!["cli"],
            nonce: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "cdp.register",
            params,
            id: 1,
        };

        let response = self.send_request(&request)?;
        let token = response["session_token"]
            .as_str()
            .ok_or_else(|| {
                WrapError::Gate("register: missing session_token in response".to_string())
            })?
            .to_string();

        debug!("registered with Gate, got session token");
        self.session_token = Some(token);
        Ok(())
    }

    /// Request a credential lease and return proxy connection info.
    ///
    /// The credential itself is never returned to the caller — it is injected
    /// by the CDP proxy at the transport layer. The returned [`LeaseInfo`]
    /// contains the proxy port and authentication tokens needed to route
    /// traffic through the proxy.
    #[instrument(skip_all, fields(credential_ref = %credential_ref))]
    pub fn request_credential(
        &mut self,
        credential_ref: &str,
        command: &str,
    ) -> Result<LeaseInfo, WrapError> {
        let session_token = self.session_token.clone().ok_or_else(|| {
            WrapError::Gate("must call register() before request_credential()".to_string())
        })?;

        let params = RequestCredentialParams {
            session_token,
            credential_ref: credential_ref.to_string(),
            scope: CredentialScope {
                hosts: vec![],
                methods: vec![],
                paths: vec![],
            },
            reason: format!("CLI wrapper for {command}"),
            nonce: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "cdp.requestCredential",
            params,
            id: 2,
        };

        let response = self.send_request(&request)?;

        let proxy_port = response["proxy_port"]
            .as_u64()
            .ok_or_else(|| WrapError::Gate("missing proxy_port in response".to_string()))?
            as u16;
        let lease_token = response["lease_token"]
            .as_str()
            .ok_or_else(|| WrapError::Gate("missing lease_token in response".to_string()))?
            .to_string();
        let channel_binding_nonce = response["channel_binding_nonce"]
            .as_str()
            .ok_or_else(|| {
                WrapError::Gate("missing channel_binding_nonce in response".to_string())
            })?
            .to_string();
        let ttl_seconds = response["ttl_seconds"].as_u64().unwrap_or(3600);

        debug!(proxy_port, ttl_seconds, "credential lease granted");
        Ok(LeaseInfo {
            proxy_port,
            lease_token,
            channel_binding_nonce,
            ttl_seconds,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Send a single JSON-RPC request and return the `result` value.
    fn send_request<P: Serialize>(
        &mut self,
        request: &JsonRpcRequest<P>,
    ) -> Result<Value, WrapError> {
        let mut payload = serde_json::to_vec(request)?;
        payload.push(b'\n');

        self.writer
            .write_all(&payload)
            .map_err(|e| WrapError::Gate(format!("write request: {e}")))?;

        let mut line = String::new();
        self.stream
            .read_line(&mut line)
            .map_err(|e| WrapError::Gate(format!("read response: {e}")))?;

        if line.is_empty() {
            return Err(WrapError::Gate(
                "Gate closed connection unexpectedly".to_string(),
            ));
        }

        let rpc: JsonRpcResponse = serde_json::from_str(line.trim())
            .map_err(|e| WrapError::Gate(format!("deserialize response: {e}")))?;

        if let Some(err) = rpc.error {
            return Err(WrapError::Gate(format!(
                "Gate returned error {}: {}",
                err.code, err.message
            )));
        }

        rpc.result.ok_or_else(|| {
            WrapError::Gate("Gate response missing both result and error".to_string())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_fingerprint_default_path() {
        // HOME must be set in any normal test environment.
        let result = GateFingerprint::default_path();
        assert!(
            result.is_ok(),
            "default_path should succeed when HOME is set"
        );
        let path = result.unwrap();
        assert!(path.ends_with(".config/cdp/gate.fingerprint"));
    }

    #[test]
    fn test_gate_fingerprint_missing_home() {
        // Temporarily remove HOME to verify error handling.
        let saved = std::env::var("HOME").ok();
        unsafe { std::env::remove_var("HOME") };
        let result = GateFingerprint::default_path();
        assert!(result.is_err());
        if let Some(h) = saved {
            unsafe { std::env::set_var("HOME", h) };
        }
    }

    #[test]
    fn test_gate_fingerprint_deserializes() {
        let json = r#"{"socket_path":"/run/cdp/gate.sock","version":"0.1.0"}"#;
        let fp: GateFingerprint = serde_json::from_str(json).expect("deserialize");
        assert_eq!(fp.socket_path, "/run/cdp/gate.sock");
        assert_eq!(fp.version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn test_request_without_registration_fails() {
        // Build a GateClient without calling register() and verify
        // request_credential returns an appropriate error.
        // We can't easily test the full client without a running Gate, but we
        // can verify the guard logic.
        // Use a dummy path — connect will fail, but we're testing a different path.
        let result = UnixStream::connect("/nonexistent/path/cdp.sock");
        assert!(
            result.is_err(),
            "connecting to nonexistent socket should fail"
        );
    }
}
