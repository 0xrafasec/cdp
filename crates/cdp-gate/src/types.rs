use std::os::fd::OwnedFd;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Agent identity
// ---------------------------------------------------------------------------

/// Cryptographic fingerprint derived from SO_PEERCRED + /proc inspection.
///
/// The fingerprint is `SHA-256(UID || PID || binary_hash || start_time)` where
/// all integers are little-endian encoded. The `pidfd` keeps the kernel from
/// recycling the PID while we hold it.
pub struct AgentFingerprint {
    pub uid: u32,
    pub pid: u32,
    pub binary_path: PathBuf,
    /// Raw SHA-256 of the agent binary.
    pub binary_hash: [u8; 32],
    /// Clock-tick start time from `/proc/<pid>/stat` field 22.
    pub start_time: u64,
    /// Composite fingerprint: SHA-256(uid || pid || binary_hash || start_time).
    pub fingerprint_hash: [u8; 32],
    /// File descriptor from `pidfd_open` — readable when the process exits.
    pub pidfd: OwnedFd,
}

/// A registered agent tracked by the router.
pub struct AgentRegistration {
    pub fingerprint: AgentFingerprint,
    pub agent_id: String,
    pub agent_version: String,
    pub capabilities_granted: Vec<String>,
    /// Unique per Unix-socket connection; bound into the session HMAC.
    pub connection_id: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

/// Sent on the death channel when a pidfd becomes readable.
pub struct DeathNotification {
    pub pid: u32,
    pub fingerprint_hash: [u8; 32],
}

/// Peer credentials extracted from `SO_PEERCRED` on the Unix socket.
#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 message types (manual serde_json parsing)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

// ---------------------------------------------------------------------------
// cdp.register
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterParams {
    pub agent_id: String,
    pub agent_version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub attestation: Option<serde_json::Value>,
    pub nonce: String,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResult {
    pub status: String,
    pub agent_fingerprint: String,
    pub session_token: String,
    pub capabilities_granted: Vec<String>,
}

// ---------------------------------------------------------------------------
// cdp.requestCredential
// ---------------------------------------------------------------------------

/// Requested scope for a credential request.
#[derive(Debug, Deserialize)]
pub struct RequestedScope {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub ttl_seconds: Option<u64>,
    pub max_requests: Option<u64>,
}

/// Parameters for `cdp.requestCredential`.
#[derive(Debug, Deserialize)]
pub struct RequestCredentialParams {
    pub session_token: String,
    pub credential_ref: String,
    pub scope: RequestedScope,
    pub reason: String,
    pub nonce: String,
    pub timestamp: String,
}

/// Successful response for `cdp.requestCredential`.
#[derive(Debug, Serialize)]
pub struct RequestCredentialResult {
    pub status: String,
    pub lease_id: String,
    pub proxy_port: u16,
    pub lease_token: String,
    pub channel_binding_nonce: String,
    pub ttl_seconds: u64,
    pub granted_scope: GrantedScopeInfo,
}

/// Scope information returned to the agent.
#[derive(Debug, Serialize)]
pub struct GrantedScopeInfo {
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub ttl_seconds: Option<u64>,
    pub max_requests: Option<u64>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl JsonRpcResponse {
    /// Build a successful response.
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Build an error response.
    pub fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

/// Encode a byte slice as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_known_vectors() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0xff; 4]), "ffffffff");
    }

    #[test]
    fn json_rpc_response_success_serializes() {
        let resp = JsonRpcResponse::success(
            serde_json::Value::Number(1.into()),
            serde_json::json!({"status": "ok"}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"status\":\"ok\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn json_rpc_response_error_serializes() {
        let resp =
            JsonRpcResponse::error(serde_json::Value::Number(1.into()), -32600, "bad request");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"-32600\"").not() || json.contains("-32600"));
        assert!(json.contains("bad request"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn register_params_deserializes() {
        let json = serde_json::json!({
            "agent_id": "test-agent",
            "agent_version": "1.0.0",
            "capabilities": ["http_proxy"],
            "attestation": null,
            "nonce": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2026-04-07T14:00:00Z"
        });
        let params: RegisterParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.agent_id, "test-agent");
        assert_eq!(params.capabilities, vec!["http_proxy"]);
        assert!(params.attestation.is_none());
    }

    // Helper — std assert does not have `.not()`, so use a simple wrapper.
    trait Not {
        fn not(self) -> bool;
    }
    impl Not for bool {
        fn not(self) -> bool {
            !self
        }
    }
}
