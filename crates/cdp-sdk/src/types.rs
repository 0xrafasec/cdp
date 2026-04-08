//! Shared types for the CDP SDK.

use serde::{Deserialize, Serialize};

/// Credential access scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scope {
    /// Allowed target hostnames (e.g. `["api.acme.com"]`).
    pub hosts: Vec<String>,
    /// Allowed HTTP methods (e.g. `["GET", "POST"]`).
    pub methods: Vec<String>,
    /// Allowed URL path patterns (e.g. `["/v1/*"]`).
    pub paths: Vec<String>,
    /// Requested TTL in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Maximum number of proxied requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
}

/// Scope as granted by the gate (may be narrower than requested).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantedScope {
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
}

/// Parameters for requesting a credential lease.
#[derive(Debug, Clone)]
pub struct LeaseRequest {
    /// Opaque reference to the credential stored in the vault.
    pub credential_ref: String,
    /// Requested access scope.
    pub scope: Scope,
    /// Human-readable justification shown in approval prompts.
    pub reason: String,
}

/// JSON-RPC 2.0 request envelope (internal).
#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcRequest<'a> {
    pub jsonrpc: &'static str,
    pub method: &'a str,
    pub params: serde_json::Value,
    pub id: u64,
}

/// JSON-RPC 2.0 response envelope (internal).
#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    #[allow(dead_code)]
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 error object (internal).
#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// Result of `cdp.register`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RegisterResult {
    pub status: String,
    pub agent_fingerprint: String,
    pub session_token: String,
    pub capabilities_granted: Vec<String>,
}

/// Result of `cdp.requestCredential`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RequestCredentialResult {
    pub status: String,
    pub lease_id: String,
    pub proxy_port: u16,
    pub lease_token: String,
    pub channel_binding_nonce: String,
    pub ttl_seconds: u64,
    pub granted_scope: GrantedScope,
}

/// Result of `cdp.renewLease`.
#[derive(Debug, Clone, Deserialize)]
pub struct RenewalInfo {
    pub status: String,
    pub new_expires_at: String,
    pub renewals_remaining: u32,
}
