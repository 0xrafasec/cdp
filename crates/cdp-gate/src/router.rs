//! JSON-RPC 2.0 router with replay protection and agent registration.

use std::collections::HashMap;
use std::num::NonZero;
use std::sync::Arc;

use chrono::Utc;
use lru::LruCache;
use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, RwLock, mpsc};
use uuid::Uuid;
use zeroize::Zeroizing;

use cdp_lease::LeaseManager;
use cdp_policy::{AgentInfo, PolicyDecision, PolicyEngine, Scope};

use crate::config::GateConfig;
use crate::error::*;
use crate::types::*;

pub struct Router {
    config: Arc<GateConfig>,
    gate_key: Zeroizing<[u8; 32]>,
    registry: Arc<RwLock<HashMap<String, AgentRegistration>>>,
    nonce_cache: Arc<Mutex<LruCache<String, ()>>>,
    death_tx: mpsc::Sender<DeathNotification>,
    /// Lease lifecycle manager shared with the proxy subsystem.
    lease_manager: Arc<LeaseManager>,
    /// Per-lease proxy listener pool.
    proxy_manager: Arc<cdp_proxy::ProxyManager>,
    /// Policy engine for evaluating credential requests.
    policy_engine: Arc<PolicyEngine>,
}

/// Minimum nonce cache size to prevent replay attacks with undersized caches.
const MIN_NONCE_CACHE_ENTRIES: usize = 10_000;

impl Router {
    /// Create a new `Router` using the provided gate key.
    ///
    /// The gate key **must** be the same key used by [`LeaseManager`] and
    /// [`ProxyManager`] so that session and lease tokens are verifiable
    /// across all components.
    pub fn new(
        config: Arc<GateConfig>,
        gate_key: Zeroizing<[u8; 32]>,
        death_tx: mpsc::Sender<DeathNotification>,
        lease_manager: Arc<LeaseManager>,
        proxy_manager: Arc<cdp_proxy::ProxyManager>,
        policy_engine: Arc<PolicyEngine>,
    ) -> Self {
        let effective_entries = config
            .security
            .nonce_max_entries
            .max(MIN_NONCE_CACHE_ENTRIES);
        if config.security.nonce_max_entries < MIN_NONCE_CACHE_ENTRIES {
            tracing::warn!(
                configured = config.security.nonce_max_entries,
                effective = effective_entries,
                "nonce_max_entries below minimum ({MIN_NONCE_CACHE_ENTRIES}); using minimum"
            );
        }
        let capacity = NonZero::new(effective_entries).expect("nonce_max_entries is non-zero");
        let nonce_cache = Arc::new(Mutex::new(LruCache::new(capacity)));

        Self {
            config,
            gate_key,
            registry: Arc::new(RwLock::new(HashMap::new())),
            nonce_cache,
            death_tx,
            lease_manager,
            proxy_manager,
            policy_engine,
        }
    }

    /// Route an incoming JSON-RPC request and return the serialized response.
    pub async fn handle_request(
        &self,
        raw_json: &[u8],
        peer: &PeerInfo,
        connection_id: &[u8],
    ) -> JsonRpcResponse {
        // Parse JSON.
        let request: JsonRpcRequest = match serde_json::from_slice(raw_json) {
            Ok(r) => r,
            Err(e) => {
                return JsonRpcResponse::error(
                    serde_json::Value::Null,
                    PARSE_ERROR,
                    format!("parse error: {e}"),
                );
            }
        };

        let id = request.id.clone();

        // Validate jsonrpc field.
        if request.jsonrpc != "2.0" {
            return JsonRpcResponse::error(id, INVALID_REQUEST, "jsonrpc must be \"2.0\"");
        }

        // Route by method.
        match request.method.as_str() {
            "cdp.register" => {
                let params: RegisterParams = match serde_json::from_value(request.params) {
                    Ok(p) => p,
                    Err(e) => {
                        return JsonRpcResponse::error(
                            id,
                            INVALID_REQUEST,
                            format!("invalid params: {e}"),
                        );
                    }
                };
                match self.handle_register(params, peer, connection_id).await {
                    Ok(value) => JsonRpcResponse::success(id, value),
                    Err(e) => gate_error_to_response(id, e),
                }
            }
            "cdp.requestCredential" => {
                // Parse params first (before session validation so we can return
                // a structured error for malformed params).
                let params: RequestCredentialParams =
                    match serde_json::from_value(request.params.clone()) {
                        Ok(p) => p,
                        Err(e) => {
                            return JsonRpcResponse::error(
                                id,
                                INVALID_REQUEST,
                                format!("invalid params: {e}"),
                            );
                        }
                    };
                // Validate session using the session_token from params.
                if let Err(e) = self
                    .validate_session(&request.params, peer, connection_id)
                    .await
                {
                    return gate_error_to_response(id, e);
                }
                match self
                    .handle_request_credential(params, peer, connection_id)
                    .await
                {
                    Ok(value) => JsonRpcResponse::success(id, value),
                    Err(e) => gate_error_to_response(id, e),
                }
            }
            other => {
                // Validate session first, then report method not found.
                if let Err(e) = self
                    .validate_session(&request.params, peer, connection_id)
                    .await
                {
                    return gate_error_to_response(id, e);
                }
                JsonRpcResponse::error(id, METHOD_NOT_FOUND, format!("method not found: {other}"))
            }
        }
    }

    /// Validate replay protection: nonce uniqueness and timestamp freshness.
    async fn validate_replay(&self, nonce: &str, timestamp: &str) -> Result<(), GateError> {
        // Validate nonce is a UUID v4.
        let uuid = Uuid::parse_str(nonce)
            .map_err(|_| GateError::Replay("nonce is not a valid UUID".to_string()))?;
        if uuid.get_version_num() != 4 {
            return Err(GateError::Replay(
                "nonce UUID version must be 4".to_string(),
            ));
        }

        // Parse timestamp as RFC 3339.
        let ts = chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|_| GateError::Replay("timestamp is not valid RFC 3339".to_string()))?;
        let ts_utc = ts.with_timezone(&Utc);

        // Reject if older than 30 seconds.
        let age = Utc::now().signed_duration_since(ts_utc);
        if age.num_seconds().abs() > 30 {
            return Err(GateError::Replay(format!(
                "timestamp is {} seconds old (max 30)",
                age.num_seconds()
            )));
        }

        // Check for duplicate nonce.
        let mut cache = self.nonce_cache.lock().await;
        if cache.contains(nonce) {
            return Err(GateError::Replay(format!("duplicate nonce: {nonce}")));
        }
        cache.put(nonce.to_string(), ());

        Ok(())
    }

    /// Handle a `cdp.register` request.
    async fn handle_register(
        &self,
        params: RegisterParams,
        peer: &PeerInfo,
        connection_id: &[u8],
    ) -> Result<serde_json::Value, GateError> {
        // Replay protection.
        self.validate_replay(&params.nonce, &params.timestamp)
            .await?;

        // Verify agent identity via /proc inspection.
        let fingerprint = crate::agent_verify::verify_agent(peer.pid, peer.uid).await?;

        // Generate session token.
        let raw_token = cdp_crypto::generate_session_token(
            self.gate_key.as_ref(),
            &fingerprint.fingerprint_hash,
            connection_id,
        );
        let session_token = format!("cdp_sess_{raw_token}");

        // Spawn liveness monitor for this agent.
        let death_tx = self.death_tx.clone();
        let fp_hash = fingerprint.fingerprint_hash;
        let pid = peer.pid;
        let pidfd = fingerprint
            .pidfd
            .try_clone()
            .map_err(|e| GateError::Syscall(format!("failed to clone pidfd: {e}")))?;
        tokio::spawn(async move {
            // Wait for pidfd to become readable (process exit).
            use tokio::io::unix::AsyncFd;
            if let Ok(async_fd) = AsyncFd::new(pidfd) {
                let _ = async_fd.readable().await;
            }
            let notification = DeathNotification {
                pid,
                fingerprint_hash: fp_hash,
            };
            let _ = death_tx.send(notification).await;
        });

        // Build agent ID key as hex of fingerprint hash.
        let fp_hex = hex_encode(&fingerprint.fingerprint_hash);

        // Capabilities: echo back what was requested (policy engine comes later).
        let capabilities_granted = params.capabilities.clone();

        // Store registration (session token is not stored — it is recomputed
        // from the gate key + fingerprint + connection_id on every validation).
        let registration = AgentRegistration {
            agent_id: params.agent_id.clone(),
            agent_version: params.agent_version.clone(),
            capabilities_granted: capabilities_granted.clone(),
            connection_id: connection_id.to_vec(),
            registered_at: Utc::now(),
            fingerprint,
        };
        {
            let mut registry = self.registry.write().await;
            registry.insert(fp_hex.clone(), registration);
        }

        tracing::info!(
            agent_id = %params.agent_id,
            pid = peer.pid,
            fingerprint = %fp_hex,
            "agent registered"
        );

        let result = RegisterResult {
            status: "registered".to_string(),
            agent_fingerprint: fp_hex,
            session_token,
            capabilities_granted,
        };
        Ok(serde_json::to_value(result).expect("RegisterResult is always serializable"))
    }

    /// Handle a `cdp.requestCredential` request.
    ///
    /// Pipeline:
    /// 1. Replay protection (nonce + timestamp).
    /// 2. Look up agent registration by peer identity.
    /// 3. Build [`AgentInfo`] for the policy engine.
    /// 4. Evaluate policy (with optional user approval).
    /// 5. Create lease via [`LeaseManager`].
    /// 6. Start per-lease proxy via [`ProxyManager`].
    /// 7. Return lease token, channel-binding nonce, port, and granted scope.
    async fn handle_request_credential(
        &self,
        params: RequestCredentialParams,
        peer: &PeerInfo,
        connection_id: &[u8],
    ) -> Result<serde_json::Value, GateError> {
        // 1. Replay protection.
        self.validate_replay(&params.nonce, &params.timestamp)
            .await?;

        // 2. Look up the registration for this peer.
        let registration = {
            let registry = self.registry.read().await;
            registry
                .values()
                .find(|r| r.fingerprint.pid == peer.pid && r.connection_id == connection_id)
                .map(|r| {
                    // Clone the fields we need (AgentFingerprint is not Clone).
                    (
                        r.fingerprint.uid,
                        r.fingerprint.pid,
                        r.fingerprint.binary_path.clone(),
                        r.fingerprint.binary_hash,
                        r.fingerprint.start_time,
                        r.fingerprint.fingerprint_hash,
                        r.agent_id.clone(),
                        r.agent_version.clone(),
                    )
                })
        };

        let (
            uid,
            pid,
            binary_path,
            binary_hash,
            start_time,
            fingerprint_hash,
            agent_id,
            agent_version,
        ) = registration.ok_or_else(|| {
            GateError::SessionInvalid("no registration found for this peer".to_string())
        })?;

        // 3. Build AgentInfo.
        let agent_info = AgentInfo {
            uid,
            pid,
            binary_path,
            binary_hash,
            start_time,
            fingerprint_hash,
            agent_id: Some(agent_id),
            agent_version: Some(agent_version),
        };

        // 4. Convert requested scope from RPC params.
        let requested_scope = Scope {
            hosts: params.scope.hosts,
            methods: params.scope.methods,
            paths: params.scope.paths,
            ttl_seconds: params.scope.ttl_seconds,
            max_requests: params.scope.max_requests,
            ..Scope::default()
        };

        // 5. Policy evaluation (may prompt the user).
        let decision = self
            .policy_engine
            .evaluate_with_approval(
                &agent_info,
                &params.credential_ref,
                &requested_scope,
                &params.reason,
            )
            .await?;

        let (granted_scope, policy_name, constraints) = match decision {
            PolicyDecision::AutoApprove {
                granted_scope,
                policy_name,
                constraints,
            } => (granted_scope, policy_name, constraints),
            PolicyDecision::Denied { reason } => {
                return Err(GateError::CredentialDenied(reason));
            }
            PolicyDecision::RequiresApproval { .. } => {
                // evaluate_with_approval resolves this branch; reaching here
                // indicates an approval timeout or command error (which returns
                // an Err above via `?`).  Handle defensively:
                return Err(GateError::CredentialDenied(
                    "approval required but not resolved".to_string(),
                ));
            }
        };

        // 6. Create the lease.
        let lease = self
            .lease_manager
            .create_lease(
                &agent_info,
                &params.credential_ref,
                granted_scope.clone(),
                &constraints,
                &policy_name,
                "auto",
            )
            .await?;

        // 7. Start the proxy listener.
        let proxy_port = self.proxy_manager.start_proxy(&lease.lease_id).await?;

        // 8. Encode the channel-binding nonce for the agent.
        let cb_nonce_hex = hex_encode(&lease.channel_binding_nonce);

        tracing::info!(
            agent_pid = pid,
            credential_ref = %params.credential_ref,
            lease_id = %lease.lease_id,
            proxy_port,
            "credential lease granted"
        );

        let result = RequestCredentialResult {
            status: "granted".to_string(),
            lease_id: lease.lease_id.to_string(),
            proxy_port,
            lease_token: lease.lease_token.clone(),
            channel_binding_nonce: cb_nonce_hex,
            ttl_seconds: lease.ttl_seconds,
            granted_scope: GrantedScopeInfo {
                hosts: granted_scope.hosts,
                methods: granted_scope.methods,
                paths: granted_scope.paths,
                ttl_seconds: granted_scope.ttl_seconds,
                max_requests: granted_scope.max_requests,
            },
        };

        Ok(serde_json::to_value(result).expect("RequestCredentialResult is always serializable"))
    }

    /// Validate a session token from request params.
    async fn validate_session(
        &self,
        params: &serde_json::Value,
        peer: &PeerInfo,
        connection_id: &[u8],
    ) -> Result<(), GateError> {
        let token = params
            .get("session_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GateError::SessionInvalid("missing session_token".to_string()))?;

        let raw_token = token
            .strip_prefix("cdp_sess_")
            .ok_or_else(|| GateError::SessionInvalid("invalid session_token prefix".to_string()))?;

        // Find the registration for this peer by scanning the registry.
        let registry = self.registry.read().await;
        let registration = registry
            .values()
            .find(|r| r.fingerprint.pid == peer.pid && r.connection_id == connection_id);

        let reg = registration.ok_or_else(|| {
            GateError::SessionInvalid("no registration found for this peer".to_string())
        })?;

        let valid = cdp_crypto::verify_session_token(
            self.gate_key.as_ref(),
            &reg.fingerprint.fingerprint_hash,
            connection_id,
            raw_token,
        );

        if !valid {
            return Err(GateError::SessionInvalid(
                "session token HMAC invalid".to_string(),
            ));
        }

        Ok(())
    }

    /// Handle a death notification by removing the agent from the registry
    /// and revoking all their active leases + stopping proxy listeners.
    pub async fn handle_death(&self, notification: DeathNotification) {
        let key = hex_encode(&notification.fingerprint_hash);

        // Remove from registry.
        let removed = {
            let mut registry = self.registry.write().await;
            registry.remove(&key).is_some()
        };

        if removed {
            tracing::info!(
                pid = notification.pid,
                fingerprint = %key,
                "agent deregistered (process exited)"
            );

            // Revoke all leases for this agent.
            match self
                .lease_manager
                .revoke_agent_leases(&notification.fingerprint_hash, "agent process exited")
                .await
            {
                Ok(revoked_ids) => {
                    // Stop the proxy listener for each revoked lease.
                    for lease_id in revoked_ids {
                        self.proxy_manager.release_lease(&lease_id).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        fingerprint = %key,
                        error = %e,
                        "failed to revoke agent leases on death"
                    );
                }
            }
        }
    }

    /// Handle a full connection lifecycle (read-eval-print loop).
    pub async fn handle_connection(self: Arc<Self>, stream: UnixStream, peer: PeerInfo) {
        // Generate a random 16-byte connection ID bound into session tokens.
        let mut connection_id = [0u8; 16];
        rand::rng().fill_bytes(&mut connection_id);

        // Split into read and write halves.
        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF — client disconnected.
                    tracing::debug!(pid = peer.pid, "client disconnected");
                    break;
                }
                Ok(_) => {
                    let response = self
                        .handle_request(line.trim_end().as_bytes(), &peer, &connection_id)
                        .await;

                    let mut json = serde_json::to_string(&response)
                        .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"},"id":null}"#.to_string());
                    json.push('\n');

                    if let Err(e) = writer.write_all(json.as_bytes()).await {
                        tracing::warn!(pid = peer.pid, error = %e, "write failed");
                        break;
                    }
                    if let Err(e) = writer.flush().await {
                        tracing::warn!(pid = peer.pid, error = %e, "flush failed");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(pid = peer.pid, error = %e, "read error");
                    break;
                }
            }
        }

        // On disconnect, purge any registrations belonging to this connection_id.
        {
            let mut registry = self.registry.write().await;
            registry.retain(|_, reg| reg.connection_id != connection_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Error mapping helper
// ---------------------------------------------------------------------------

fn gate_error_to_response(id: serde_json::Value, err: GateError) -> JsonRpcResponse {
    match &err {
        GateError::Replay(_) => JsonRpcResponse::error(id, REPLAY_DETECTED, err.to_string()),
        GateError::SessionInvalid(_) => {
            JsonRpcResponse::error(id, SESSION_INVALID, err.to_string())
        }
        GateError::AgentVerification(_) => {
            JsonRpcResponse::error(id, AGENT_VERIFICATION_FAILED, err.to_string())
        }
        GateError::CredentialDenied(_) => {
            JsonRpcResponse::error(id, CREDENTIAL_DENIED, err.to_string())
        }
        GateError::Lease(_) => JsonRpcResponse::error(id, LEASE_ERROR, err.to_string()),
        GateError::Proxy(_) => JsonRpcResponse::error(id, PROXY_ERROR, err.to_string()),
        GateError::JsonRpc { code, message } => JsonRpcResponse::error(id, *code, message.clone()),
        _ => JsonRpcResponse::error(id, -32603, err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cdp_policy::{ApprovalConfig, PolicyEngine};
    use chrono::Duration;

    fn make_router() -> Router {
        let config = Arc::new(GateConfig::default());
        let (tx, _rx) = mpsc::channel(16);

        let gate_key = vec![0u8; 32];
        let lease_manager = Arc::new(LeaseManager::new(gate_key.clone(), None));

        let proxy_config = cdp_proxy::ProxyConfig::default();
        let credential_provider = Arc::new(cdp_proxy::credential::MockCredentialProvider::new());
        let proxy_manager = Arc::new(cdp_proxy::ProxyManager::new(
            proxy_config,
            Arc::clone(&lease_manager),
            credential_provider,
            Zeroizing::new(gate_key),
            None,
        ));

        let approval_config = ApprovalConfig {
            gui_command: "echo".to_string(),
            timeout_seconds: 5,
            show_binary_hash: true,
            label_reason_untrusted: true,
            max_reason_length: 200,
        };
        let tmp_dir = tempfile::tempdir().expect("tempdir");
        let policy_dir = tmp_dir.keep();
        let policy_engine =
            Arc::new(PolicyEngine::new(policy_dir, approval_config).expect("PolicyEngine::new"));

        let gate_key_arr = Zeroizing::new([0u8; 32]);

        Router::new(
            config,
            gate_key_arr,
            tx,
            lease_manager,
            proxy_manager,
            policy_engine,
        )
    }

    // -----------------------------------------------------------------------
    // validate_replay tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_replay_fresh_nonce_passes() {
        let router = make_router();
        let nonce = Uuid::new_v4().to_string();
        let ts = Utc::now().to_rfc3339();
        router.validate_replay(&nonce, &ts).await.unwrap();
    }

    #[tokio::test]
    async fn validate_replay_duplicate_nonce_rejected() {
        let router = make_router();
        let nonce = Uuid::new_v4().to_string();
        let ts = Utc::now().to_rfc3339();
        router.validate_replay(&nonce, &ts).await.unwrap();
        // Second use of the same nonce should fail.
        let err = router.validate_replay(&nonce, &ts).await.unwrap_err();
        assert!(matches!(err, GateError::Replay(_)));
    }

    #[tokio::test]
    async fn validate_replay_stale_timestamp_rejected() {
        let router = make_router();
        let nonce = Uuid::new_v4().to_string();
        // Timestamp 60 seconds in the past.
        let old_ts = (Utc::now() - Duration::seconds(60)).to_rfc3339();
        let err = router.validate_replay(&nonce, &old_ts).await.unwrap_err();
        assert!(matches!(err, GateError::Replay(_)));
    }

    #[tokio::test]
    async fn validate_replay_invalid_uuid_rejected() {
        let router = make_router();
        let ts = Utc::now().to_rfc3339();
        let err = router.validate_replay("not-a-uuid", &ts).await.unwrap_err();
        assert!(matches!(err, GateError::Replay(_)));
    }

    // -----------------------------------------------------------------------
    // handle_request tests
    // -----------------------------------------------------------------------

    fn dummy_peer() -> PeerInfo {
        PeerInfo {
            pid: 1,
            uid: 1000,
            gid: 1000,
        }
    }

    #[tokio::test]
    async fn handle_request_invalid_json_returns_parse_error() {
        let router = make_router();
        let peer = dummy_peer();
        let resp = router
            .handle_request(b"{{not valid json", &peer, &[1u8; 16])
            .await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    }

    #[tokio::test]
    async fn handle_request_missing_jsonrpc_returns_parse_error() {
        let router = make_router();
        let peer = dummy_peer();
        // Missing `jsonrpc` field fails serde deserialization → parse error.
        let raw = br#"{"method":"cdp.register","params":{},"id":1}"#;
        let resp = router.handle_request(raw, &peer, &[1u8; 16]).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    }

    #[tokio::test]
    async fn handle_request_wrong_jsonrpc_version_returns_invalid_request() {
        let router = make_router();
        let peer = dummy_peer();
        let raw = br#"{"jsonrpc":"1.0","method":"cdp.register","params":{},"id":1}"#;
        let resp = router.handle_request(raw, &peer, &[1u8; 16]).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_REQUEST);
    }
}
