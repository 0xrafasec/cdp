//! HTTP request/response handling for the CDP proxy.
//!
//! This module provides:
//! - [`inject_headers`] / [`strip_proxy_internal_headers`]: header utilities
//!   used by the outbound request builder.
//! - [`ProxyServer`]: a per-lease HTTP/1.1 proxy that binds a TCP listener and
//!   processes the full authentication → scope → DNS → credential → forward →
//!   redirect → sanitise pipeline for every request.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use cdp_audit::{AuditEventType, AuditFields};
use cdp_lease::{LeaseId, LeaseManager};

use crate::credential::CredentialProvider;
use crate::ProxyError;

// ---------------------------------------------------------------------------
// Body-size limit for buffering inbound request bodies.
// ---------------------------------------------------------------------------

/// Maximum body size buffered in memory per request (4 MiB).
///
/// This is a safety cap applied before any scope-level `max_size_bytes` check.
/// It prevents a malicious agent from OOM-ing the proxy by sending a giant body
/// to an endpoint that has no body constraint configured.
const GLOBAL_MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// ProxyServer
// ---------------------------------------------------------------------------

/// A running per-lease HTTP/1.1 proxy listener.
///
/// Each lease gets exactly one `ProxyServer` bound to a unique loopback port.
/// The server verifies triple authentication (lease token + channel binding +
/// OS peer identity) on every request before injecting credentials and
/// forwarding upstream.
pub struct ProxyServer {
    /// The lease this proxy serves.
    pub lease_id: LeaseId,
    /// Local address the listener will bind to.
    pub bind_addr: SocketAddr,
    /// Gate HMAC key — used to verify lease tokens.  Zeroized on drop.
    gate_key: Zeroizing<Vec<u8>>,
    /// Lease store — `use_lease` is called on every proxied request.
    lease_manager: Arc<LeaseManager>,
    /// Credential back-end — provides headers to inject upstream.
    credential_provider: Arc<dyn CredentialProvider>,
    /// Optional audit sink.
    audit_tx: Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
}

impl ProxyServer {
    /// Create a new server.  Binding does not happen until [`run`] is called.
    pub fn new(
        lease_id: LeaseId,
        bind_addr: SocketAddr,
        gate_key: Zeroizing<Vec<u8>>,
        lease_manager: Arc<LeaseManager>,
        credential_provider: Arc<dyn CredentialProvider>,
        audit_tx: Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
    ) -> Self {
        Self {
            lease_id,
            bind_addr,
            gate_key,
            lease_manager,
            credential_provider,
            audit_tx,
        }
    }

    /// Bind the TCP listener and begin accepting connections.
    ///
    /// The future completes when `shutdown_rx` fires (the sender is dropped or
    /// explicitly sends `()`).  All in-flight requests are given a chance to
    /// finish because hyper's connection-level future is polled to completion
    /// inside the spawned task.
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        tracing::info!(
            lease_id = %self.lease_id,
            addr = %self.bind_addr,
            "proxy listener bound"
        );

        // Wrap shared state in Arcs so each connection task gets a clone.
        let lease_id = Arc::new(self.lease_id);
        let gate_key = Arc::new(self.gate_key);
        let lease_manager = self.lease_manager;
        let credential_provider = self.credential_provider;
        let audit_tx = self.audit_tx;

        loop {
            tokio::select! {
                biased;

                // Shutdown signal received — exit the accept loop.
                _ = &mut shutdown_rx => {
                    tracing::info!(lease_id = %lease_id, "proxy listener shutting down");
                    break;
                }

                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, remote_addr)) => {
                            tracing::debug!(
                                lease_id = %lease_id,
                                remote = %remote_addr,
                                "accepted proxy connection"
                            );

                            // Clone all shared state for the connection task.
                            let lease_id_clone = Arc::clone(&lease_id);
                            let gate_key_clone = Arc::clone(&gate_key);
                            let lease_mgr = Arc::clone(&lease_manager);
                            let cred_prov = Arc::clone(&credential_provider);
                            let audit_clone = audit_tx.clone();

                            tokio::spawn(async move {
                                let io = hyper_util::rt::TokioIo::new(stream);
                                let service = service_fn(move |req| {
                                    let lid = Arc::clone(&lease_id_clone);
                                    let gk = Arc::clone(&gate_key_clone);
                                    let lm = Arc::clone(&lease_mgr);
                                    let cp = Arc::clone(&cred_prov);
                                    let at = audit_clone.clone();
                                    async move {
                                        handle_request(
                                            req,
                                            remote_addr,
                                            (*lid).clone(),
                                            (*gk).clone(),
                                            lm,
                                            cp,
                                            at,
                                        )
                                        .await
                                    }
                                });

                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    tracing::warn!(error = %e, "hyper connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "accept error on proxy listener");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-request handler
// ---------------------------------------------------------------------------

/// Handle one HTTP request through the full CDP proxy pipeline.
///
/// This function never panics.  Every failure path returns an appropriate HTTP
/// error response to the agent so that hyper can complete the connection
/// cleanly.
async fn handle_request(
    req: hyper::Request<Incoming>,
    remote_addr: SocketAddr,
    lease_id: LeaseId,
    gate_key: Zeroizing<Vec<u8>>,
    lease_manager: Arc<LeaseManager>,
    credential_provider: Arc<dyn CredentialProvider>,
    audit_tx: Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
) -> Result<hyper::Response<Full<Bytes>>, hyper::Error> {
    match handle_request_inner(
        req,
        remote_addr,
        lease_id,
        gate_key,
        lease_manager,
        credential_provider,
        audit_tx,
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            // Convert ProxyError into an HTTP error response without aborting
            // the hyper connection — the agent can handle the error code.
            Ok(proxy_error_to_response(e))
        }
    }
}

/// Inner handler — returns `Result<Response, ProxyError>` so all paths can use `?`.
async fn handle_request_inner(
    req: hyper::Request<Incoming>,
    remote_addr: SocketAddr,
    lease_id: LeaseId,
    gate_key: Zeroizing<Vec<u8>>,
    lease_manager: Arc<LeaseManager>,
    credential_provider: Arc<dyn CredentialProvider>,
    audit_tx: Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
) -> Result<hyper::Response<Full<Bytes>>, ProxyError> {
    // -----------------------------------------------------------------------
    // 1. Buffer the entire request body (enforcing the global size cap).
    // -----------------------------------------------------------------------
    let (parts, body) = req.into_parts();
    let body_bytes = collect_body(body, GLOBAL_MAX_BODY_BYTES).await?;

    // -----------------------------------------------------------------------
    // 2. Authentication: lease token + channel binding + OS peer identity.
    // -----------------------------------------------------------------------
    let lease = match crate::auth::authenticate(
        remote_addr,
        &parts.headers,
        &lease_id,
        // authenticate needs the full lease for token / channel-binding check.
        // We call use_lease *after* auth so the counter only advances on
        // successful authenticated requests.  But we need the lease data to
        // authenticate, so we read it first without incrementing.
        &lease_manager.get_lease(&lease_id).await?,
        &gate_key,
    )
    .await
    {
        Ok(()) => {
            // Auth passed — now record the use (increments request counter).
            lease_manager.use_lease(&lease_id).await?
        }
        Err(e) => {
            emit_blocked(
                &audit_tx,
                &lease_id,
                format!("auth failed: {e}"),
            );
            return Err(e);
        }
    };

    // -----------------------------------------------------------------------
    // 3. Extract Host and path for scope / DNS checks.
    // -----------------------------------------------------------------------
    let host = extract_host(&parts.headers, &parts.uri).ok_or_else(|| {
        ProxyError::ScopeViolation("missing Host header".to_string())
    })?;

    let _path = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());

    // -----------------------------------------------------------------------
    // 4. Scope validation.
    // -----------------------------------------------------------------------
    if let Err(e) = crate::scope::validate_request(
        &parts.method,
        &host,
        parts.uri.path(),
        content_type,
        if body_bytes.is_empty() {
            None
        } else {
            Some(&body_bytes)
        },
        &lease.granted_scope,
    ) {
        emit_blocked(
            &audit_tx,
            &lease_id,
            format!("scope violation: {e}"),
        );
        return Err(e);
    }

    // -----------------------------------------------------------------------
    // 5. DNS pin verification — resolve and check against lease pins.
    // -----------------------------------------------------------------------
    let pinned_ips = match crate::dns::resolve_and_verify(&lease, &host).await {
        Ok(ips) => ips,
        Err(e) => {
            emit_blocked(
                &audit_tx,
                &lease_id,
                format!("dns_rebinding_detected: {e}"),
            );
            return Err(e);
        }
    };

    // -----------------------------------------------------------------------
    // 6. Fetch credential headers from the provider.
    // -----------------------------------------------------------------------
    let cred_headers = credential_provider
        .fetch_credential(&lease.credential_ref, lease_id.as_str())
        .await?;

    // -----------------------------------------------------------------------
    // 7. Execute the request (with redirect following).
    // -----------------------------------------------------------------------
    let response = execute_with_redirects(ForwardContext {
        original_parts: &parts,
        body_bytes: &body_bytes,
        initial_host: &host,
        cred_headers: &cred_headers,
        initial_pinned_ips: &pinned_ips,
        lease: &lease,
        lease_id: &lease_id,
        audit_tx: &audit_tx,
    })
    .await?;

    Ok(response)
}

// ---------------------------------------------------------------------------
// Request execution with redirect loop
// ---------------------------------------------------------------------------

/// Arguments for the redirect-following request executor.
struct ForwardContext<'a> {
    original_parts: &'a http::request::Parts,
    body_bytes: &'a [u8],
    initial_host: &'a str,
    cred_headers: &'a [crate::credential::CredentialHeader],
    initial_pinned_ips: &'a [std::net::IpAddr],
    lease: &'a cdp_lease::Lease,
    lease_id: &'a LeaseId,
    audit_tx: &'a Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
}

/// Execute the outbound request, following redirects up to `MAX_REDIRECT_HOPS`
/// times when the lease permits redirect following.
async fn execute_with_redirects(
    ctx: ForwardContext<'_>,
) -> Result<hyper::Response<Full<Bytes>>, ProxyError> {
    let ForwardContext {
        original_parts,
        body_bytes,
        initial_host,
        cred_headers,
        initial_pinned_ips,
        lease,
        lease_id,
        audit_tx,
    } = ctx;
    const MAX_REDIRECT_HOPS: usize = 5;

    // Current request target (mutates on redirect).
    let mut current_uri = original_parts.uri.clone();
    let mut current_host = initial_host.to_string();
    let mut current_pinned_ips: Vec<std::net::IpAddr> = initial_pinned_ips.to_vec();
    let mut hops = 0usize;

    loop {
        // Build the outbound request.
        let mut builder = http::Request::builder()
            .method(original_parts.method.clone())
            .uri(&current_uri);

        // Copy non-internal inbound headers to the outbound request.
        let mut outbound_headers = original_parts.headers.clone();
        strip_proxy_internal_headers(&mut outbound_headers);
        // Update Host to match the current target.
        outbound_headers.insert(
            http::header::HOST,
            http::header::HeaderValue::from_str(&current_host)
                .map_err(|e| ProxyError::Upstream(format!("invalid host header: {e}")))?,
        );

        if let Some(header_map) = builder.headers_mut() {
            *header_map = outbound_headers;
        }

        // Inject credential headers.
        builder = inject_headers(builder, cred_headers)?;

        let outbound_req = builder
            .body(Full::new(Bytes::copy_from_slice(body_bytes)))
            .map_err(|e| ProxyError::Upstream(format!("failed to build request: {e}")))?;

        // Determine the upstream port from the URI scheme.
        let port = port_for_uri(&current_uri);

        // Connect to the first pinned IP.
        let target_ip = current_pinned_ips
            .first()
            .copied()
            .ok_or_else(|| ProxyError::Upstream("no pinned IPs available".to_string()))?;

        let stream = TcpStream::connect((target_ip, port))
            .await
            .map_err(|e| ProxyError::Upstream(format!("TCP connect to {target_ip}:{port}: {e}")))?;

        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| ProxyError::Hyper(e.to_string()))?;

        // Drive the connection in a background task.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!(error = %e, "upstream connection error");
            }
        });

        // Convert the Full<Bytes> body to Incoming-compatible type.
        let response = sender
            .send_request(outbound_req)
            .await
            .map_err(|e| ProxyError::Hyper(e.to_string()))?;

        let (resp_parts, resp_body) = response.into_parts();

        // Evaluate redirect (before buffering body, to avoid reading large bodies).
        let redirect_action = crate::redirect::evaluate_redirect(
            resp_parts.status,
            &resp_parts.headers,
            lease.follow_redirects,
            &lease.granted_scope.hosts,
        )?;

        match redirect_action {
            crate::redirect::RedirectAction::Follow { location, host: new_host } => {
                if hops >= MAX_REDIRECT_HOPS {
                    return Err(ProxyError::RedirectBlocked(format!(
                        "too many redirects (max {MAX_REDIRECT_HOPS})"
                    )));
                }
                hops += 1;

                // Re-verify DNS pin for the new host.
                let new_pinned = crate::dns::resolve_and_verify(lease, &new_host).await
                    .map_err(|e| {
                        emit_blocked(
                            audit_tx,
                            lease_id,
                            format!("dns_rebinding_detected on redirect to {new_host}: {e}"),
                        );
                        e
                    })?;

                current_uri = location;
                current_host = new_host;
                current_pinned_ips = new_pinned;

                // Consume and discard the redirect response body.
                let _ = resp_body.collect().await;
                continue;
            }

            crate::redirect::RedirectAction::Block { reason } => {
                emit_blocked(audit_tx, lease_id, format!("redirect blocked: {reason}"));
                // Consume the body before returning.
                let _ = resp_body.collect().await;
                return Err(ProxyError::RedirectBlocked(reason));
            }

            crate::redirect::RedirectAction::PassThrough => {
                // Buffer response body.
                let collected = resp_body
                    .collect()
                    .await
                    .map_err(|e| ProxyError::Hyper(e.to_string()))?;
                let resp_bytes = collected.to_bytes();

                // Build a mutable response to apply sanitisation.
                let mut response = hyper::Response::from_parts(
                    resp_parts,
                    Full::new(resp_bytes),
                );

                crate::sanitizer::sanitize_response(&mut response);

                return Ok(response);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Credential injection
// ---------------------------------------------------------------------------

/// Inject credential headers into an outbound request builder.
///
/// Each [`SecureBuffer`] value is converted to a header value.  The function
/// returns an error if any header name or value is not valid HTTP.
pub fn inject_headers(
    mut builder: http::request::Builder,
    headers: &[crate::credential::CredentialHeader],
) -> Result<http::request::Builder, ProxyError> {
    for h in headers {
        let name = http::header::HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|e| ProxyError::CredentialInjection(format!("invalid header name {:?}: {e}", h.name)))?;

        let value = http::header::HeaderValue::from_bytes(h.value.as_ref())
            .map_err(|e| {
                ProxyError::CredentialInjection(format!(
                    "invalid header value for {:?}: {e}",
                    h.name
                ))
            })?;

        builder = builder.header(name, value);
    }
    Ok(builder)
}

/// Remove the CDP internal headers that the agent sends to authenticate
/// with the proxy.  These must never be forwarded to the upstream service.
pub fn strip_proxy_internal_headers(headers: &mut http::HeaderMap) {
    use http::header::HeaderName;
    let internal = [
        crate::auth::HEADER_LEASE_TOKEN,
        crate::auth::HEADER_CHANNEL_BINDING,
    ];
    for name in &internal {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(hn);
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Buffer an inbound request body up to `max_bytes`.
///
/// Returns [`ProxyError::BodyTooLarge`] if the body exceeds the limit.
async fn collect_body(
    body: Incoming,
    max_bytes: u64,
) -> Result<Vec<u8>, ProxyError> {
    let collected = body
        .collect()
        .await
        .map_err(|e| ProxyError::Hyper(e.to_string()))?;
    let bytes = collected.to_bytes();
    let size = bytes.len() as u64;
    if size > max_bytes {
        return Err(ProxyError::BodyTooLarge {
            size,
            limit: max_bytes,
        });
    }
    Ok(bytes.to_vec())
}

/// Extract the target hostname from the `Host` header or the request URI.
fn extract_host(headers: &http::HeaderMap, uri: &http::Uri) -> Option<String> {
    // Prefer the Host header (most reliable for HTTP/1.1).
    if let Some(host_hdr) = headers.get(http::header::HOST)
        && let Ok(host_str) = host_hdr.to_str()
    {
        // Strip port if present (e.g. "api.example.com:8080" → "api.example.com").
        let host = host_str.split(':').next().unwrap_or(host_str);
        return Some(host.to_string());
    }
    // Fall back to URI authority.
    uri.host().map(|h| h.to_string())
}

/// Determine the upstream TCP port from the request URI.
///
/// Uses explicit port if present, otherwise defaults to 443 for HTTPS and
/// 80 for everything else.
fn port_for_uri(uri: &http::Uri) -> u16 {
    if let Some(port) = uri.port_u16() {
        return port;
    }
    match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    }
}

/// Emit a `ProxyBlocked` audit event.
fn emit_blocked(
    audit_tx: &Option<mpsc::UnboundedSender<(AuditEventType, AuditFields)>>,
    lease_id: &LeaseId,
    detail: String,
) {
    if let Some(tx) = audit_tx {
        let _ = tx.send((
            AuditEventType::ProxyBlocked,
            AuditFields {
                lease_id: Some(lease_id.to_string()),
                detail: Some(detail),
                ..Default::default()
            },
        ));
    }
}

/// Convert a [`ProxyError`] into an appropriate HTTP error response.
///
/// Error messages returned to the agent are deliberately generic to avoid
/// leaking internal paths, IPs, or architecture details (security review L-2).
/// Detailed information is logged server-side via `tracing`.
fn proxy_error_to_response(err: ProxyError) -> hyper::Response<Full<Bytes>> {
    let (status, body) = match &err {
        ProxyError::AuthFailed(_) => {
            tracing::warn!(error = %err, "proxy auth failed");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: authentication failed")
        }
        ProxyError::ScopeViolation(_) => {
            tracing::warn!(error = %err, "proxy scope violation");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: scope violation")
        }
        ProxyError::DnsPinMismatch { .. } => {
            tracing::warn!(error = %err, "DNS pin mismatch");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: dns_rebinding_detected")
        }
        ProxyError::RedirectBlocked(_) => {
            tracing::warn!(error = %err, "redirect blocked");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: redirect blocked")
        }
        ProxyError::BodyTooLarge { .. } => {
            tracing::warn!(error = %err, "body too large");
            (http::StatusCode::PAYLOAD_TOO_LARGE, "413 Payload Too Large")
        }
        ProxyError::ForbiddenField(_) => {
            tracing::warn!(error = %err, "forbidden field in body");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: scope violation")
        }
        ProxyError::ContentTypeNotAllowed(_) => {
            tracing::warn!(error = %err, "content type not allowed");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: scope violation")
        }
        ProxyError::Lease(cdp_lease::LeaseError::NotFound(_))
        | ProxyError::Lease(cdp_lease::LeaseError::Expired(_))
        | ProxyError::Lease(cdp_lease::LeaseError::Revoked(_)) => {
            tracing::warn!(error = %err, "lease not usable");
            (http::StatusCode::FORBIDDEN, "403 Forbidden: lease not valid")
        }
        _ => {
            tracing::error!(error = %err, "proxy upstream error");
            (http::StatusCode::BAD_GATEWAY, "502 Bad Gateway")
        }
    };

    let body_bytes = Bytes::from(body);
    hyper::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(body_bytes))
        .unwrap_or_else(|_| {
            hyper::Response::new(Full::new(Bytes::from_static(b"502 Bad Gateway")))
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cdp_crypto::SecureBuffer;
    use crate::credential::CredentialHeader;

    #[test]
    fn test_inject_headers_adds_header() {
        let builder = http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/data");
        let headers = vec![CredentialHeader {
            name: "Authorization".to_string(),
            value: SecureBuffer::new(b"Bearer token123".to_vec()),
        }];
        let builder = inject_headers(builder, &headers).expect("inject must succeed");
        let req = builder.body(()).expect("build must succeed");
        assert_eq!(
            req.headers().get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer token123")
        );
    }

    #[test]
    fn test_inject_multiple_headers() {
        let builder = http::Request::builder()
            .method("POST")
            .uri("https://api.example.com/data");
        let headers = vec![
            CredentialHeader {
                name: "Authorization".to_string(),
                value: SecureBuffer::new(b"Bearer tok".to_vec()),
            },
            CredentialHeader {
                name: "X-API-Key".to_string(),
                value: SecureBuffer::new(b"apikey123".to_vec()),
            },
        ];
        let builder = inject_headers(builder, &headers).expect("inject must succeed");
        let req = builder.body(()).expect("build must succeed");
        assert!(req.headers().get("authorization").is_some());
        assert!(req.headers().get("x-api-key").is_some());
    }

    #[test]
    fn test_strip_proxy_internal_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(crate::auth::HEADER_LEASE_TOKEN),
            "some-token".parse().expect("valid"),
        );
        headers.insert(
            http::header::HeaderName::from_static(crate::auth::HEADER_CHANNEL_BINDING),
            "nonce-hex".parse().expect("valid"),
        );
        headers.insert(
            http::header::HeaderName::from_static("host"),
            "api.example.com".parse().expect("valid"),
        );

        strip_proxy_internal_headers(&mut headers);

        assert!(headers.get(crate::auth::HEADER_LEASE_TOKEN).is_none());
        assert!(headers.get(crate::auth::HEADER_CHANNEL_BINDING).is_none());
        assert!(headers.get("host").is_some()); // non-internal preserved
    }

    #[test]
    fn test_extract_host_from_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HOST,
            "api.example.com:8080".parse().expect("valid"),
        );
        let uri = "http://api.example.com:8080/path"
            .parse::<http::Uri>()
            .expect("valid");
        let host = extract_host(&headers, &uri).expect("must find host");
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn test_extract_host_from_uri_fallback() {
        let headers = http::HeaderMap::new(); // no Host header
        let uri = "http://api.example.com/path"
            .parse::<http::Uri>()
            .expect("valid");
        let host = extract_host(&headers, &uri).expect("must find host from uri");
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn test_extract_host_missing_returns_none() {
        let headers = http::HeaderMap::new();
        let uri = "/relative-path".parse::<http::Uri>().expect("valid");
        assert!(extract_host(&headers, &uri).is_none());
    }

    #[test]
    fn test_port_for_uri_explicit() {
        let uri = "http://api.example.com:9090/path"
            .parse::<http::Uri>()
            .expect("valid");
        assert_eq!(port_for_uri(&uri), 9090);
    }

    #[test]
    fn test_port_for_uri_https_default() {
        let uri = "https://api.example.com/path"
            .parse::<http::Uri>()
            .expect("valid");
        assert_eq!(port_for_uri(&uri), 443);
    }

    #[test]
    fn test_port_for_uri_http_default() {
        let uri = "http://api.example.com/path"
            .parse::<http::Uri>()
            .expect("valid");
        assert_eq!(port_for_uri(&uri), 80);
    }

    /// Extract the body bytes from a `Full<Bytes>` response for test assertions.
    fn response_body_string(resp: hyper::Response<Full<Bytes>>) -> String {
        // Full<Bytes> stores data internally; access via the frame API.
        use http_body_util::BodyExt;
        // Collect synchronously since Full<Bytes> is immediately ready.
        let rt = tokio::runtime::Builder::new_current_thread().build().expect("rt");
        let collected = rt.block_on(async {
            resp.into_body().collect().await.expect("collect")
        });
        String::from_utf8_lossy(&collected.to_bytes()).to_string()
    }

    #[test]
    fn test_proxy_error_to_response_auth_failure() {
        let err = ProxyError::AuthFailed("bad token".to_string());
        let resp = proxy_error_to_response(err);
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        // Error body must NOT contain the internal message (L-2 fix).
        let body = response_body_string(resp);
        assert!(!body.contains("bad token"), "internal details must not leak to agent");
    }

    #[test]
    fn test_proxy_error_to_response_body_too_large() {
        let err = ProxyError::BodyTooLarge { size: 100, limit: 50 };
        let resp = proxy_error_to_response(err);
        assert_eq!(resp.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn test_proxy_error_to_response_dns_pin() {
        let err = ProxyError::DnsPinMismatch {
            host: "evil.example.com".to_string(),
            resolved: "1.2.3.4".parse().expect("valid"),
            pinned: vec![],
        };
        let resp = proxy_error_to_response(err);
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
        // Must not leak the internal IP or host details.
        let body = response_body_string(resp);
        assert!(!body.contains("evil.example.com"), "internal host must not leak");
        assert!(!body.contains("1.2.3.4"), "internal IP must not leak");
    }

    #[test]
    fn test_proxy_error_to_response_upstream_502() {
        let err = ProxyError::Upstream("connection refused".to_string());
        let resp = proxy_error_to_response(err);
        assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
        let body = response_body_string(resp);
        assert!(!body.contains("connection refused"), "upstream error details must not leak");
    }
}
