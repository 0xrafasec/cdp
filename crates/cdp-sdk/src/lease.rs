//! Active credential lease — proxy-authenticated HTTP and lease lifecycle.
//!
//! A `Lease` is the result of a successful `cdp.requestCredential` call. It
//! carries the proxy port and authentication tokens needed to route HTTP
//! requests through the CDP proxy, which injects the actual credential at the
//! transport layer.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use http::{HeaderName, HeaderValue, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use tracing::instrument;

use crate::transport::Transport;
use crate::types::{GrantedScope, RenewalInfo};
use crate::{CdpError, Result};

/// Options for [`Lease::fetch`].
#[derive(Debug, Default, Clone)]
pub struct FetchOptions {
    /// HTTP method. Defaults to `GET`.
    pub method: Option<String>,
    /// Additional request headers. The CDP auth headers are injected automatically.
    pub headers: HashMap<String, String>,
    /// Request body bytes. `None` means no body.
    pub body: Option<Vec<u8>>,
}

/// HTTP response returned by [`Lease::fetch`].
#[derive(Debug)]
pub struct Response {
    /// HTTP status code (e.g. 200).
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Raw response body.
    pub body: Vec<u8>,
}

/// An active credential lease.
///
/// Use [`fetch`](Lease::fetch) to make authenticated HTTP requests, or
/// [`renew`](Lease::renew) / [`revoke`](Lease::revoke) to manage the lease
/// lifecycle. Call [`is_expired`](Lease::is_expired) before making requests
/// when long-lived usage is expected.
#[derive(Debug)]
pub struct Lease {
    lease_id: String,
    proxy_port: u16,
    lease_token: String,
    channel_binding_nonce: String,
    ttl_seconds: u64,
    granted_scope: GrantedScope,
    expires_at: DateTime<Utc>,
    session_token: String,
    // Transport is stored as an Option so we can `take` it in revoke().
    transport: Option<Box<Transport>>,
}

impl Lease {
    /// Construct a new lease. Called internally by `Session::request_lease`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        lease_id: String,
        proxy_port: u16,
        lease_token: String,
        channel_binding_nonce: String,
        ttl_seconds: u64,
        granted_scope: GrantedScope,
        expires_at: DateTime<Utc>,
        session_token: String,
    ) -> Self {
        Self {
            lease_id,
            proxy_port,
            lease_token,
            channel_binding_nonce,
            ttl_seconds,
            granted_scope,
            expires_at,
            session_token,
            transport: None,
        }
    }

    /// Set the transport used for `renew` and `revoke` calls.
    /// Called internally when the lease needs to communicate back to the gate.
    #[allow(dead_code)]
    pub(crate) fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = Some(Box::new(transport));
        self
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The opaque lease identifier.
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// The local port on which the CDP proxy is listening.
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    /// The HMAC lease token (sent as `X-CDP-Lease-Token`).
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }

    /// The channel-binding nonce (sent as `X-CDP-Channel-Binding`).
    pub fn channel_binding_nonce(&self) -> &str {
        &self.channel_binding_nonce
    }

    /// TTL in seconds as originally granted.
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// The scope as granted by the gate.
    pub fn granted_scope(&self) -> &GrantedScope {
        &self.granted_scope
    }

    /// The UTC timestamp at which the lease expires.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Returns `true` if the lease has passed its expiry time.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    // ── HTTP proxy ────────────────────────────────────────────────────────────

    /// Make an HTTP request through the CDP proxy with auth headers injected.
    ///
    /// The proxy listens at `127.0.0.1:<proxy_port>`. The `Host` header of
    /// the original URL is preserved so the proxy can route the request to the
    /// correct upstream target.
    ///
    /// Returns [`CdpError::LeaseExpired`] if `is_expired()` is true before
    /// sending the request.
    #[instrument(name = "Lease::fetch", skip(self, options), fields(lease_id = %self.lease_id))]
    pub async fn fetch(&self, url: &str, options: FetchOptions) -> Result<Response> {
        if self.is_expired() {
            return Err(CdpError::LeaseExpired);
        }

        let method = options
            .method
            .as_deref()
            .unwrap_or("GET")
            .parse::<http::Method>()
            .map_err(|e| CdpError::ProxyRequest(format!("invalid method: {e}")))?;

        let original_uri: Uri = url
            .parse()
            .map_err(|e| CdpError::ProxyRequest(format!("invalid URL '{url}': {e}")))?;

        // Build the proxy URI: connect to 127.0.0.1:<port> but use the full
        // original URL as the request-target so the proxy can identify the
        // upstream host from the URL.
        let proxy_uri: Uri = format!("http://127.0.0.1:{}", self.proxy_port)
            .parse()
            .map_err(|e| CdpError::ProxyRequest(format!("invalid proxy URI: {e}")))?;

        // Preserve the original path+query for the request target.
        let path_and_query = original_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // The proxy determines the upstream host from the Host header.
        let host = original_uri
            .host()
            .ok_or_else(|| CdpError::ProxyRequest("URL has no host".to_string()))?
            .to_string();
        let port = original_uri.port_u16();
        let host_header_value = match port {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };

        let request_uri: Uri = path_and_query
            .parse()
            .map_err(|e| CdpError::ProxyRequest(format!("invalid path: {e}")))?;

        let mut builder = Request::builder()
            .method(method)
            .uri(request_uri)
            .header("host", &host_header_value)
            .header("x-cdp-lease-token", &self.lease_token)
            .header("x-cdp-channel-binding", &self.channel_binding_nonce)
            .header("x-cdp-original-url", url);

        // Add caller-supplied headers (CDP auth headers take precedence).
        for (name, value) in &options.headers {
            let header_name = name.parse::<HeaderName>().map_err(|e| {
                CdpError::ProxyRequest(format!("invalid header name '{name}': {e}"))
            })?;
            let header_value = value.parse::<HeaderValue>().map_err(|e| {
                CdpError::ProxyRequest(format!("invalid header value for '{name}': {e}"))
            })?;
            builder = builder.header(header_name, header_value);
        }

        let hyper_response = if let Some(body_bytes) = options.body {
            let req = builder
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|e| CdpError::ProxyRequest(format!("failed to build request: {e}")))?;

            // Re-point to proxy address by constructing a new client per request.
            // hyper-util's Client uses the URI host for routing; we pass a modified URI.
            self.send_via_proxy(req, &proxy_uri).await?
        } else {
            let req = builder
                .body(Full::new(Bytes::new()))
                .map_err(|e| CdpError::ProxyRequest(format!("failed to build request: {e}")))?;
            self.send_via_proxy(req, &proxy_uri).await?
        };

        let status = hyper_response.status().as_u16();
        let mut headers = HashMap::new();
        for (name, value) in hyper_response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_string(), v.to_string());
            }
        }

        let body_bytes = hyper_response
            .into_body()
            .collect()
            .await
            .map_err(|e| CdpError::ProxyRequest(format!("failed to read response body: {e}")))?
            .to_bytes();

        tracing::debug!(status = status, "proxy response received");

        Ok(Response {
            status,
            headers,
            body: body_bytes.to_vec(),
        })
    }

    /// Renew the lease, extending it by `extend_seconds` seconds.
    ///
    /// The gate enforces maximum renewal limits (3 renewals, 4h cumulative).
    #[instrument(name = "Lease::renew", skip(self), fields(lease_id = %self.lease_id))]
    pub async fn renew(&mut self, extend_seconds: u64) -> Result<RenewalInfo> {
        let transport = self.transport.as_mut().ok_or_else(|| {
            CdpError::Connection("no transport available for renew (use Session::request_lease to obtain a Lease with transport)".to_string())
        })?;

        let params = json!({
            "session_token": self.session_token,
            "lease_id": self.lease_id,
            "extend_seconds": extend_seconds,
        });

        let result_value = transport.send("cdp.renewLease", params).await?;
        let info: RenewalInfo = serde_json::from_value(result_value).map_err(|e| {
            CdpError::MalformedResponse(format!("invalid renewLease response: {e}"))
        })?;

        // Update local expiry to match the gate's new expiry.
        if let Ok(new_expiry) = info.new_expires_at.parse::<DateTime<Utc>>() {
            self.expires_at = new_expiry;
        } else {
            // Fallback: extend by the requested duration.
            self.expires_at = Utc::now() + chrono::Duration::seconds(extend_seconds as i64);
        }

        tracing::info!(
            renewals_remaining = info.renewals_remaining,
            new_expires_at = %info.new_expires_at,
            "lease renewed"
        );

        Ok(info)
    }

    /// Revoke the lease immediately.
    ///
    /// After revocation the lease is consumed and cannot be used again.
    #[instrument(name = "Lease::revoke", skip(self), fields(lease_id = %self.lease_id))]
    pub async fn revoke(mut self, reason: &str) -> Result<()> {
        let mut transport = self
            .transport
            .take()
            .ok_or_else(|| CdpError::Connection("no transport available for revoke".to_string()))?;

        let params = json!({
            "session_token": self.session_token,
            "lease_id": self.lease_id,
            "reason": reason,
        });

        let result_value = transport.send("cdp.revokeLease", params).await?;
        let status = result_value
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if status != "revoked" {
            return Err(CdpError::MalformedResponse(format!(
                "unexpected revoke status: {status}"
            )));
        }

        tracing::info!(reason = reason, "lease revoked");
        Ok(())
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    async fn send_via_proxy(
        &self,
        mut req: Request<Full<Bytes>>,
        proxy_uri: &Uri,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        // Override the URI to point at the proxy, keeping path+query from the
        // original request for the proxy to forward.
        let original_path = req.uri().path_and_query().cloned();
        let mut parts = proxy_uri.clone().into_parts();
        parts.path_and_query = original_path;
        let final_uri = Uri::from_parts(parts)
            .map_err(|e| CdpError::ProxyRequest(format!("URI construction failed: {e}")))?;

        *req.uri_mut() = final_uri;

        let client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();

        client
            .request(req)
            .await
            .map_err(|e| CdpError::ProxyRequest(format!("HTTP request failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_lease(expires_offset_secs: i64) -> Lease {
        let expires_at = Utc::now() + Duration::seconds(expires_offset_secs);
        Lease::new(
            "lease-test".to_string(),
            9999,
            "lease-token-val".to_string(),
            "nonce-val".to_string(),
            300,
            GrantedScope {
                hosts: vec!["example.com".to_string()],
                methods: vec!["GET".to_string()],
                paths: vec!["/".to_string()],
                ttl_seconds: Some(300),
                max_requests: Some(100),
            },
            expires_at,
            "sess-tok".to_string(),
        )
    }

    #[test]
    fn is_expired_false_for_future_lease() {
        let lease = make_lease(300);
        assert!(!lease.is_expired());
    }

    #[test]
    fn is_expired_true_for_past_lease() {
        let lease = make_lease(-1);
        assert!(lease.is_expired());
    }

    #[test]
    fn accessors_return_correct_values() {
        let lease = make_lease(300);
        assert_eq!(lease.lease_id(), "lease-test");
        assert_eq!(lease.proxy_port(), 9999);
        assert_eq!(lease.lease_token(), "lease-token-val");
        assert_eq!(lease.channel_binding_nonce(), "nonce-val");
        assert_eq!(lease.ttl_seconds(), 300);
    }

    #[tokio::test]
    async fn fetch_returns_lease_expired_error() {
        let lease = make_lease(-1);
        let result = lease
            .fetch("https://example.com/test", Default::default())
            .await;
        assert!(
            matches!(result, Err(CdpError::LeaseExpired)),
            "expected LeaseExpired: {result:?}"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_invalid_url() {
        let lease = make_lease(300);
        let result = lease.fetch("not a valid url !!!", Default::default()).await;
        assert!(
            matches!(result, Err(CdpError::ProxyRequest(_))),
            "expected ProxyRequest error for invalid URL: {result:?}"
        );
    }

    #[tokio::test]
    async fn fetch_injects_auth_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Spawn a minimal HTTP server to capture the request headers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let captured = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request_text = String::from_utf8_lossy(&buf[..n]).to_string();
            // Send a minimal HTTP response.
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            request_text
        });

        let lease = Lease::new(
            "lease-123".to_string(),
            port,
            "my-lease-token".to_string(),
            "my-nonce".to_string(),
            300,
            GrantedScope {
                hosts: vec!["127.0.0.1".to_string()],
                methods: vec!["GET".to_string()],
                paths: vec!["/".to_string()],
                ttl_seconds: Some(300),
                max_requests: None,
            },
            Utc::now() + Duration::seconds(300),
            "sess".to_string(),
        );

        let url = format!("http://127.0.0.1:{port}/test");
        let _ = lease.fetch(&url, Default::default()).await;

        let request_text = captured.await.unwrap();
        assert!(
            request_text.contains("x-cdp-lease-token: my-lease-token"),
            "lease token header missing in:\n{request_text}"
        );
        assert!(
            request_text.contains("x-cdp-channel-binding: my-nonce"),
            "channel binding header missing in:\n{request_text}"
        );
    }
}
