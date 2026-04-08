//! MITM HTTPS proxy — intercept, cookie-inject, and forward HTTPS traffic.
//!
//! For CONNECT requests to origins in `allowed_origins`:
//! - Terminate TLS using a per-origin leaf certificate signed by the [`MitmCa`].
//! - Inject cookies from the [`CookieStore`] as a `Cookie:` header.
//! - Forward the request to the real upstream server.
//! - Strip `Set-Cookie` headers from the response (browser-mode: proxy holds cookies).
//! - Return the sanitised response to the agent.
//!
//! For CONNECT requests to origins not in `allowed_origins`:
//! - Tunnel through transparently without TLS interception.
//!
//! Triple authentication (lease token + channel binding + `SO_PEERCRED`) is
//! enforced by the existing [`ProxyServer`] layer — this module only adds
//! interception on top of established, authenticated tunnels.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use cdp_browser::CookieStore;

use crate::ProxyError;
use crate::mitm_ca::MitmCa;

// webpki_roots provides Mozilla root certificate bundle.
extern crate webpki_roots;

// ---------------------------------------------------------------------------
// MitmProxy
// ---------------------------------------------------------------------------

/// Intercepts HTTPS CONNECT tunnels for matching origins, injecting session cookies.
///
/// Non-matching CONNECT requests are tunnelled transparently. The proxy is
/// stateless per-request: it always queries the [`CookieStore`] for fresh cookies.
#[derive(Clone)]
pub struct MitmProxy {
    ca: Arc<MitmCa>,
    cookie_store: Arc<CookieStore>,
    allowed_origins: Arc<HashSet<String>>,
}

impl MitmProxy {
    /// Create a new MITM proxy.
    ///
    /// # Parameters
    ///
    /// - `ca`: the MITM CA used to sign per-origin TLS certificates.
    /// - `cookie_store`: shared cookie store populated by the browser login flow.
    /// - `allowed_origins`: set of hostnames for which interception is performed.
    pub fn new(
        ca: Arc<MitmCa>,
        cookie_store: Arc<CookieStore>,
        allowed_origins: HashSet<String>,
    ) -> Self {
        Self {
            ca,
            cookie_store,
            allowed_origins: Arc::new(allowed_origins),
        }
    }

    /// Handle an HTTP CONNECT request from an agent.
    ///
    /// - If `host` is in `allowed_origins`: perform TLS interception.
    /// - Otherwise: establish a transparent TCP tunnel.
    ///
    /// Returns the HTTP response to send back to the agent (200 Connection
    /// Established for both paths) followed by async data forwarding.
    pub async fn handle_connect(
        &self,
        host: String,
        port: u16,
        agent_stream: TcpStream,
    ) -> Result<(), ProxyError> {
        if self.allowed_origins.contains(&host) {
            self.intercept(host, port, agent_stream).await
        } else {
            self.tunnel(host, port, agent_stream).await
        }
    }

    /// Perform TLS interception for a matching origin.
    ///
    /// Flow:
    /// 1. Send 200 Connection Established to the agent.
    /// 2. Accept TLS from the agent using a per-origin leaf cert.
    /// 3. Connect to the real upstream.
    /// 4. Perform upstream TLS handshake.
    /// 5. Forward requests from agent, injecting Cookie headers.
    /// 6. Strip Set-Cookie from upstream responses.
    async fn intercept(
        &self,
        host: String,
        port: u16,
        agent_stream: TcpStream,
    ) -> Result<(), ProxyError> {
        debug!("MITM intercept: {host}:{port}");

        // Step 1: Send 200 Connection Established.
        let mut agent_stream = agent_stream;
        agent_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| ProxyError::Upstream(format!("write 200 to agent: {e}")))?;

        // Step 2: Build TLS acceptor with per-origin leaf cert.
        let (cert_der, key_der) = self
            .ca
            .issue_leaf_cert(&host)
            .await
            .map_err(|e| ProxyError::Upstream(format!("issue leaf cert: {e}")))?;

        let tls_config = build_server_tls_config(cert_der, key_der)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let agent_tls = acceptor
            .accept(agent_stream)
            .await
            .map_err(|e| ProxyError::Upstream(format!("TLS accept from agent: {e}")))?;

        // Step 3: Connect to the real upstream.
        let upstream_addr = format!("{host}:{port}");
        let upstream_tcp = TcpStream::connect(&upstream_addr).await.map_err(|e| {
            ProxyError::Upstream(format!("connect to upstream {upstream_addr}: {e}"))
        })?;

        // Step 4: Upstream TLS handshake.
        let upstream_tls_config = build_client_tls_config(&host)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(upstream_tls_config));
        let server_name: rustls::pki_types::ServerName<'_> = host
            .clone()
            .try_into()
            .map_err(|_| ProxyError::Upstream(format!("invalid server name: {host}")))?;

        let upstream_tls = connector
            .connect(server_name, upstream_tcp)
            .await
            .map_err(|e| ProxyError::Upstream(format!("upstream TLS handshake: {e}")))?;

        // Step 5 & 6: Proxy requests/responses with cookie injection and Set-Cookie stripping.
        let origin_url = format!("https://{host}");
        let cookie_header = self.cookie_store.build_cookie_header(&origin_url).await;

        self.forward_with_interception(agent_tls, upstream_tls, cookie_header)
            .await
    }

    /// Forward requests from agent to upstream, injecting cookies and stripping Set-Cookie.
    ///
    /// This uses a simple line-by-line HTTP/1.1 parser for the header section to
    /// avoid pulling in a full HTTP parser dependency for this relatively simple
    /// interception use case.
    async fn forward_with_interception<A, U>(
        &self,
        agent_conn: A,
        upstream_conn: U,
        cookie_header: Option<String>,
    ) -> Result<(), ProxyError>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin + Send,
        U: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let (mut agent_read, mut agent_write) = tokio::io::split(agent_conn);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_conn);

        // Forward agent → upstream, injecting cookies.
        let cookie_hdr = cookie_header.clone();
        let agent_to_upstream = async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = agent_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let data = &buf[..n];
                // Inject Cookie header after the request-line + headers, before the blank line.
                // Find the end of the first header block.
                if let Some(hdr) = &cookie_hdr {
                    let injected = inject_cookie_header(data, hdr);
                    upstream_write.write_all(&injected).await?;
                } else {
                    upstream_write.write_all(data).await?;
                }
            }
            Ok::<_, io::Error>(())
        };

        // Forward upstream → agent, stripping Set-Cookie.
        let upstream_to_agent = async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = upstream_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let data = &buf[..n];
                let stripped = strip_set_cookie(data);
                agent_write.write_all(&stripped).await?;
            }
            Ok::<_, io::Error>(())
        };

        // Run both directions concurrently.
        tokio::select! {
            r = agent_to_upstream => {
                if let Err(e) = r {
                    debug!("agent→upstream copy ended: {e}");
                }
            }
            r = upstream_to_agent => {
                if let Err(e) = r {
                    debug!("upstream→agent copy ended: {e}");
                }
            }
        }

        Ok(())
    }

    /// Transparent TCP tunnel for non-intercepted origins.
    async fn tunnel(
        &self,
        host: String,
        port: u16,
        mut agent_stream: TcpStream,
    ) -> Result<(), ProxyError> {
        debug!("MITM passthrough tunnel: {host}:{port}");

        let upstream_addr = format!("{host}:{port}");
        let mut upstream = TcpStream::connect(&upstream_addr)
            .await
            .map_err(|e| ProxyError::Upstream(format!("tunnel connect to {upstream_addr}: {e}")))?;

        // Send 200 Connection Established.
        agent_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| ProxyError::Upstream(format!("write 200 (tunnel): {e}")))?;

        // Bidirectional copy.
        match tokio::io::copy_bidirectional(&mut agent_stream, &mut upstream).await {
            Ok((a, b)) => {
                debug!("tunnel {host}:{port} closed: {a} bytes →, {b} bytes ←");
            }
            Err(e) => {
                warn!("tunnel {host}:{port} error: {e}");
            }
        }

        Ok(())
    }

    /// Parse a `Host: hostname:port` or `hostname:port` string from a CONNECT request.
    ///
    /// Returns `(host, port)`. Port defaults to 443 if not specified.
    pub fn parse_connect_target(authority: &str) -> Result<(String, u16), ProxyError> {
        let (host, port_str) = authority.rsplit_once(':').ok_or_else(|| {
            ProxyError::Upstream(format!("CONNECT authority missing port: '{authority}'"))
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            ProxyError::Upstream(format!("CONNECT authority has invalid port: '{authority}'"))
        })?;
        Ok((host.to_string(), port))
    }

    /// Build an HTTP 200 Connection Established response body.
    pub fn connection_established_response() -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .expect("static response is valid")
    }

    /// Build an HTTP 502 Bad Gateway response.
    pub fn bad_gateway_response(reason: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(format!("Bad Gateway: {reason}"))))
            .expect("static response is valid")
    }
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

/// Build a `rustls::ServerConfig` using the provided certificate and key.
fn build_server_tls_config(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerConfig, ProxyError> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| ProxyError::Upstream(format!("build server TLS config: {e}")))?;

    Ok(config)
}

/// Build a `rustls::ClientConfig` for connecting to the real upstream.
///
/// Uses the Mozilla WebPKI root certificates compiled in via `webpki-roots`.
/// This provides consistent root certificate behaviour across platforms.
fn build_client_tls_config(_host: &str) -> Result<rustls::ClientConfig, ProxyError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

// ---------------------------------------------------------------------------
// Header manipulation helpers
// ---------------------------------------------------------------------------

/// Inject a `Cookie: <value>` header into an HTTP/1.1 request buffer.
///
/// The injection point is just before the blank-line separator (`\r\n\r\n`).
/// This inserts the Cookie header as the last header before the body.
/// If no separator is found (e.g. streaming body), the data is returned unchanged.
fn inject_cookie_header(data: &[u8], cookie_value: &str) -> Vec<u8> {
    // Find the header/body separator: \r\n\r\n.
    // `pos` is AFTER the separator; inject before the separator (pos - 4).
    if let Some(pos) = find_header_end(data) {
        // Insert cookie header before the \r\n\r\n separator.
        let insert_at = pos.saturating_sub(4); // position of the \r\n\r\n
        let mut result = Vec::with_capacity(data.len() + cookie_value.len() + 20);
        result.extend_from_slice(&data[..insert_at]);
        result.extend_from_slice(b"Cookie: ");
        result.extend_from_slice(cookie_value.as_bytes());
        result.extend_from_slice(b"\r\n");
        result.extend_from_slice(&data[insert_at..]); // includes \r\n\r\n + body
        result
    } else {
        data.to_vec()
    }
}

/// Strip all `Set-Cookie:` headers from an HTTP/1.1 response buffer.
///
/// Only processes the header section; the body is passed through unchanged.
fn strip_set_cookie(data: &[u8]) -> Vec<u8> {
    if let Some(header_end_pos) = find_header_end(data) {
        let header_section = &data[..header_end_pos];
        let body_section = &data[header_end_pos..];

        let filtered = filter_header_lines(header_section, |line| {
            let lower = line.to_ascii_lowercase();
            !lower.starts_with(b"set-cookie:")
        });

        let mut result = filtered;
        result.extend_from_slice(body_section);
        result
    } else {
        data.to_vec()
    }
}

/// Find the position just after the `\r\n\r\n` header terminator.
fn find_header_end(data: &[u8]) -> Option<usize> {
    let separator = b"\r\n\r\n";
    data.windows(separator.len())
        .position(|w| w == separator)
        .map(|p| p + separator.len())
}

/// Filter header lines by a predicate, keeping lines where `keep(line)` returns true.
///
/// Lines are split on `\r\n`. The request/status line is always kept.
fn filter_header_lines(header_section: &[u8], keep: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut result = Vec::with_capacity(header_section.len());
    let mut start = 0;

    while start < header_section.len() {
        let end = header_section[start..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| start + p)
            .unwrap_or(header_section.len());

        let line = &header_section[start..end];

        if keep(line) {
            result.extend_from_slice(line);
            if end < header_section.len() {
                result.extend_from_slice(b"\r\n");
            }
        }

        start = end + 2;
        if start > header_section.len() {
            break;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_target_with_port() {
        let (host, port) = MitmProxy::parse_connect_target("api.example.com:443").unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_target_no_port_fails() {
        let result = MitmProxy::parse_connect_target("api.example.com");
        assert!(matches!(result, Err(ProxyError::Upstream(_))));
    }

    #[test]
    fn test_parse_connect_target_invalid_port_fails() {
        let result = MitmProxy::parse_connect_target("api.example.com:notaport");
        assert!(matches!(result, Err(ProxyError::Upstream(_))));
    }

    #[test]
    fn test_connection_established_response() {
        let resp = MitmProxy::connection_established_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_bad_gateway_response() {
        let resp = MitmProxy::bad_gateway_response("upstream unreachable");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_find_header_end_found() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let pos = find_header_end(data);
        // \r\n\r\n starts at position 33 (after "Host: example.com\r\n"),
        // so position after separator = 33 + 4 = 37.
        assert!(pos.is_some());
        let p = pos.unwrap();
        assert_eq!(&data[p..], b"body", "body should be at pos {p}");
    }

    #[test]
    fn test_find_header_end_not_found() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(find_header_end(data).is_none());
    }

    #[test]
    fn test_inject_cookie_header() {
        let request = b"GET /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let injected = inject_cookie_header(request, "session_id=abc");
        let injected_str = String::from_utf8(injected).unwrap();
        assert!(
            injected_str.contains("Cookie: session_id=abc\r\n"),
            "cookie header must be present"
        );
        // The blank line (\r\n\r\n) must still be present at the end.
        assert!(
            injected_str.ends_with("\r\n\r\n"),
            "must end with blank line: {:?}",
            injected_str
        );
        // Cookie must appear before the blank line.
        let cookie_pos = injected_str.find("Cookie:").unwrap();
        let blank_pos = injected_str.find("\r\n\r\n").unwrap();
        assert!(cookie_pos < blank_pos, "Cookie must be before blank line");
    }

    #[test]
    fn test_inject_cookie_header_no_separator() {
        // Data without \r\n\r\n should be returned unchanged.
        let data = b"partial data without header end";
        let result = inject_cookie_header(data, "session=x");
        assert_eq!(result, data);
    }

    #[test]
    fn test_strip_set_cookie() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=abc; HttpOnly\r\nX-Custom: value\r\n\r\n{\"ok\":true}";
        let stripped = strip_set_cookie(response);
        let stripped_str = String::from_utf8(stripped).unwrap();
        assert!(!stripped_str.contains("Set-Cookie"));
        assert!(stripped_str.contains("Content-Type: application/json"));
        assert!(stripped_str.contains("X-Custom: value"));
        assert!(stripped_str.contains("{\"ok\":true}"));
    }

    #[test]
    fn test_strip_set_cookie_multiple() {
        let response =
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-OK: yes\r\n\r\n";
        let stripped = strip_set_cookie(response);
        let stripped_str = String::from_utf8(stripped).unwrap();
        assert!(!stripped_str.contains("Set-Cookie"));
        assert!(stripped_str.contains("X-OK: yes"));
    }

    #[test]
    fn test_strip_set_cookie_no_header_section() {
        // No \r\n\r\n separator — data returned unchanged.
        let data = b"no header end here";
        let result = strip_set_cookie(data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_filter_header_lines_keep_all() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
        let result = filter_header_lines(headers, |_| true);
        assert!(result.contains(&b'2'));
    }

    #[test]
    fn test_filter_header_lines_drop_all() {
        let headers = b"X-Custom: value\r\nX-Other: val\r\n";
        let result = filter_header_lines(headers, |_| false);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_mitm_proxy_new() {
        let ca = MitmCa::generate(&["api.example.com".to_string()], 1).expect("generate CA");
        let store = Arc::new(CookieStore::new());
        let origins: HashSet<String> = ["api.example.com".to_string()].into_iter().collect();

        let _proxy = MitmProxy::new(Arc::new(ca), store, origins);
        // Just verify construction doesn't panic.
    }
}
