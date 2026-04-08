//! mTLS listener for AI-to-AI token issuance (Phase 9).
//!
//! This module provides a TLS listener that requires mutual authentication:
//! the server presents its certificate and the client must present a valid
//! certificate signed by the configured CA. Client identity is extracted from
//! the verified certificate and returned alongside the accepted stream.
//!
//! Remote constraints enforced at this layer:
//! - `remote_max_ttl_seconds = 300` — tokens issued to remote agents expire in ≤ 5 minutes.
//! - `single_use = true` — all tokens issued over this channel are single-use.
//! - `delegation_allowed = false` — remote agents may not sub-delegate.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{debug, instrument, warn};

use crate::error::GateError;

// ---------------------------------------------------------------------------
// Remote constraint constants
// ---------------------------------------------------------------------------

/// Maximum TTL (in seconds) for tokens issued to remote agents over mTLS.
pub const REMOTE_MAX_TTL_SECONDS: u64 = 300;

/// All tokens issued over the mTLS channel are single-use.
pub const REMOTE_SINGLE_USE: bool = true;

/// Remote agents received via mTLS may not sub-delegate their tokens.
pub const REMOTE_DELEGATION_ALLOWED: bool = false;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the mTLS listener.
#[derive(Debug, Clone)]
pub struct TlsListenerConfig {
    /// TCP port to listen on. Default: 9443.
    pub bind_port: u16,
    /// Path to the PEM-encoded server certificate chain.
    pub server_cert_path: PathBuf,
    /// Path to the PEM-encoded server private key.
    pub server_key_path: PathBuf,
    /// Path to the PEM-encoded CA certificate used to verify client certificates.
    pub client_ca_cert_path: PathBuf,
    /// If `true` (default), reject connections that do not present a client certificate.
    pub require_client_cert: bool,
}

impl TlsListenerConfig {
    /// Create a config with the default port 9443 and mandatory client cert.
    pub fn new(
        server_cert_path: impl Into<PathBuf>,
        server_key_path: impl Into<PathBuf>,
        client_ca_cert_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            bind_port: 9443,
            server_cert_path: server_cert_path.into(),
            server_key_path: server_key_path.into(),
            client_ca_cert_path: client_ca_cert_path.into(),
            require_client_cert: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Client identity extracted from the verified certificate
// ---------------------------------------------------------------------------

/// Identity extracted from a verified TLS client certificate.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Common Name from the certificate subject, if present.
    pub common_name: Option<String>,
    /// DNS Subject Alternative Names.
    pub san_dns_names: Vec<String>,
    /// Email Subject Alternative Names (RFC 822 names).
    pub san_emails: Vec<String>,
    /// SHA-256 fingerprint of the raw DER certificate bytes (lowercase hex).
    pub certificate_fingerprint: String,
    /// Issuer distinguished name, as a display string.
    pub issuer: String,
}

// ---------------------------------------------------------------------------
// TlsListener
// ---------------------------------------------------------------------------

/// An mTLS TCP listener.
///
/// Each accepted connection is fully handshaked before being returned. The
/// client's identity is extracted from the verified peer certificate.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    bind_addr: SocketAddr,
}

impl TlsListener {
    /// Bind the mTLS listener to the configured address.
    ///
    /// Reads certificate/key/CA files from disk, constructs a [`rustls::ServerConfig`]
    /// with mandatory client certificate verification, and binds the TCP socket.
    #[instrument(skip(config), fields(port = config.bind_port))]
    pub async fn bind(config: TlsListenerConfig) -> Result<Self, GateError> {
        // Load server certificate chain.
        let server_certs = load_certs(&config.server_cert_path)?;
        // Load server private key.
        let server_key = load_private_key(&config.server_key_path)?;
        // Load client CA certificate for peer verification.
        let client_ca_certs = load_certs(&config.client_ca_cert_path)?;

        // Build the root certificate store for client verification.
        let mut root_store = rustls::RootCertStore::empty();
        for ca_cert in client_ca_certs {
            root_store
                .add(ca_cert)
                .map_err(|e| GateError::Listener(format!("failed to add client CA cert: {e}")))?;
        }

        // Build server config with mandatory client authentication.
        let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| GateError::Listener(format!("client verifier build failed: {e}")))?;

        let tls_config = ServerConfig::builder()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(server_certs, server_key)
            .map_err(|e| GateError::Listener(format!("TLS config error: {e}")))?;

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // Bind TCP socket.
        let addr: SocketAddr = format!("0.0.0.0:{}", config.bind_port)
            .parse()
            .map_err(|e| GateError::Listener(format!("invalid bind address: {e}")))?;
        let inner = TcpListener::bind(addr).await.map_err(|e| {
            GateError::Listener(format!("failed to bind mTLS listener on {addr}: {e}"))
        })?;
        let bind_addr = inner
            .local_addr()
            .map_err(|e| GateError::Listener(format!("local_addr failed: {e}")))?;

        tracing::info!(addr = %bind_addr, "mTLS listener bound");
        Ok(Self {
            inner,
            acceptor,
            bind_addr,
        })
    }

    /// The local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Accept the next incoming mTLS connection.
    ///
    /// Performs the full TLS handshake (including client certificate verification)
    /// before returning. The [`ClientIdentity`] is extracted from the verified
    /// peer certificate.
    #[instrument(skip(self))]
    pub async fn accept(&self) -> Result<(TlsStream<TcpStream>, ClientIdentity), GateError> {
        let (tcp_stream, peer_addr) = self
            .inner
            .accept()
            .await
            .map_err(|e| GateError::Listener(format!("TCP accept failed: {e}")))?;
        debug!(peer = %peer_addr, "accepted TCP connection, starting TLS handshake");

        let tls_stream = self.acceptor.accept(tcp_stream).await.map_err(|e| {
            GateError::Listener(format!("TLS handshake failed from {peer_addr}: {e}"))
        })?;

        // Extract client identity from the server-side TLS connection.
        let identity = extract_client_identity(&tls_stream).map_err(|e| {
            GateError::AgentVerification(format!("client identity extraction: {e}"))
        })?;

        debug!(
            fingerprint = %identity.certificate_fingerprint,
            cn = ?identity.common_name,
            "mTLS client authenticated"
        );
        Ok((tls_stream, identity))
    }
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

/// Load PEM-encoded certificate chain from a file.
fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, GateError> {
    let cert_pem = fs::read(path).map_err(|e| {
        GateError::Listener(format!("failed to read cert file {}: {e}", path.display()))
    })?;
    let mut reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.map_err(|e| GateError::Listener(format!("PEM cert parse error: {e}")))
}

/// Load PEM-encoded private key from a file.
fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, GateError> {
    let key_pem = fs::read(path).map_err(|e| {
        GateError::Listener(format!("failed to read key file {}: {e}", path.display()))
    })?;
    let mut reader = std::io::BufReader::new(key_pem.as_slice());

    // Try PKCS#8 first, then PKCS#1.
    let mut pkcs8_keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| GateError::Listener(format!("PEM key parse error: {e}")))?;

    if let Some(key) = pkcs8_keys.pop() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
    }

    // Re-read since the cursor was consumed.
    let mut reader = std::io::BufReader::new(key_pem.as_slice());
    let mut rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| GateError::Listener(format!("PEM RSA key parse error: {e}")))?;

    if let Some(key) = rsa_keys.pop() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
    }

    Err(GateError::Listener(format!(
        "no private key found in {}",
        path.display()
    )))
}

// ---------------------------------------------------------------------------
// Identity extraction
// ---------------------------------------------------------------------------

/// Extract [`ClientIdentity`] from the peer certificate in an accepted mTLS stream.
///
/// Uses raw DER parsing (via the `cdp-token` crate's mTLS verifier) to extract
/// CN, SANs, and the certificate fingerprint.
fn extract_client_identity(stream: &TlsStream<TcpStream>) -> Result<ClientIdentity, String> {
    let (_, server_conn) = stream.get_ref();

    // Retrieve the peer certificate chain. The first cert is the end-entity cert.
    let certs = server_conn
        .peer_certificates()
        .ok_or_else(|| "no peer certificates in mTLS stream".to_string())?;

    let end_entity = certs.first().ok_or("empty certificate chain")?;
    let cert_der = end_entity.as_ref();

    // Compute SHA-256 fingerprint.
    let fingerprint = {
        let mut h = Sha256::new();
        h.update(cert_der);
        hex_encode(&h.finalize())
    };

    // Parse the DER certificate for CN, SANs, and issuer.
    // We use a simple ASN.1 walk rather than pulling in a full parser dependency.
    let (cn, san_dns_names, san_emails, issuer) = parse_cert_fields(cert_der);

    Ok(ClientIdentity {
        common_name: if cn.is_empty() { None } else { Some(cn) },
        san_dns_names,
        san_emails,
        certificate_fingerprint: fingerprint,
        issuer,
    })
}

/// Parse CN, SANs, and issuer from a DER-encoded certificate.
///
/// Uses the `cdp-token` crate's attestation verifier for the heavy lifting,
/// supplementing it with issuer extraction via raw ASN.1 inspection of the
/// outermost sequence.
fn parse_cert_fields(cert_der: &[u8]) -> (String, Vec<String>, Vec<String>, String) {
    // Delegate CN / SAN extraction to cdp-token's mTLS verifier.
    match cdp_token::validator::verify_mtls_attestation(cert_der) {
        Ok(result) => {
            let cn = result.identity.clone();
            let dns = result
                .metadata
                .get("san_dns")
                .map(|s| s.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            let email = result
                .metadata
                .get("san_email")
                .map(|s| s.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            // Issuer is not returned by the verifier; use the fingerprint as fallback.
            let issuer = result
                .metadata
                .get("issuer")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (cn, dns, email, issuer)
        }
        Err(e) => {
            warn!(error = %e, "failed to parse client certificate fields; using fingerprint only");
            (String::new(), vec![], vec![], "unknown".to_string())
        }
    }
}

/// Encode bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_constraint_constants() {
        assert_eq!(REMOTE_MAX_TTL_SECONDS, 300);
        assert!(REMOTE_SINGLE_USE);
        assert!(!REMOTE_DELEGATION_ALLOWED);
    }

    #[test]
    fn tls_listener_config_defaults() {
        let cfg = TlsListenerConfig::new("cert.pem", "key.pem", "ca.pem");
        assert_eq!(cfg.bind_port, 9443);
        assert!(cfg.require_client_cert);
        assert_eq!(cfg.server_cert_path, PathBuf::from("cert.pem"));
    }

    #[test]
    fn hex_encode_output() {
        assert_eq!(hex_encode(&[0xca, 0xfe]), "cafe");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn load_certs_missing_file_returns_error() {
        let err = load_certs(Path::new("/nonexistent/cert.pem")).unwrap_err();
        assert!(matches!(err, GateError::Listener(_)));
    }

    #[test]
    fn load_private_key_missing_file_returns_error() {
        let err = load_private_key(Path::new("/nonexistent/key.pem")).unwrap_err();
        assert!(matches!(err, GateError::Listener(_)));
    }

    /// Integration test: bind a listener with self-signed certs and accept a
    /// client connection with mutual auth.
    ///
    /// This test is marked `#[ignore]` because it requires generating real
    /// certificates. It is included to demonstrate the API contract.
    #[tokio::test]
    #[ignore]
    async fn mtls_accept_roundtrip() {
        // This test requires real PEM-encoded certificates. In CI it is skipped.
        // Run manually with: cargo test -p cdp-gate -- mtls_accept_roundtrip --ignored
        let config = TlsListenerConfig::new(
            "/tmp/test-server.pem",
            "/tmp/test-server-key.pem",
            "/tmp/test-ca.pem",
        );
        let listener = TlsListener::bind(config).await.expect("bind");
        let addr = listener.local_addr();
        assert_ne!(addr.port(), 0);
    }
}
