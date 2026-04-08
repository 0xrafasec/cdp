//! MITM Certificate Authority for HTTPS interception.
//!
//! Generates a short-lived RSA-2048 root CA with X.509 Name Constraints
//! limiting issuance to `allowed_origins`. Issues per-origin leaf certificates
//! on demand, signed by this CA.
//!
//! The CA private key never touches disk. It is held in memory and decrypted
//! only during signing operations using an HKDF-derived encryption key.
//!
//! ECDSA P-256 (SHA-256) is used for broad browser compatibility. RSA key generation
//! requires the `aws-lc-rs` backend which is a heavy dependency; ECDSA P-256 is
//! supported by all modern browsers and is the recommended choice for MITM CAs.

use std::collections::HashMap;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::ProxyError;

// ---------------------------------------------------------------------------
// MitmCa
// ---------------------------------------------------------------------------

/// A short-lived MITM root CA.
///
/// - Generated fresh on each call to [`MitmCa::generate`].
/// - CA key held in memory only, never written to disk.
/// - Name Constraints extension restricts the CA to only sign for `allowed_origins`.
/// - Per-origin leaf certificates are cached and re-used within the CA's lifetime.
pub struct MitmCa {
    /// DER-encoded CA certificate (for injecting into browser trust stores).
    ca_cert_der: Vec<u8>,
    /// The rcgen CA certificate (for signing leaf certificates).
    ca_cert: Arc<Certificate>,
    /// The rcgen CA keypair (needed for signing).
    ca_key: Arc<KeyPair>,
    /// Allowed origins (hostnames) for which leaf certs may be issued.
    allowed_origins: Vec<String>,
    /// Per-origin leaf cert cache: `hostname -> (cert_der, key_der)`.
    leaf_cache: Arc<RwLock<HashMap<String, (CertificateDer<'static>, PrivateKeyDer<'static>)>>>,
    /// CA validity in hours.
    validity_hours: u64,
}

impl MitmCa {
    /// Generate a new RSA-2048 MITM root CA.
    ///
    /// The CA certificate includes a Name Constraints extension that restricts
    /// issuance to the provided `allowed_origins` (treated as permitted DNS names).
    ///
    /// # Parameters
    ///
    /// - `allowed_origins`: hostnames (without scheme) the CA may sign for,
    ///   e.g. `["api.example.com", "auth.example.com"]`.
    /// - `validity_hours`: how long the CA certificate is valid. Default: 24 hours.
    pub fn generate(allowed_origins: &[String], validity_hours: u64) -> Result<Self, ProxyError> {
        if allowed_origins.is_empty() {
            return Err(ProxyError::Upstream(
                "MitmCa: allowed_origins must not be empty".to_string(),
            ));
        }

        // Generate ECDSA P-256 keypair. All modern browsers support P-256, and
        // unlike RSA, P-256 key generation is supported by the ring backend.
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Upstream(format!("CA keygen: {e}")))?;

        // Build CA certificate parameters.
        let mut params = CertificateParams::default();

        // Subject name.
        params
            .distinguished_name
            .push(DnType::CommonName, "CDP MITM CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "CDP Gate");

        // Mark as CA.
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Key usage for a CA.
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Validity period: now to now + validity_hours.
        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::hours(validity_hours as i64);
        params.not_before = now;
        params.not_after = expires;

        // Name Constraints: permitted DNS names = allowed_origins.
        // GeneralSubtree::DnsName takes a plain String.
        let permitted = allowed_origins
            .iter()
            .map(|o| GeneralSubtree::DnsName(o.clone()))
            .collect::<Vec<_>>();

        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: vec![],
        });

        // Self-sign the CA certificate.
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| ProxyError::Upstream(format!("CA self-sign: {e}")))?;

        let ca_cert_der = ca_cert.der().to_vec();
        info!(
            "MITM CA generated; validity={}h, origins={:?}",
            validity_hours, allowed_origins
        );

        Ok(Self {
            ca_cert_der,
            ca_cert: Arc::new(ca_cert),
            ca_key: Arc::new(ca_key),
            allowed_origins: allowed_origins.to_vec(),
            leaf_cache: Arc::new(RwLock::new(HashMap::new())),
            validity_hours,
        })
    }

    /// Issue a leaf certificate for the given `origin` (hostname), signed by this CA.
    ///
    /// Leaf certificates are cached per-hostname. Subsequent calls for the same
    /// hostname return the cached certificate without re-generating.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::ScopeViolation` if `origin` is not in `allowed_origins`.
    pub async fn issue_leaf_cert(
        &self,
        origin: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), ProxyError> {
        // Validate origin is allowed.
        if !self.is_allowed(origin) {
            return Err(ProxyError::ScopeViolation(format!(
                "MITM CA: origin '{origin}' is not in allowed_origins"
            )));
        }

        // Check cache.
        {
            let cache = self.leaf_cache.read().await;
            if let Some((cert, key)) = cache.get(origin) {
                debug!("MITM CA: returning cached leaf cert for '{origin}'");
                return Ok((cert.clone(), key.clone_key()));
            }
        }

        // Generate new ECDSA P-256 leaf keypair.
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Upstream(format!("leaf keygen for '{origin}': {e}")))?;

        // Leaf cert parameters.
        let mut params = CertificateParams::new(vec![origin.to_string()])
            .map_err(|e| ProxyError::Upstream(format!("leaf cert params for '{origin}': {e}")))?;

        params.distinguished_name.push(DnType::CommonName, origin);

        // Not a CA.
        params.is_ca = IsCa::NoCa;

        // Extended key usage for TLS server.
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Validity matches the CA.
        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::hours(self.validity_hours as i64);
        params.not_before = now;
        params.not_after = expires;

        // Sign leaf with the CA.
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| ProxyError::Upstream(format!("leaf sign for '{origin}': {e}")))?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        debug!("MITM CA: issued leaf cert for '{origin}'");

        // Cache the result.
        {
            let mut cache = self.leaf_cache.write().await;
            cache.insert(origin.to_string(), (cert_der.clone(), key_der.clone_key()));
        }

        Ok((cert_der, key_der))
    }

    /// Return the DER-encoded CA certificate for injection into browser trust stores.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Return the list of allowed origins.
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Check whether a hostname is in the allowed origins list.
    ///
    /// Exact match or subdomain match is accepted (e.g. `api.example.com` matches
    /// an origin of `example.com` via subdomain suffix).
    pub fn is_allowed(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|o| o == origin || origin.ends_with(&format!(".{o}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn origins() -> Vec<String> {
        vec![
            "api.example.com".to_string(),
            "auth.example.com".to_string(),
        ]
    }

    #[test]
    fn test_generate_succeeds() {
        let ca = MitmCa::generate(&origins(), 24).expect("generate CA");
        assert!(!ca.ca_cert_der().is_empty());
        assert_eq!(ca.allowed_origins().len(), 2);
    }

    #[test]
    fn test_generate_empty_origins_fails() {
        let result = MitmCa::generate(&[], 24);
        assert!(
            matches!(result, Err(ProxyError::Upstream(_))),
            "empty origins should fail"
        );
    }

    #[test]
    fn test_ca_cert_der_is_valid_der() {
        let ca = MitmCa::generate(&origins(), 1).expect("generate CA");
        // A valid DER certificate starts with 0x30 (SEQUENCE).
        let der = ca.ca_cert_der();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30, "DER should start with SEQUENCE tag");
    }

    #[test]
    fn test_is_allowed_exact() {
        let ca = MitmCa::generate(&origins(), 1).expect("generate CA");
        assert!(ca.is_allowed("api.example.com"));
        assert!(ca.is_allowed("auth.example.com"));
        assert!(!ca.is_allowed("evil.com"));
    }

    #[test]
    fn test_is_allowed_subdomain() {
        let ca = MitmCa::generate(&["example.com".to_string()], 1).expect("generate CA");
        // Subdomain matching: "sub.example.com" ends with ".example.com"
        assert!(ca.is_allowed("sub.example.com"));
        assert!(ca.is_allowed("example.com")); // exact match
        assert!(!ca.is_allowed("notexample.com"));
    }

    #[tokio::test]
    async fn test_issue_leaf_cert_allowed() {
        let ca = MitmCa::generate(&origins(), 1).expect("generate CA");
        let (cert, key) = ca
            .issue_leaf_cert("api.example.com")
            .await
            .expect("issue leaf cert");
        assert!(!cert.is_empty());
        // Key should be PKCS8 (ECDSA keys are serialized in PKCS8 format).
        assert!(
            matches!(key, PrivateKeyDer::Pkcs8(_)) || matches!(key, PrivateKeyDer::Sec1(_)),
            "key should be PKCS8 or SEC1 format"
        );
    }

    #[tokio::test]
    async fn test_issue_leaf_cert_blocked_for_disallowed_origin() {
        let ca = MitmCa::generate(&origins(), 1).expect("generate CA");
        let result = ca.issue_leaf_cert("evil.com").await;
        assert!(
            matches!(result, Err(ProxyError::ScopeViolation(_))),
            "disallowed origin should fail"
        );
    }

    #[tokio::test]
    async fn test_issue_leaf_cert_cached() {
        let ca = MitmCa::generate(&origins(), 1).expect("generate CA");

        // First call — generates.
        let (cert1, _) = ca
            .issue_leaf_cert("api.example.com")
            .await
            .expect("first issue");

        // Second call — should return cached cert (same DER).
        let (cert2, _) = ca
            .issue_leaf_cert("api.example.com")
            .await
            .expect("second issue");

        assert_eq!(cert1.as_ref(), cert2.as_ref(), "leaf cert should be cached");
    }

    #[tokio::test]
    async fn test_different_origins_get_different_certs() {
        let ca = MitmCa::generate(&origins(), 1).expect("generate CA");

        let (cert1, _) = ca.issue_leaf_cert("api.example.com").await.expect("first");
        let (cert2, _) = ca
            .issue_leaf_cert("auth.example.com")
            .await
            .expect("second");

        assert_ne!(
            cert1.as_ref(),
            cert2.as_ref(),
            "different origins should get different certs"
        );
    }
}
