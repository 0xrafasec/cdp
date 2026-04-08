//! Attestation verifier.
//!
//! Supports:
//! - **mTLS**: parse DER certificate, extract CN / SANs, compute SHA-256 fingerprint.
//! - **OIDC**: decode JWT, verify RS256 signature against JWKS endpoint, check iss/aud/exp.
//! - **Enclave / SignedCode**: not yet supported (returns [`TokenError::AttestationFailed`]).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, warn};

use crate::{Result, TokenError};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Which attestation mechanism was used to verify an agent identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationType {
    /// Mutual TLS client certificate.
    Mtls,
    /// OpenID Connect ID token.
    Oidc,
    /// Hardware enclave (e.g. Intel SGX, AMD SEV).
    Enclave,
    /// Signed code (e.g. macOS notarisation, Windows Authenticode).
    SignedCode,
}

/// The result of a successful attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Verified identity string (e.g. certificate CN or OIDC `sub`).
    pub identity: String,
    /// Which attestation mechanism produced this result.
    pub attestation_type: AttestationType,
    /// When the verification was performed.
    pub verified_at: DateTime<Utc>,
    /// Additional key-value metadata (e.g. certificate SANs, OIDC claims).
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// OIDC configuration
// ---------------------------------------------------------------------------

/// A single trusted OIDC issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedIssuer {
    /// Human-readable name for logging.
    pub name: String,
    /// The `iss` claim value expected in tokens (also used to derive JWKS URL).
    pub issuer_url: String,
    /// The `aud` claim that must be present in tokens.
    pub required_audience: String,
}

/// Configuration for OIDC attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// List of issuers whose tokens we accept.
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// How long (in seconds) to cache JWKS responses. Default 3600.
    #[serde(default = "default_jwks_cache_secs")]
    pub cache_jwks_seconds: u64,
}

fn default_jwks_cache_secs() -> u64 {
    3600
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            trusted_issuers: vec![],
            cache_jwks_seconds: default_jwks_cache_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal JWKS types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Deserialize)]
struct JwkKey {
    #[serde(rename = "kid")]
    key_id: Option<String>,
    #[serde(rename = "kty")]
    key_type: String,
    /// Base64url-encoded RSA modulus.
    n: Option<String>,
    /// Base64url-encoded RSA public exponent.
    e: Option<String>,
    /// Algorithm hint (e.g. "RS256"). Present in many JWKS responses; kept for completeness.
    #[allow(dead_code)]
    alg: Option<String>,
}

// ---------------------------------------------------------------------------
// mTLS attestation
// ---------------------------------------------------------------------------

// OID for X.509 Common Name (2.5.4.3)
const OID_COMMON_NAME: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.5.4.3");
// OID for X.509 Subject Alternative Name (2.5.29.17)
const OID_SUBJECT_ALT_NAME: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.5.29.17");

/// Verify a DER-encoded X.509 client certificate.
///
/// Extracts:
/// - Common Name (CN) from the subject.
/// - DNS and email SANs from the Subject Alternative Names extension.
/// - SHA-256 fingerprint of the raw DER bytes.
///
/// Does **not** perform certificate chain validation — that is assumed to be
/// handled by the TLS layer (rustls with a trusted CA). This function only
/// extracts identity information from an already-trusted certificate.
#[instrument(skip(cert_der), fields(cert_len = cert_der.len()))]
pub fn verify_mtls_attestation(cert_der: &[u8]) -> Result<AttestationResult> {
    use der::Decode;
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| TokenError::InvalidCertificate(format!("DER parse error: {e}")))?;

    // Use the compile-time OID constants directly.
    let cn_oid = OID_COMMON_NAME;
    let san_oid = OID_SUBJECT_ALT_NAME;

    // --- Subject CN ---
    let subject = cert.tbs_certificate.subject;
    let mut cn = String::new();
    'outer: for rdn in subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == cn_oid {
                // Try UTF-8 string first, then PrintableString.
                if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef<'_>>() {
                    cn = s.as_str().to_string();
                    break 'outer;
                } else if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef<'_>>() {
                    cn = s.as_str().to_string();
                    break 'outer;
                }
            }
        }
    }

    // --- SANs ---
    let mut san_dns_names: Vec<String> = vec![];
    let mut san_emails: Vec<String> = vec![];

    if let Some(exts) = cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == san_oid {
                use x509_cert::ext::pkix::SubjectAltName;
                use x509_cert::ext::pkix::name::GeneralName;
                if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                    for name in san.0.iter() {
                        match name {
                            GeneralName::DnsName(dns) => {
                                san_dns_names.push(dns.as_str().to_string());
                            }
                            GeneralName::Rfc822Name(email) => {
                                san_emails.push(email.as_str().to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // --- Fingerprint ---
    let fingerprint = {
        let mut h = Sha256::new();
        h.update(cert_der);
        let digest = h.finalize();
        hex_encode(&digest)
    };

    // Use CN as identity; fall back to first SAN DNS name.
    let identity = if !cn.is_empty() {
        cn
    } else if let Some(dns) = san_dns_names.first() {
        dns.clone()
    } else {
        fingerprint.clone()
    };

    let mut metadata = HashMap::new();
    metadata.insert("fingerprint".to_string(), fingerprint);
    if !san_dns_names.is_empty() {
        metadata.insert("san_dns".to_string(), san_dns_names.join(","));
    }
    if !san_emails.is_empty() {
        metadata.insert("san_email".to_string(), san_emails.join(","));
    }

    debug!(identity = %identity, "mTLS attestation verified");
    Ok(AttestationResult {
        identity,
        attestation_type: AttestationType::Mtls,
        verified_at: Utc::now(),
        metadata,
    })
}

// ---------------------------------------------------------------------------
// OIDC attestation
// ---------------------------------------------------------------------------

/// Verify an OIDC ID token against the configured trusted issuers.
///
/// Steps:
/// 1. Decode the JWT header to extract `kid` and `alg`.
/// 2. Decode the claims to extract `iss`, `aud`, `exp`, `sub`.
/// 3. Look up the matching [`TrustedIssuer`] by `iss`.
/// 4. Fetch the JWKS from `{issuer_url}/.well-known/jwks.json`.
/// 5. Verify the RS256 signature with the matching key.
/// 6. Check `aud` and `exp`.
///
/// Only RS256 is supported. Requests are made with a 10-second timeout.
#[instrument(skip(token, config), fields(token_prefix = %token.get(..20).unwrap_or("?")))]
pub async fn verify_oidc_attestation(token: &str, config: &OidcConfig) -> Result<AttestationResult> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(TokenError::OidcVerification("malformed JWT".to_string()));
    }

    // Decode header.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| TokenError::OidcVerification(format!("header decode: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| TokenError::OidcVerification(format!("header parse: {e}")))?;

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(TokenError::OidcVerification(format!(
            "unsupported algorithm {alg:?}; only RS256 is accepted"
        )));
    }
    let kid = header.get("kid").and_then(|v| v.as_str()).map(str::to_string);

    // Decode claims (without verifying signature yet).
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| TokenError::OidcVerification(format!("claims decode: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
        .map_err(|e| TokenError::OidcVerification(format!("claims parse: {e}")))?;

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TokenError::OidcVerification("missing `iss` claim".to_string()))?;
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TokenError::OidcVerification("missing `sub` claim".to_string()))?;
    let aud = claims.get("aud");
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| TokenError::OidcVerification("missing `exp` claim".to_string()))?;

    // Find matching trusted issuer.
    let trusted = config
        .trusted_issuers
        .iter()
        .find(|ti| ti.issuer_url == iss)
        .ok_or_else(|| {
            TokenError::OidcVerification(format!("issuer {iss:?} is not trusted"))
        })?;

    // Check audience.
    let aud_ok = match aud {
        Some(serde_json::Value::String(s)) => s == &trusted.required_audience,
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(&trusted.required_audience))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(TokenError::OidcVerification(format!(
            "audience does not include {:?}",
            trusted.required_audience
        )));
    }

    // Check expiration.
    let now = Utc::now().timestamp();
    if exp <= now {
        return Err(TokenError::Expired);
    }

    // Fetch JWKS.
    let jwks_url = format!("{}/.well-known/jwks.json", trusted.issuer_url.trim_end_matches('/'));
    debug!(url = %jwks_url, "fetching JWKS");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| TokenError::OidcVerification(format!("HTTP client error: {e}")))?;

    let jwks_resp = client
        .get(&jwks_url)
        .send()
        .await
        .map_err(|e| TokenError::OidcVerification(format!("JWKS fetch error: {e}")))?;

    if !jwks_resp.status().is_success() {
        return Err(TokenError::OidcVerification(format!(
            "JWKS endpoint returned HTTP {}",
            jwks_resp.status()
        )));
    }

    let jwks: Jwks = jwks_resp
        .json()
        .await
        .map_err(|e| TokenError::OidcVerification(format!("JWKS parse error: {e}")))?;

    // Find the matching key.
    let jwk = find_jwk(&jwks, kid.as_deref())
        .ok_or_else(|| TokenError::OidcVerification("no matching JWK found".to_string()))?;

    // Verify RS256 signature.
    verify_rs256(parts[0], parts[1], parts[2], jwk)?;

    let mut metadata = HashMap::new();
    metadata.insert("iss".to_string(), iss.to_string());
    metadata.insert("aud".to_string(), trusted.required_audience.clone());

    debug!(sub = %sub, iss = %iss, "OIDC attestation verified");
    Ok(AttestationResult {
        identity: sub.to_string(),
        attestation_type: AttestationType::Oidc,
        verified_at: Utc::now(),
        metadata,
    })
}

// ---------------------------------------------------------------------------
// Unsupported attestation types
// ---------------------------------------------------------------------------

/// Enclave attestation — not yet implemented.
pub fn verify_enclave_attestation(_evidence: &[u8]) -> Result<AttestationResult> {
    Err(TokenError::AttestationFailed(
        "enclave attestation is not yet implemented".to_string(),
    ))
}

/// Signed-code attestation — not yet implemented.
pub fn verify_signed_code_attestation(_evidence: &[u8]) -> Result<AttestationResult> {
    Err(TokenError::AttestationFailed(
        "signed-code attestation is not yet implemented".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_jwk<'a>(jwks: &'a Jwks, kid: Option<&str>) -> Option<&'a JwkKey> {
    if let Some(kid) = kid {
        // Prefer the key with a matching `kid`.
        if let Some(k) = jwks.keys.iter().find(|k| {
            k.key_type == "RSA" && k.key_id.as_deref() == Some(kid)
        }) {
            return Some(k);
        }
    }
    // Fall back to the first RSA key.
    jwks.keys.iter().find(|k| k.key_type == "RSA")
}

/// Verify an RS256 JWT signature using a JWK.
fn verify_rs256(header_b64: &str, claims_b64: &str, sig_b64: &str, jwk: &JwkKey) -> Result<()> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rsa::{pkcs1v15::VerifyingKey as RsaVerifyingKey, signature::Verifier as RsaVerifier};
    use sha2::Sha256;

    let n_bytes = URL_SAFE_NO_PAD
        .decode(jwk.n.as_deref().unwrap_or(""))
        .map_err(|e| TokenError::OidcVerification(format!("JWK `n` decode: {e}")))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(jwk.e.as_deref().unwrap_or(""))
        .map_err(|e| TokenError::OidcVerification(format!("JWK `e` decode: {e}")))?;

    let n = rsa::BigUint::from_bytes_be(&n_bytes);
    let e = rsa::BigUint::from_bytes_be(&e_bytes);
    let rsa_key = rsa::RsaPublicKey::new(n, e)
        .map_err(|e| TokenError::OidcVerification(format!("RSA key construction: {e}")))?;

    let verifying_key: RsaVerifyingKey<Sha256> = RsaVerifyingKey::new(rsa_key);

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| TokenError::OidcVerification(format!("signature decode: {e}")))?;
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| TokenError::OidcVerification(format!("signature parse: {e}")))?;

    let signing_input = format!("{header_b64}.{claims_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| TokenError::OidcVerification("RS256 signature verification failed".to_string()))?;

    Ok(())
}

/// Encode bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
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
    fn attestation_type_serialize() {
        let t = AttestationType::Mtls;
        let s = serde_json::to_string(&t).expect("serialize");
        assert_eq!(s, "\"Mtls\"");
    }

    #[test]
    fn enclave_returns_error() {
        let err = verify_enclave_attestation(b"evidence").expect_err("not implemented");
        assert!(matches!(err, TokenError::AttestationFailed(_)));
    }

    #[test]
    fn signed_code_returns_error() {
        let err = verify_signed_code_attestation(b"evidence").expect_err("not implemented");
        assert!(matches!(err, TokenError::AttestationFailed(_)));
    }

    #[test]
    fn verify_mtls_rejects_garbage_der() {
        let err = verify_mtls_attestation(b"not a certificate").expect_err("should fail");
        assert!(matches!(err, TokenError::InvalidCertificate(_)));
    }

    #[test]
    fn hex_encode_known() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
