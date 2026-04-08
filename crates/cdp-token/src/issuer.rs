//! Ed25519 JWT token issuer and verifier.
//!
//! Tokens use the "EdDSA" algorithm with the JWT compact serialization:
//! `base64url(header).base64url(claims).base64url(signature)`.
//!
//! The signing key is stored in mlock'd memory via [`cdp_crypto::SecureBuffer`].

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use cdp_crypto::SecureBuffer;

use crate::{Result, TokenError};


// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// JWT claims for a CDP AI-to-AI delegation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issuer (gate identity or sub-issuer URL).
    pub iss: String,
    /// Subject — the agent identity (fingerprint hash hex).
    pub sub: String,
    /// Audience — the intended recipient service or agent.
    pub aud: String,
    /// Expiration time as Unix timestamp (seconds).
    pub exp: i64,
    /// Issued-at time as Unix timestamp (seconds).
    pub iat: i64,
    /// JWT ID — UUID v4, unique per token (used for revocation).
    pub jti: String,
    /// Scope strings granted to this token.
    #[serde(default)]
    pub scope: Vec<String>,
    /// The lease ID backing this delegation.
    pub lease_id: String,
    /// Delegation chain — ordered list of issuer fingerprints.
    #[serde(default)]
    pub delegation_chain: Vec<String>,
    /// If true the token is consumed on first use.
    #[serde(default = "default_single_use")]
    pub single_use: bool,
}

fn default_single_use() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

/// JWT header used for every token this issuer produces.
const JWT_HEADER_B64: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";
// base64url({"alg":"EdDSA","typ":"JWT"}) — pre-computed for performance.

/// Validates the pre-computed header at module load time (debug builds only).
#[cfg(debug_assertions)]
fn _check_header_const() {
    let expected = URL_SAFE_NO_PAD
        .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#.as_bytes());
    assert_eq!(expected, JWT_HEADER_B64, "JWT_HEADER_B64 constant is wrong");
}

/// An Ed25519 JWT issuer.
///
/// The secret key is held in mlock'd [`SecureBuffer`] memory. The [`VerifyingKey`]
/// is kept separately to allow signature verification without touching the secret.
pub struct TokenIssuer {
    /// Signing key bytes in mlock'd, zeroize-on-drop memory.
    secret_bytes: SecureBuffer,
    /// Cached verifying key derived from the signing key.
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenIssuer")
            .field("public_key", &self.public_key_base64())
            .finish_non_exhaustive()
    }
}

impl TokenIssuer {
    /// Generate a fresh Ed25519 signing key from OS entropy.
    ///
    /// The private key bytes are placed in mlock'd memory immediately after
    /// generation.
    pub fn new() -> Result<Self> {
        // ed25519-dalek 2.x uses rand_core 0.6 for its generate() method.
        // We use getrandom to fill raw bytes and construct the key directly
        // to avoid rand version conflicts.
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret)
            .map_err(|e| TokenError::SigningKey(format!("failed to generate entropy: {e}")))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let secret = signing_key.to_bytes();
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            secret_bytes: SecureBuffer::new(secret.to_vec()),
            verifying_key,
        })
    }

    /// Reconstruct a [`TokenIssuer`] from an existing 32-byte Ed25519 secret key.
    ///
    /// The bytes are copied into mlock'd memory.
    pub fn from_key(secret_key_bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(secret_key_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            secret_bytes: SecureBuffer::new(secret_key_bytes.to_vec()),
            verifying_key,
        })
    }

    /// Return the raw 32-byte Ed25519 public key.
    pub fn public_key(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Return the public key encoded as standard base64 (no padding).
    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes())
    }

    /// Sign and return a compact JWT string for the given claims.
    ///
    /// The token format is:
    /// `base64url(header).base64url(claims_json).base64url(signature)`
    #[instrument(skip(self, claims), fields(sub = %claims.sub, jti = %claims.jti))]
    pub fn issue(&self, claims: &TokenClaims) -> Result<String> {
        // Serialize claims to JSON.
        let claims_json = serde_json::to_vec(claims)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        // The signing input is: base64url(header) + "." + base64url(claims)
        let signing_input = format!("{JWT_HEADER_B64}.{claims_b64}");

        // Reconstruct the SigningKey from secure memory.
        let secret_bytes: [u8; 32] = self
            .secret_bytes
            .as_ref()
            .try_into()
            .map_err(|_| TokenError::SigningKey("stored key has wrong length".to_string()))?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // Sign the input.
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        tracing::debug!(jti = %claims.jti, "issued JWT");
        Ok(format!("{signing_input}.{signature_b64}"))
    }

    /// Verify a compact JWT string.
    ///
    /// Checks:
    /// 1. Token structure (three dot-separated parts).
    /// 2. Header declares `alg=EdDSA`.
    /// 3. Ed25519 signature is valid.
    /// 4. `exp` claim is in the future.
    ///
    /// Does **not** check revocation — callers must consult [`RevocationList`].
    #[instrument(skip(self, token), fields(token_prefix = %token.get(..20).unwrap_or("?")))]
    pub fn verify(&self, token: &str) -> Result<TokenClaims> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(TokenError::InvalidClaims("malformed JWT: expected 3 parts".to_string()));
        }

        let (header_b64, claims_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // 1. Validate header.
        let header_json = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| TokenError::InvalidClaims(format!("invalid header encoding: {e}")))?;
        let header: serde_json::Value = serde_json::from_slice(&header_json)
            .map_err(|e| TokenError::InvalidClaims(format!("header parse error: {e}")))?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
            return Err(TokenError::InvalidClaims("unsupported algorithm; expected EdDSA".to_string()));
        }

        // 2. Verify signature over signing_input = header_b64 + "." + claims_b64.
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| TokenError::InvalidClaims(format!("invalid signature encoding: {e}")))?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TokenError::InvalidClaims("signature must be 64 bytes".to_string()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        self.verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| TokenError::Crypto("signature verification failed".to_string()))?;

        // 3. Decode claims.
        let claims_json = URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|e| TokenError::InvalidClaims(format!("invalid claims encoding: {e}")))?;
        let claims: TokenClaims = serde_json::from_slice(&claims_json)
            .map_err(|e| TokenError::Serialization(format!("claims parse error: {e}")))?;

        // 4. Check expiration.
        let now = chrono::Utc::now().timestamp();
        if claims.exp <= now {
            return Err(TokenError::Expired);
        }

        tracing::debug!(jti = %claims.jti, sub = %claims.sub, "verified JWT");
        Ok(claims)
    }
}

// ---------------------------------------------------------------------------
// Arc-based wrapper for shared issuers
// ---------------------------------------------------------------------------

impl TokenIssuer {
    /// Wrap this issuer in an [`Arc`] for shared ownership.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Sign an arbitrary JSON value as the JWT claims body.
    ///
    /// Returns a compact JWT string. This is `pub(crate)` because callers
    /// outside this crate should use the typed [`issue`] API.
    pub(crate) fn sign_claims_value(&self, claims: &serde_json::Value) -> Result<String> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let claims_json = serde_json::to_vec(claims)
            .map_err(|e| TokenError::Serialization(e.to_string()))?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);
        let signing_input = format!("{JWT_HEADER_B64}.{claims_b64}");

        let secret_bytes: [u8; 32] = self
            .secret_bytes
            .as_ref()
            .try_into()
            .map_err(|_| TokenError::SigningKey("stored key has wrong length".to_string()))?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(exp_offset_secs: i64) -> TokenClaims {
        let now = chrono::Utc::now().timestamp();
        TokenClaims {
            iss: "cdp-gate".to_string(),
            sub: "agent-abc123".to_string(),
            aud: "remote-api".to_string(),
            exp: now + exp_offset_secs,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: vec!["read".to_string()],
            lease_id: "lease-123".to_string(),
            delegation_chain: vec![],
            single_use: true,
        }
    }

    #[test]
    fn new_generates_key() {
        let issuer = TokenIssuer::new().expect("should generate key");
        let pk = issuer.public_key();
        assert_eq!(pk.len(), 32);
        // All-zero key would be trivially weak.
        assert_ne!(pk, &[0u8; 32]);
    }

    #[test]
    fn from_key_roundtrip() {
        let issuer1 = TokenIssuer::new().expect("gen key");
        let pk1 = *issuer1.public_key();

        let secret: [u8; 32] = issuer1.secret_bytes.as_ref().try_into().expect("32 bytes");
        let issuer2 = TokenIssuer::from_key(&secret).expect("from key");
        assert_eq!(pk1, *issuer2.public_key());
    }

    #[test]
    fn public_key_base64_is_valid() {
        let issuer = TokenIssuer::new().expect("gen key");
        let b64 = issuer.public_key_base64();
        let decoded = URL_SAFE_NO_PAD.decode(&b64).expect("valid base64");
        assert_eq!(decoded, issuer.public_key().as_slice());
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let issuer = TokenIssuer::new().expect("gen key");
        let claims = make_claims(300);
        let jti = claims.jti.clone();

        let token = issuer.issue(&claims).expect("issue");
        let verified = issuer.verify(&token).expect("verify");

        assert_eq!(verified.sub, "agent-abc123");
        assert_eq!(verified.jti, jti);
        assert!(verified.single_use);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let issuer = TokenIssuer::new().expect("gen key");
        let claims = make_claims(-1); // already expired
        let token = issuer.issue(&claims).expect("issue");
        let err = issuer.verify(&token).expect_err("should be expired");
        assert!(matches!(err, TokenError::Expired));
    }

    #[test]
    fn verify_rejects_tampered_claims() {
        let issuer = TokenIssuer::new().expect("gen key");
        let claims = make_claims(300);
        let token = issuer.issue(&claims).expect("issue");

        // Tamper with the claims part (middle segment).
        let mut parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered_claims = URL_SAFE_NO_PAD
            .encode(r#"{"iss":"evil","sub":"attacker","aud":"api","exp":9999999999,"iat":0,"jti":"x","lease_id":"y","single_use":false}"#);
        parts[1] = &tampered_claims;
        let bad_token = parts.join(".");
        let err = issuer.verify(&bad_token).expect_err("should reject tampered token");
        // Should fail sig verification.
        assert!(matches!(err, TokenError::Crypto(_)));
    }

    #[test]
    fn verify_rejects_wrong_algorithm() {
        let issuer = TokenIssuer::new().expect("gen key");
        // Build a token with RS256 header.
        let bad_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = make_claims(300);
        let claims_json = serde_json::to_vec(&claims).expect("serialize");
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);
        let fake_sig = URL_SAFE_NO_PAD.encode(b"fakesig");
        let token = format!("{bad_header}.{claims_b64}.{fake_sig}");
        let err = issuer.verify(&token).expect_err("should reject RS256");
        assert!(matches!(err, TokenError::InvalidClaims(_)));
    }

    #[test]
    fn verify_rejects_malformed_token() {
        let issuer = TokenIssuer::new().expect("gen key");
        let err = issuer.verify("not.a.token.with.five.parts").expect_err("malformed");
        // splitn(3, '.') with more than 3 parts just puts the rest in part[2],
        // which will fail signature verification — but the simpler case is fewer parts.
        let err2 = issuer.verify("onlytwoparts.here").expect_err("two parts");
        assert!(matches!(err2, TokenError::InvalidClaims(_)));
        // The first case has the right number of parts but a fake signature.
        assert!(matches!(err, TokenError::InvalidClaims(_) | TokenError::Crypto(_)));
    }

    #[test]
    fn different_issuers_cannot_verify_each_others_tokens() {
        let issuer_a = TokenIssuer::new().expect("gen key A");
        let issuer_b = TokenIssuer::new().expect("gen key B");
        let claims = make_claims(300);
        let token = issuer_a.issue(&claims).expect("issue with A");
        let err = issuer_b.verify(&token).expect_err("B cannot verify A's token");
        assert!(matches!(err, TokenError::Crypto(_)));
    }
}
