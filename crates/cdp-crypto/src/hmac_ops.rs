//! HMAC-SHA256 token generation and constant-time verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 with a domain tag and length-prefixed parts.
///
/// Each field is prefixed with its 8-byte big-endian length to prevent
/// ambiguous concatenation (e.g. shifting bytes between adjacent fields).
/// The `domain` tag provides namespace separation between token types.
fn compute_hmac_bytes(key: &[u8], domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(domain);
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Encode a byte slice as a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
}

/// Decode a lowercase hex string to bytes. Returns `None` on invalid input.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Session tokens
// ---------------------------------------------------------------------------

const SESSION_DOMAIN: &[u8] = b"cdp-session-v1\x00";
const LEASE_DOMAIN: &[u8] = b"cdp-lease-v1\x00";

/// Generate a session token: HMAC-SHA256(gate_key, domain || len(fingerprint) || fingerprint || len(connection_id) || connection_id).
pub fn generate_session_token(gate_key: &[u8], fingerprint: &[u8], connection_id: &[u8]) -> String {
    let bytes = compute_hmac_bytes(gate_key, SESSION_DOMAIN, &[fingerprint, connection_id]);
    bytes_to_hex(&bytes)
}

/// Verify a session token in constant time.
///
/// Returns `false` on any format or MAC error.
pub fn verify_session_token(
    gate_key: &[u8],
    fingerprint: &[u8],
    connection_id: &[u8],
    token: &str,
) -> bool {
    let Some(token_bytes) = hex_to_bytes(token) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(gate_key).expect("HMAC accepts any key length");
    mac.update(SESSION_DOMAIN);
    mac.update(&(fingerprint.len() as u64).to_be_bytes());
    mac.update(fingerprint);
    mac.update(&(connection_id.len() as u64).to_be_bytes());
    mac.update(connection_id);
    mac.verify_slice(&token_bytes).is_ok()
}

// ---------------------------------------------------------------------------
// Lease tokens
// ---------------------------------------------------------------------------

/// Generate a lease token: HMAC-SHA256(gate_key, domain || len(lease_id) || lease_id || len(fingerprint) || fingerprint || len(cb_nonce) || cb_nonce).
pub fn generate_lease_token(
    gate_key: &[u8],
    lease_id: &str,
    fingerprint: &[u8],
    cb_nonce: &[u8],
) -> String {
    let bytes = compute_hmac_bytes(
        gate_key,
        LEASE_DOMAIN,
        &[lease_id.as_bytes(), fingerprint, cb_nonce],
    );
    bytes_to_hex(&bytes)
}

/// Verify a lease token in constant time.
///
/// Returns `false` on any format or MAC error.
pub fn verify_lease_token(
    gate_key: &[u8],
    lease_id: &str,
    fingerprint: &[u8],
    cb_nonce: &[u8],
    token: &str,
) -> bool {
    let Some(token_bytes) = hex_to_bytes(token) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(gate_key).expect("HMAC accepts any key length");
    mac.update(LEASE_DOMAIN);
    mac.update(&(lease_id.len() as u64).to_be_bytes());
    mac.update(lease_id.as_bytes());
    mac.update(&(fingerprint.len() as u64).to_be_bytes());
    mac.update(fingerprint);
    mac.update(&(cb_nonce.len() as u64).to_be_bytes());
    mac.update(cb_nonce);
    mac.verify_slice(&token_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"super-secret-gate-key-for-testing-only";
    const FP: &[u8] = b"agent-fingerprint-bytes";
    const CONN: &[u8] = b"connection-id-001";
    const LEASE: &str = "lease-abc-123";
    const CB: &[u8] = b"channel-binding-nonce";

    #[test]
    fn test_session_token_roundtrip() {
        let token = generate_session_token(KEY, FP, CONN);
        assert!(verify_session_token(KEY, FP, CONN, &token));
    }

    #[test]
    fn test_session_token_reject_tampered() {
        let mut token = generate_session_token(KEY, FP, CONN);
        // Flip the first character.
        let first = token.remove(0);
        token.insert(0, if first == 'a' { 'b' } else { 'a' });
        assert!(!verify_session_token(KEY, FP, CONN, &token));
    }

    #[test]
    fn test_lease_token_roundtrip() {
        let token = generate_lease_token(KEY, LEASE, FP, CB);
        assert!(verify_lease_token(KEY, LEASE, FP, CB, &token));
    }

    #[test]
    fn test_lease_token_reject_tampered() {
        let mut token = generate_lease_token(KEY, LEASE, FP, CB);
        let first = token.remove(0);
        token.insert(0, if first == 'a' { 'b' } else { 'a' });
        assert!(!verify_lease_token(KEY, LEASE, FP, CB, &token));
    }
}
