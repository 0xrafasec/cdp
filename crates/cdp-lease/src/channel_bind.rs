//! Channel binding — nonce generation and constant-time verification.
//!
//! The channel binding nonce is a 32-byte random value generated at lease
//! creation and embedded in the lease token (HMAC covers it).  Every proxied
//! request must present the nonce alongside the lease token so that a stolen
//! token cannot be replayed from a different channel.

use rand::RngCore as _;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a 32-byte cryptographically random channel binding nonce.
///
/// Uses [`rand::rngs::OsRng`] which sources entropy directly from the OS
/// (`getrandom(2)` on Linux), providing CSPRNG-quality randomness.
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Verify that `received` matches the `expected` nonce in constant time.
///
/// Returns `false` immediately (without revealing further information) when
/// `received.len() != 32` — length is not a secret value.  For equal-length
/// inputs, a byte-by-byte XOR accumulator is used so that the comparison time
/// is independent of where (or whether) any difference occurs.
pub fn verify_binding(expected: &[u8; 32], received: &[u8]) -> bool {
    if received.len() != 32 {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(received.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce_is_32_bytes() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn test_generate_nonce_is_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        // Two independent OsRng calls must not produce the same 256-bit value.
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_binding_matching() {
        let nonce = generate_nonce();
        assert!(verify_binding(&nonce, &nonce));
    }

    #[test]
    fn test_verify_binding_different() {
        let a = generate_nonce();
        let mut b = a;
        b[0] ^= 0xff;
        assert!(!verify_binding(&a, &b));
    }

    #[test]
    fn test_verify_binding_wrong_length() {
        let nonce = generate_nonce();
        let short = &nonce[..16];
        assert!(!verify_binding(&nonce, short));
    }

    #[test]
    fn test_verify_binding_empty() {
        let nonce = generate_nonce();
        assert!(!verify_binding(&nonce, &[]));
    }
}
