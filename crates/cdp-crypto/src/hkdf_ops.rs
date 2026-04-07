//! HKDF-SHA256 key derivation for per-credential encryption keys.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Derive a per-credential 256-bit encryption key using HKDF-SHA256.
///
/// - `master` — input keying material (e.g. Argon2id output from vault auth).
/// - `salt` — random per-Gate-instance salt (generated at startup, persisted).
///   Using a salt strengthens derived keys against pre-computation attacks.
/// - `credential_ref` / `lease_id` — used to build the HKDF `info` field with
///   length-prefixed encoding to prevent ambiguity between different
///   (credential_ref, lease_id) pairs.
pub fn derive_credential_key(
    master: &[u8],
    salt: &[u8],
    credential_ref: &str,
    lease_id: &str,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut okm = Zeroizing::new([0u8; 32]);

    // Length-prefixed info to prevent ambiguous concatenation.
    let cr_bytes = credential_ref.as_bytes();
    let li_bytes = lease_id.as_bytes();
    let mut info = Vec::with_capacity(8 + cr_bytes.len() + li_bytes.len());
    info.extend_from_slice(&(cr_bytes.len() as u32).to_be_bytes());
    info.extend_from_slice(cr_bytes);
    info.extend_from_slice(&(li_bytes.len() as u32).to_be_bytes());
    info.extend_from_slice(li_bytes);

    hk.expand(&info, okm.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SALT: &[u8] = b"random-gate-salt-32-bytes-long!!";

    #[test]
    fn test_hkdf_determinism() {
        let k1 = derive_credential_key(MASTER, SALT, "cred-abc", "lease-001").unwrap();
        let k2 = derive_credential_key(MASTER, SALT, "cred-abc", "lease-001").unwrap();
        assert_eq!(*k1, *k2, "same inputs must produce same key");
    }

    #[test]
    fn test_hkdf_different_inputs() {
        let k1 = derive_credential_key(MASTER, SALT, "cred-abc", "lease-001").unwrap();
        let k2 = derive_credential_key(MASTER, SALT, "cred-xyz", "lease-001").unwrap();
        let k3 = derive_credential_key(MASTER, SALT, "cred-abc", "lease-002").unwrap();
        assert_ne!(*k1, *k2, "different credential_ref must differ");
        assert_ne!(*k1, *k3, "different lease_id must differ");
        assert_ne!(*k2, *k3);
    }

    #[test]
    fn test_hkdf_different_salt() {
        let k1 = derive_credential_key(MASTER, SALT, "cred-abc", "lease-001").unwrap();
        let k2 = derive_credential_key(
            MASTER,
            b"different-salt-value!!!!!!!!!!!",
            "cred-abc",
            "lease-001",
        )
        .unwrap();
        assert_ne!(*k1, *k2, "different salt must produce different key");
    }

    #[test]
    fn test_hkdf_no_ambiguity() {
        // "cred-ab" + "c-lease" vs "cred-abc" + "-lease" — must differ due to length prefix.
        let k1 = derive_credential_key(MASTER, SALT, "cred-ab", "c-lease").unwrap();
        let k2 = derive_credential_key(MASTER, SALT, "cred-abc", "-lease").unwrap();
        assert_ne!(*k1, *k2, "length-prefixed encoding must prevent ambiguity");
    }
}
