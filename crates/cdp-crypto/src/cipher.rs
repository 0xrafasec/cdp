//! ChaCha20-Poly1305 authenticated encryption/decryption.

use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{Aead, OsRng},
};

use crate::{CryptoError, EncryptedBlob, SecureBuffer};

/// Encrypt `plaintext` with ChaCha20-Poly1305 using a fresh 96-bit random nonce.
///
/// The 16-byte authentication tag is appended to the returned ciphertext by the
/// underlying AEAD implementation.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    Ok(EncryptedBlob {
        nonce: nonce.into(),
        ciphertext,
    })
}

/// Decrypt an [`EncryptedBlob`], returning the plaintext in a [`SecureBuffer`].
///
/// The `SecureBuffer` is mlock'd and zeroed on drop so secrets do not linger in
/// swap or freed heap memory.
pub fn decrypt(key: &[u8; 32], blob: &EncryptedBlob) -> Result<SecureBuffer, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from_slice(&blob.nonce);
    let plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption)?;
    Ok(SecureBuffer::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello, secure world!";
        let blob = encrypt(&key, plaintext).expect("encrypt");
        let decrypted = decrypt(&key, &blob).expect("decrypt");
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        let blob = encrypt(&key_a, b"sensitive").expect("encrypt");
        let result = decrypt(&key_b, &blob);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn test_encrypt_produces_different_nonces() {
        let key = test_key();
        let data = b"same plaintext";
        let blob1 = encrypt(&key, data).expect("encrypt 1");
        let blob2 = encrypt(&key, data).expect("encrypt 2");
        assert_ne!(
            blob1.nonce, blob2.nonce,
            "two encryptions must produce distinct nonces"
        );
    }
}
