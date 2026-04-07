//! Secure memory pool: mlock'd buffers and an encrypted credential store.

use std::collections::HashMap;
use std::ops::Deref;
use std::ptr::NonNull;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// An encrypted blob produced by ChaCha20-Poly1305.
///
/// The 16-byte authentication tag is appended to `ciphertext` by the AEAD
/// implementation, so callers do not need to handle it separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// 96-bit (12-byte) random nonce.
    pub nonce: [u8; 12],
    /// Ciphertext with appended 16-byte Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

/// A heap buffer that is locked into RAM with `mlock(2)` and zeroed on drop.
///
/// If `mlock` fails (e.g. in CI with low `RLIMIT_MEMLOCK`), a warning is
/// logged but construction still succeeds — the data is always zeroed on drop.
pub struct SecureBuffer(Vec<u8>);

impl SecureBuffer {
    /// Wrap `data`, attempting to lock it into RAM.
    pub fn new(data: Vec<u8>) -> Self {
        if !data.is_empty() {
            // SAFETY: pointer is valid and length matches the allocation.
            if let Some(ptr) = NonNull::new(data.as_ptr() as *mut std::ffi::c_void) {
                let result = unsafe { nix::sys::mman::mlock(ptr, data.len()) };
                if let Err(e) = result {
                    // Low mlock limits are common in CI — degrade gracefully.
                    eprintln!("cdp-crypto: mlock warning: {e}");
                }
            }
        }
        Self(data)
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Save pointer and length before zeroize, because zeroize truncates the
        // Vec to zero length which would cause us to skip the munlock call.
        let ptr = self.0.as_ptr();
        let len = self.0.len();

        // Zeroize first so secrets cannot be read from a swap-backed page.
        self.0.zeroize();

        if len > 0
            && let Some(nn) = NonNull::new(ptr as *mut std::ffi::c_void)
        {
            // SAFETY: pointer and length match the original mlock'd allocation.
            let _ = unsafe { nix::sys::mman::munlock(nn, len) };
        }
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An in-memory store of encrypted credential blobs, keyed by credential ref.
#[derive(Default)]
pub struct SecurePool {
    inner: HashMap<String, EncryptedBlob>,
}

impl SecurePool {
    /// Create an empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a blob.
    pub fn insert(&mut self, key: String, blob: EncryptedBlob) {
        self.inner.insert(key, blob);
    }

    /// Retrieve a reference to a blob.
    pub fn get(&self, key: &str) -> Option<&EncryptedBlob> {
        self.inner.get(key)
    }

    /// Remove and return a blob.
    pub fn remove(&mut self, key: &str) -> Option<EncryptedBlob> {
        self.inner.remove(key)
    }

    /// Number of entries in the pool.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if the pool contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_access() {
        let data = b"super secret credential".to_vec();
        let buf = SecureBuffer::new(data.clone());
        assert_eq!(&*buf, data.as_slice());
        assert_eq!(buf.as_ref(), data.as_slice());
    }

    #[test]
    fn test_secure_pool_insert_get_remove() {
        let mut pool = SecurePool::new();
        assert!(pool.is_empty());

        let blob = EncryptedBlob {
            nonce: [0u8; 12],
            ciphertext: vec![1, 2, 3],
        };
        pool.insert("cred-1".to_string(), blob.clone());
        assert_eq!(pool.len(), 1);

        let retrieved = pool.get("cred-1").expect("should be present");
        assert_eq!(retrieved.ciphertext, vec![1, 2, 3]);

        let removed = pool.remove("cred-1").expect("should remove");
        assert_eq!(removed.ciphertext, blob.ciphertext);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_encrypted_blob_serde() {
        let blob = EncryptedBlob {
            nonce: [42u8; 12],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&blob).expect("serialize");
        let decoded: EncryptedBlob = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.nonce, blob.nonce);
        assert_eq!(decoded.ciphertext, blob.ciphertext);
    }
}
