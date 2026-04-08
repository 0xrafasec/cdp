//! File-based development vault backend.
//!
//! Stores credentials in an Argon2id-encrypted file. Intended for local
//! development and integration testing only — **not for production use**.
//!
//! File layout: `[16-byte salt][12-byte nonce][ChaCha20-Poly1305 ciphertext]`
//!
//! A warning is emitted at `open()` time to prevent accidental production use.

use std::collections::HashMap;
use std::future::Future;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::pin::Pin;

use argon2::{Argon2, Params};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{Aead, OsRng},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::{Zeroize, Zeroizing};

use crate::{CredentialRef, EncryptedCredential, RotationStream, VaultBackend, VaultError};

// ---------------------------------------------------------------------------
// File format constants
// ---------------------------------------------------------------------------

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Minimum file length: salt + nonce (ciphertext may be empty but tag is 16 bytes).
const MIN_FILE_LEN: usize = SALT_LEN + NONCE_LEN;

// Argon2id parameters.
const ARGON2_M_COST: u32 = 65_536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const ARGON2_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// DevCredential / DevVaultFile
// ---------------------------------------------------------------------------

/// A single credential entry stored in a dev vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevCredential {
    /// The credential value (e.g. an API key or password).
    pub value: String,
    /// Human-readable name.
    pub name: String,
}

/// Internal representation of the JSON stored inside the encrypted file.
#[derive(Deserialize, Serialize)]
struct DevVaultFile {
    credentials: HashMap<String, DevCredential>,
}

// ---------------------------------------------------------------------------
// FileBackend
// ---------------------------------------------------------------------------

/// File-based development vault backend.
///
/// Credentials are decrypted at `open()` time and held in memory for the
/// lifetime of the backend. Each `fetch()` call re-encrypts the credential
/// value using a per-session ephemeral IPC key so the [`EncryptedCredential`]
/// API is consistent with the subprocess backend.
pub struct FileBackend {
    credentials: HashMap<String, DevCredential>,
    /// Per-session ephemeral key used to encrypt outgoing [`EncryptedCredential`]
    /// values. Matches the key returned by [`ipc_key()`].
    ipc_key: Zeroizing<[u8; 32]>,
}

impl FileBackend {
    /// Open and decrypt a dev vault file.
    ///
    /// `path` — path to the encrypted vault file.
    /// `password` — master password; used to derive the encryption key via Argon2id.
    ///
    /// # Errors
    /// Returns `VaultError::Io` on file read failure, `VaultError::Decryption`
    /// on authentication failure, and `VaultError::Protocol` on JSON parse errors.
    pub fn open(path: &Path, password: &str) -> Result<Self, VaultError> {
        let bytes = std::fs::read(path)?;

        if bytes.len() < MIN_FILE_LEN {
            return Err(VaultError::Decryption(format!(
                "file too short: {} bytes (minimum {})",
                bytes.len(),
                MIN_FILE_LEN
            )));
        }

        let (salt, rest) = bytes.split_at(SALT_LEN);
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

        let key = derive_key(password, salt)?;
        let plaintext_vec = chacha_decrypt(&key, nonce_bytes, ciphertext)?;

        let vault: DevVaultFile = serde_json::from_slice(&plaintext_vec)
            .map_err(|e| VaultError::Protocol(format!("failed to parse vault JSON: {e}")))?;
        // Zeroize the decrypted JSON plaintext now that it has been parsed.
        let mut plaintext_zeroizing = Zeroizing::new(plaintext_vec);
        plaintext_zeroizing.zeroize();

        // Generate a random per-session IPC key.
        let mut ipc_key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(ipc_key.as_mut());

        warn!("file-based dev vault backend active — NOT for production use");

        Ok(Self {
            credentials: vault.credentials,
            ipc_key,
        })
    }

    /// Return the per-session IPC encryption key.
    ///
    /// Callers must use this key to decrypt [`EncryptedCredential`] values
    /// returned by [`VaultBackend::fetch`].
    pub fn ipc_key(&self) -> &Zeroizing<[u8; 32]> {
        &self.ipc_key
    }
}

/// Create a new encrypted dev vault file.
///
/// Serialises `credentials` to JSON, encrypts with Argon2id + ChaCha20-Poly1305,
/// and writes `[salt][nonce][ciphertext]` to `path`. Creates parent directories
/// if necessary.
pub fn create_dev_vault(
    path: &Path,
    password: &str,
    credentials: &HashMap<String, DevCredential>,
) -> Result<(), VaultError> {
    // Serialise to JSON.
    let vault = DevVaultFile {
        credentials: credentials.clone(),
    };
    let plaintext = serde_json::to_vec(&vault)
        .map_err(|e| VaultError::Protocol(format!("serialize vault: {e}")))?;

    // Generate random salt and nonce.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt)?;
    let ciphertext = chacha_encrypt(&key, &nonce_bytes, &plaintext)?;

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write: salt || nonce || ciphertext.
    let mut file_bytes = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    file_bytes.extend_from_slice(&salt);
    file_bytes.extend_from_slice(&nonce_bytes);
    file_bytes.extend_from_slice(&ciphertext);

    // Write with restrictive permissions (owner read/write only).
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(&file_bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// VaultBackend implementation
// ---------------------------------------------------------------------------

impl VaultBackend for FileBackend {
    fn list_credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CredentialRef>, VaultError>> + Send + '_>> {
        let refs: Vec<CredentialRef> = self
            .credentials
            .iter()
            .map(|(id, cred)| CredentialRef {
                id: id.clone(),
                name: cred.name.clone(),
                vault_type: "dev".to_string(),
            })
            .collect();

        Box::pin(async move { Ok(refs) })
    }

    fn fetch(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<EncryptedCredential, VaultError>> + Send + '_>> {
        let result = match self.credentials.get(ref_id) {
            None => Err(VaultError::NotFound(format!(
                "credential '{ref_id}' not found in dev vault"
            ))),
            Some(cred) => {
                let cipher = ChaCha20Poly1305::new(self.ipc_key.as_ref().into());
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                match cipher.encrypt(&nonce, cred.value.as_bytes()) {
                    Ok(data) => Ok(EncryptedCredential {
                        data,
                        nonce: nonce.into(),
                    }),
                    Err(e) => Err(VaultError::Decryption(format!("encrypt credential: {e}"))),
                }
            }
        };

        Box::pin(async move { result })
    }

    fn exists(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, VaultError>> + Send + '_>> {
        let found = self.credentials.contains_key(ref_id);
        Box::pin(async move { Ok(found) })
    }

    fn watch_rotation(
        &self,
        _ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<RotationStream, VaultError>> + Send + '_>> {
        Box::pin(async move {
            // Dev credentials do not rotate. Return a channel whose sender is
            // immediately dropped — the receiver will return None when polled.
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            Ok(rx)
        })
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from `password` and `salt` using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; ARGON2_KEY_LEN]>, VaultError> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|e| VaultError::Decryption(format!("Argon2id params: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; ARGON2_KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::Decryption(format!("Argon2id hash_password_into: {e}")))?;

    Ok(key)
}

/// Encrypt `plaintext` with ChaCha20-Poly1305 using the pre-generated `nonce_bytes`.
fn chacha_encrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Decryption(format!("ChaCha20-Poly1305 encrypt: {e}")))
}

/// Decrypt `ciphertext` with ChaCha20-Poly1305.
fn chacha_decrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        VaultError::Decryption("decryption failed (wrong password or corrupted file)".to_string())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_credentials() -> HashMap<String, DevCredential> {
        let mut m = HashMap::new();
        m.insert(
            "api-key-1".to_string(),
            DevCredential {
                value: "super-secret-api-key".to_string(),
                name: "My API Key".to_string(),
            },
        );
        m.insert(
            "db-password".to_string(),
            DevCredential {
                value: "postgres-password-123".to_string(),
                name: "Database Password".to_string(),
            },
        );
        m
    }

    #[test]
    fn test_create_and_open_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        let creds = sample_credentials();

        create_dev_vault(&path, "my-master-password", &creds).expect("create vault");
        let backend = FileBackend::open(&path, "my-master-password").expect("open vault");

        assert_eq!(backend.credentials.len(), creds.len());
        for (id, expected) in &creds {
            let actual = backend.credentials.get(id).expect("credential present");
            assert_eq!(actual.value, expected.value);
            assert_eq!(actual.name, expected.name);
        }
    }

    #[test]
    fn test_wrong_password_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        create_dev_vault(&path, "correct-password", &sample_credentials()).unwrap();

        let result = FileBackend::open(&path, "wrong-password");
        assert!(
            matches!(result, Err(VaultError::Decryption(_))),
            "wrong password must return Decryption error"
        );
    }

    #[tokio::test]
    async fn test_list_credentials() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        let creds = sample_credentials();
        create_dev_vault(&path, "pw", &creds).unwrap();

        let backend = FileBackend::open(&path, "pw").unwrap();
        let list = backend.list_credentials().await.expect("list");
        assert_eq!(list.len(), creds.len());

        let ids: std::collections::HashSet<&str> = list.iter().map(|r| r.id.as_str()).collect();
        for id in creds.keys() {
            assert!(ids.contains(id.as_str()), "id {id} missing from list");
        }
        for r in &list {
            assert_eq!(r.vault_type, "dev");
        }
    }

    #[tokio::test]
    async fn test_fetch_credential() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        create_dev_vault(&path, "pw", &sample_credentials()).unwrap();

        let backend = FileBackend::open(&path, "pw").unwrap();
        let enc = backend.fetch("api-key-1").await.expect("fetch");

        // Decrypt with the IPC key.
        let cipher = ChaCha20Poly1305::new(backend.ipc_key().as_ref().into());
        let nonce = chacha20poly1305::Nonce::from_slice(&enc.nonce);
        let plaintext = cipher.decrypt(nonce, enc.data.as_slice()).expect("decrypt");
        assert_eq!(plaintext, b"super-secret-api-key");
    }

    #[tokio::test]
    async fn test_fetch_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        create_dev_vault(&path, "pw", &sample_credentials()).unwrap();

        let backend = FileBackend::open(&path, "pw").unwrap();
        let result = backend.fetch("nonexistent-id").await;
        assert!(
            matches!(result, Err(VaultError::NotFound(_))),
            "expected NotFound"
        );
    }

    #[tokio::test]
    async fn test_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        create_dev_vault(&path, "pw", &sample_credentials()).unwrap();

        let backend = FileBackend::open(&path, "pw").unwrap();
        assert!(backend.exists("api-key-1").await.unwrap());
        assert!(!backend.exists("not-there").await.unwrap());
    }

    #[test]
    fn test_empty_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.cdp");
        let empty: HashMap<String, DevCredential> = HashMap::new();
        create_dev_vault(&path, "pw", &empty).unwrap();

        let backend = FileBackend::open(&path, "pw").unwrap();
        assert!(backend.credentials.is_empty());
    }

    #[test]
    fn test_corrupted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupted.cdp");
        // Write random garbage that is long enough to parse salt+nonce but
        // whose ciphertext will fail authentication.
        let garbage: Vec<u8> = (0u8..64u8).collect();
        std::fs::write(&path, &garbage).unwrap();

        let result = FileBackend::open(&path, "pw");
        assert!(
            matches!(result, Err(VaultError::Decryption(_))),
            "corrupted file must return Decryption error"
        );
    }

    #[test]
    fn test_too_short_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.cdp");
        std::fs::write(&path, b"tooshort").unwrap();

        let result = FileBackend::open(&path, "pw");
        assert!(
            matches!(result, Err(VaultError::Decryption(_))),
            "too-short file must return Decryption error"
        );
    }

    #[tokio::test]
    async fn test_watch_rotation_never_fires() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.cdp");
        create_dev_vault(&path, "pw", &sample_credentials()).unwrap();

        let backend = FileBackend::open(&path, "pw").unwrap();
        let mut rx = backend
            .watch_rotation("api-key-1")
            .await
            .expect("watch_rotation");

        // The channel sender is dropped immediately; try_recv should return
        // Disconnected (no messages will ever arrive).
        assert!(rx.try_recv().is_err());
    }
}
