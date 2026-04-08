//! Gate daemon identity — Ed25519 keypair and fingerprint file.

use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::Rng;
use serde::Serialize;

use crate::agent_verify::hash_binary;
use crate::error::GateError;
use crate::types::hex_encode;

/// The Gate's own identity, kept in memory for signing operations.
pub struct GateIdentity {
    pub signing_key: SigningKey,
    pub fingerprint_path: PathBuf,
}

/// JSON structure written to the fingerprint file.
#[derive(Debug, Serialize)]
struct GateFingerprintFile {
    gate_pid: u32,
    gate_binary_hash: String,
    public_key: String,
    socket_path: String,
    started_at: String,
}

impl GateIdentity {
    /// Generate an Ed25519 keypair and write the fingerprint file.
    ///
    /// Creates the parent directory (0700) if it doesn't exist and sets the
    /// fingerprint file to 0400 (owner-read-only).
    pub fn create(fingerprint_path: &Path, socket_path: &str) -> Result<Self, GateError> {
        // ed25519-dalek uses rand_core 0.6 but we have rand 0.9 (rand_core 0.9).
        // Generate 32 random bytes and construct the signing key from them.
        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Hash the gate binary itself via /proc/self/exe.
        let self_exe = std::fs::read_link("/proc/self/exe")
            .map_err(|e| GateError::Fingerprint(format!("failed to read /proc/self/exe: {e}")))?;
        let gate_hash = hash_binary(&self_exe)
            .map_err(|e| GateError::Fingerprint(format!("failed to hash gate binary: {e}")))?;

        let fp = GateFingerprintFile {
            gate_pid: std::process::id(),
            gate_binary_hash: format!("sha256:{}", hex_encode(&gate_hash)),
            public_key: base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes()),
            socket_path: socket_path.to_string(),
            started_at: Utc::now().to_rfc3339(),
        };

        // Create parent directory with 0700 permissions.
        if let Some(parent) = fingerprint_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| GateError::Fingerprint(format!("failed to create dir: {e}")))?;
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| GateError::Fingerprint(format!("failed to set dir permissions: {e}")),
            )?;
        }

        // Write JSON content.
        let json = serde_json::to_string_pretty(&fp)
            .map_err(|e| GateError::Fingerprint(format!("failed to serialize fingerprint: {e}")))?;
        std::fs::write(fingerprint_path, json.as_bytes()).map_err(|e| {
            GateError::Fingerprint(format!("failed to write fingerprint file: {e}"))
        })?;

        // Set file permissions to 0400 (owner-read-only).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(fingerprint_path, std::fs::Permissions::from_mode(0o400))
            .map_err(|e| GateError::Fingerprint(format!("failed to set file permissions: {e}")))?;

        Ok(Self {
            signing_key,
            fingerprint_path: fingerprint_path.to_path_buf(),
        })
    }

    /// Delete the fingerprint file. Ignores `NotFound` errors (idempotent).
    pub fn cleanup(&self) -> Result<(), GateError> {
        match std::fs::remove_file(&self.fingerprint_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(GateError::Fingerprint(format!(
                "failed to remove fingerprint file: {e}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_fingerprint_file() {
        let dir = tempfile::tempdir().unwrap();
        let fp_path = dir.path().join("gate.fingerprint");

        let identity = GateIdentity::create(&fp_path, "/tmp/test.sock").unwrap();

        // File must exist.
        assert!(fp_path.exists());

        // Permissions must be 0400.
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&fp_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o400);

        // JSON must parse and contain expected fields.
        let contents = std::fs::read_to_string(&fp_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(value["gate_pid"], std::process::id());
        assert!(
            value["gate_binary_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(value["socket_path"], "/tmp/test.sock");
        assert!(value["started_at"].is_string());

        // Public key should be valid base64.
        let pk_b64 = value["public_key"].as_str().unwrap();
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(pk_b64)
            .unwrap();
        assert_eq!(pk_bytes.len(), 32); // Ed25519 public key is 32 bytes.

        // Verify it matches the signing key.
        assert_eq!(pk_bytes, identity.signing_key.verifying_key().as_bytes());
    }

    #[test]
    fn cleanup_deletes_file() {
        let dir = tempfile::tempdir().unwrap();
        let fp_path = dir.path().join("gate.fingerprint");
        let identity = GateIdentity::create(&fp_path, "/tmp/test.sock").unwrap();
        assert!(fp_path.exists());

        identity.cleanup().unwrap();
        assert!(!fp_path.exists());
    }

    #[test]
    fn double_cleanup_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let fp_path = dir.path().join("gate.fingerprint");
        let identity = GateIdentity::create(&fp_path, "/tmp/test.sock").unwrap();

        identity.cleanup().unwrap();
        identity.cleanup().unwrap(); // should not error
    }
}
