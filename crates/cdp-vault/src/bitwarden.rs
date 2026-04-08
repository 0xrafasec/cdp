//! Bitwarden CLI backend for the vault subprocess.
//!
//! Wraps the `bw` CLI binary. All credential values are encrypted with
//! ChaCha20-Poly1305 before being returned, using the IPC session key set
//! by the parent process via the `Init` command.

use std::io::Write;
use std::process::{Command, Stdio};

use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{Aead, OsRng},
};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use cdp_crypto::SecureBuffer;

use crate::{CredentialRef, EncryptedCredential, VaultError};

// ---------------------------------------------------------------------------
// Bitwarden JSON schema types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct BwItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: u32,
    pub login: Option<BwLogin>,
    pub notes: Option<String>,
    pub fields: Option<Vec<BwField>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BwLogin {
    #[allow(dead_code)]
    pub username: Option<String>,
    pub password: Option<String>,
    #[allow(dead_code)]
    pub uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BwField {
    #[allow(dead_code)]
    pub name: String,
    pub value: String,
    #[allow(dead_code)]
    pub field_type: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BwUri {
    #[serde(rename = "match")]
    #[allow(dead_code)]
    pub match_type: Option<u32>,
    #[allow(dead_code)]
    pub uri: String,
}

// ---------------------------------------------------------------------------
// CommandExecutor trait
// ---------------------------------------------------------------------------

/// Abstraction for executing `bw` CLI commands.
///
/// The separate trait enables unit testing without a real Bitwarden installation.
pub trait CommandExecutor: Send + Sync {
    /// Execute `bw` with the given arguments, optionally writing `stdin_data`
    /// to the process's stdin, and optionally setting additional environment
    /// variables. Returns the captured stdout on success.
    fn execute(
        &self,
        args: &[&str],
        stdin_data: Option<&[u8]>,
        env: Option<&[(&str, &str)]>,
    ) -> Result<String, VaultError>;
}

// ---------------------------------------------------------------------------
// BwCliExecutor — real executor
// ---------------------------------------------------------------------------

/// Real [`CommandExecutor`] that spawns the `bw` CLI binary.
pub struct BwCliExecutor {
    cli_path: String,
}

impl BwCliExecutor {
    /// Create a new executor that runs the `bw` binary at `cli_path`.
    pub fn new(cli_path: impl Into<String>) -> Self {
        Self {
            cli_path: cli_path.into(),
        }
    }
}

impl CommandExecutor for BwCliExecutor {
    fn execute(
        &self,
        args: &[&str],
        stdin_data: Option<&[u8]>,
        env: Option<&[(&str, &str)]>,
    ) -> Result<String, VaultError> {
        let stdin_cfg = if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        };

        let mut cmd = Command::new(&self.cli_path);
        cmd.args(args)
            .env("BW_NOINTERACTION", "true")
            .stdin(stdin_cfg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(env_vars) = env {
            for (key, val) in env_vars {
                cmd.env(key, val);
            }
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| VaultError::Subprocess(format!("failed to spawn bw: {e}")))?;

        if let (Some(mut child_stdin), Some(data)) = (child.stdin.take(), stdin_data) {
            child_stdin
                .write_all(data)
                .map_err(|e| VaultError::Subprocess(format!("write to bw stdin: {e}")))?;
            // Drop stdin to signal EOF.
        }

        let output = child
            .wait_with_output()
            .map_err(|e| VaultError::Subprocess(format!("wait_with_output: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(VaultError::BitwardenCli(format!(
                "bw exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

// ---------------------------------------------------------------------------
// BitwardenBackend
// ---------------------------------------------------------------------------

/// Bitwarden vault backend. Runs inside the vault subprocess.
///
/// Uses a [`CommandExecutor`] to drive the `bw` CLI. Credentials fetched from
/// Bitwarden are encrypted with the IPC key before being returned, so the
/// plaintext never leaves the subprocess in cleartext.
pub struct BitwardenBackend {
    executor: Box<dyn CommandExecutor>,
    /// Bitwarden session key, stored in locked memory.
    session_key: Option<SecureBuffer>,
    /// Shared IPC encryption key set by the parent via the `Init` command.
    ipc_encrypt_key: Option<Zeroizing<[u8; 32]>>,
}

impl BitwardenBackend {
    /// Create a new backend with the given command executor.
    pub fn new(executor: Box<dyn CommandExecutor>) -> Self {
        Self {
            executor,
            session_key: None,
            ipc_encrypt_key: None,
        }
    }

    /// Set the shared IPC encryption key received from the parent process.
    pub fn set_ipc_key(&mut self, key: [u8; 32]) {
        self.ipc_encrypt_key = Some(Zeroizing::new(key));
    }

    /// Unlock the vault with `password`.
    ///
    /// Runs `bw unlock --raw` and stores the returned session key in a
    /// [`SecureBuffer`] (mlock'd, zeroed on drop).
    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        let mut output =
            self.executor
                .execute(&["unlock", "--raw"], Some(password.as_bytes()), None)?;

        let session_key = output.trim().to_string();
        // Zeroize the intermediate string before checking / using session_key.
        output.zeroize();

        if session_key.is_empty() {
            return Err(VaultError::BitwardenCli(
                "bw unlock returned an empty session key".to_string(),
            ));
        }
        self.session_key = Some(SecureBuffer::new(session_key.into_bytes()));
        Ok(())
    }

    /// List all items in the unlocked vault.
    pub fn list(&self) -> Result<Vec<CredentialRef>, VaultError> {
        let session = self.require_session()?;
        let session_str = std::str::from_utf8(session)
            .map_err(|_| VaultError::Locked("session key is not valid UTF-8".to_string()))?;

        let output = self.executor.execute(
            &["list", "items", "--raw"],
            None,
            Some(&[("BW_SESSION", session_str)]),
        )?;

        let items: Vec<BwItem> = serde_json::from_str(&output)
            .map_err(|e| VaultError::Protocol(format!("failed to parse bw list output: {e}")))?;

        let refs = items
            .into_iter()
            .map(|item| {
                let vault_type = match item.item_type {
                    1 => "login",
                    2 => "note",
                    3 => "card",
                    4 => "identity",
                    _ => "unknown",
                };
                CredentialRef {
                    id: item.id,
                    name: item.name,
                    vault_type: vault_type.to_string(),
                }
            })
            .collect();

        Ok(refs)
    }

    /// Fetch and encrypt a single credential by its Bitwarden item ID.
    ///
    /// Extracts the credential value (login.password, then notes, then first
    /// custom field) and encrypts it with ChaCha20-Poly1305 using the IPC key.
    pub fn fetch(&self, ref_id: &str) -> Result<EncryptedCredential, VaultError> {
        let session = self.require_session()?;
        let session_str = std::str::from_utf8(session)
            .map_err(|_| VaultError::Locked("session key is not valid UTF-8".to_string()))?;

        let output = self.executor.execute(
            &["get", "item", ref_id, "--raw"],
            None,
            Some(&[("BW_SESSION", session_str)]),
        )?;

        let item: BwItem = serde_json::from_str(&output).map_err(|e| {
            VaultError::Protocol(format!("failed to parse bw get item output: {e}"))
        })?;

        let mut value = Self::extract_credential_value(&item)?;
        let encrypted = self.encrypt_value(value.as_bytes())?;
        value.zeroize();

        Ok(encrypted)
    }

    /// Check whether a credential with `ref_id` exists in the vault.
    pub fn exists(&self, ref_id: &str) -> Result<bool, VaultError> {
        let session = self.require_session()?;
        let session_str = std::str::from_utf8(session)
            .map_err(|_| VaultError::Locked("session key is not valid UTF-8".to_string()))?;

        match self.executor.execute(
            &["get", "item", ref_id, "--raw"],
            None,
            Some(&[("BW_SESSION", session_str)]),
        ) {
            Ok(_) => Ok(true),
            Err(VaultError::BitwardenCli(msg)) if is_not_found_error(&msg) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Return the session key bytes, or `VaultError::Locked` if not unlocked.
    fn require_session(&self) -> Result<&[u8], VaultError> {
        self.session_key
            .as_deref()
            .ok_or_else(|| VaultError::Locked("vault is locked; call unlock first".to_string()))
    }

    /// Extract the credential value from a Bitwarden item.
    ///
    /// Priority: `login.password` > `notes` > first custom field with a value.
    pub(crate) fn extract_credential_value(item: &BwItem) -> Result<String, VaultError> {
        // 1. Login password.
        if let Some(login) = &item.login
            && let Some(password) = &login.password
            && !password.is_empty()
        {
            return Ok(password.clone());
        }

        // 2. Secure note content.
        if let Some(notes) = &item.notes
            && !notes.is_empty()
        {
            return Ok(notes.clone());
        }

        // 3. First non-empty custom field.
        if let Some(fields) = &item.fields {
            for field in fields {
                if !field.value.is_empty() {
                    return Ok(field.value.clone());
                }
            }
        }

        Err(VaultError::NotFound(format!(
            "item '{}' has no extractable credential value",
            item.id
        )))
    }

    /// Encrypt `plaintext` with ChaCha20-Poly1305 using the IPC key.
    fn encrypt_value(&self, plaintext: &[u8]) -> Result<EncryptedCredential, VaultError> {
        let key = self.ipc_encrypt_key.as_ref().ok_or_else(|| {
            VaultError::Locked("IPC encryption key not set; Init not received".to_string())
        })?;

        let cipher = ChaCha20Poly1305::new(key.as_ref().into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let data = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| VaultError::Decryption(format!("ChaCha20-Poly1305 encrypt: {e}")))?;

        Ok(EncryptedCredential {
            data,
            nonce: nonce.into(),
        })
    }
}

/// Returns `true` if the CLI error message indicates that the item was not found.
fn is_not_found_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("not found") || lower.contains("no items")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock executor that returns pre-configured responses.
    struct MockCommandExecutor {
        responses: Mutex<Vec<Result<String, VaultError>>>,
    }

    impl MockCommandExecutor {
        fn new(responses: Vec<Result<String, VaultError>>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl CommandExecutor for MockCommandExecutor {
        fn execute(
            &self,
            _args: &[&str],
            _stdin: Option<&[u8]>,
            _env: Option<&[(&str, &str)]>,
        ) -> Result<String, VaultError> {
            let mut queue = self.responses.lock().unwrap();
            if queue.is_empty() {
                panic!("MockCommandExecutor: no more responses queued");
            }
            // Pop from the front.
            let responses = queue.drain(..1).collect::<Vec<_>>();
            responses.into_iter().next().unwrap()
        }
    }

    fn test_ipc_key() -> [u8; 32] {
        [0xABu8; 32]
    }

    fn make_backend(responses: Vec<Result<String, VaultError>>) -> BitwardenBackend {
        let mut backend = BitwardenBackend::new(Box::new(MockCommandExecutor::new(responses)));
        backend.set_ipc_key(test_ipc_key());
        backend
    }

    // -----------------------------------------------------------------------
    // unlock tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_unlock_success() {
        let mut backend = make_backend(vec![Ok("session-key-value".to_string())]);
        backend
            .unlock("correct-password")
            .expect("unlock should succeed");
        assert!(backend.session_key.is_some());
    }

    #[test]
    fn test_unlock_wrong_password() {
        let mut backend = make_backend(vec![Err(VaultError::BitwardenCli(
            "bw exited with 1: Invalid master password.".to_string(),
        ))]);
        let result = backend.unlock("wrong-password");
        assert!(
            matches!(result, Err(VaultError::BitwardenCli(_))),
            "expected BitwardenCli error"
        );
    }

    // -----------------------------------------------------------------------
    // list tests
    // -----------------------------------------------------------------------

    fn bw_item_login_json(id: &str, name: &str, password: &str) -> String {
        serde_json::json!([{
            "id": id,
            "name": name,
            "type": 1,
            "login": { "username": "user@example.com", "password": password, "uris": [] },
            "notes": null,
            "fields": null
        }])
        .to_string()
    }

    #[test]
    fn test_list_credentials() {
        let json = bw_item_login_json("id-1", "My API Key", "secret");
        let mut backend = make_backend(vec![Ok("session-key".to_string()), Ok(json)]);
        backend.unlock("pw").unwrap();
        let creds = backend.list().expect("list should succeed");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, "id-1");
        assert_eq!(creds[0].name, "My API Key");
        assert_eq!(creds[0].vault_type, "login");
    }

    #[test]
    fn test_list_empty() {
        let mut backend = make_backend(vec![Ok("session-key".to_string()), Ok("[]".to_string())]);
        backend.unlock("pw").unwrap();
        let creds = backend.list().expect("list should succeed");
        assert!(creds.is_empty());
    }

    // -----------------------------------------------------------------------
    // fetch tests
    // -----------------------------------------------------------------------

    fn bw_get_item_login_json(id: &str, name: &str, password: &str) -> String {
        serde_json::json!({
            "id": id,
            "name": name,
            "type": 1,
            "login": { "username": "user", "password": password, "uris": [] },
            "notes": null,
            "fields": null
        })
        .to_string()
    }

    fn bw_get_item_note_json(id: &str, name: &str, notes: &str) -> String {
        serde_json::json!({
            "id": id,
            "name": name,
            "type": 2,
            "login": null,
            "notes": notes,
            "fields": null
        })
        .to_string()
    }

    #[test]
    fn test_fetch_login_credential() {
        let item_json = bw_get_item_login_json("id-1", "API Key", "s3cr3t");
        let mut backend = make_backend(vec![Ok("session-key".to_string()), Ok(item_json)]);
        backend.unlock("pw").unwrap();
        let enc = backend.fetch("id-1").expect("fetch should succeed");

        // Decrypt and verify.
        let cipher = ChaCha20Poly1305::new((&test_ipc_key()).into());
        let nonce = chacha20poly1305::Nonce::from_slice(&enc.nonce);
        let plaintext = cipher.decrypt(nonce, enc.data.as_slice()).expect("decrypt");
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), "s3cr3t");
    }

    #[test]
    fn test_fetch_notes_credential() {
        let item_json = bw_get_item_note_json("id-2", "Secure Note", "my-secret-note");
        let mut backend = make_backend(vec![Ok("session-key".to_string()), Ok(item_json)]);
        backend.unlock("pw").unwrap();
        let enc = backend.fetch("id-2").expect("fetch should succeed");

        let cipher = ChaCha20Poly1305::new((&test_ipc_key()).into());
        let nonce = chacha20poly1305::Nonce::from_slice(&enc.nonce);
        let plaintext = cipher.decrypt(nonce, enc.data.as_slice()).expect("decrypt");
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), "my-secret-note");
    }

    #[test]
    fn test_fetch_not_found() {
        let mut backend = make_backend(vec![
            Ok("session-key".to_string()),
            Err(VaultError::BitwardenCli(
                "bw exited with 1: Not found.".to_string(),
            )),
        ]);
        backend.unlock("pw").unwrap();
        let result = backend.fetch("nonexistent");
        assert!(
            matches!(result, Err(VaultError::BitwardenCli(_))),
            "expected BitwardenCli error"
        );
    }

    // -----------------------------------------------------------------------
    // exists tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_exists_found() {
        let item_json = bw_get_item_login_json("id-3", "Found", "pw");
        let mut backend = make_backend(vec![Ok("session-key".to_string()), Ok(item_json)]);
        backend.unlock("pw").unwrap();
        assert!(backend.exists("id-3").expect("exists should succeed"));
    }

    #[test]
    fn test_exists_not_found() {
        let mut backend = make_backend(vec![
            Ok("session-key".to_string()),
            Err(VaultError::BitwardenCli(
                "bw exited with 1: Not found.".to_string(),
            )),
        ]);
        backend.unlock("pw").unwrap();
        assert!(
            !backend
                .exists("nonexistent")
                .expect("exists should return false")
        );
    }

    // -----------------------------------------------------------------------
    // extract_credential_value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_credential_value_priority_login_over_notes() {
        let item = BwItem {
            id: "x".to_string(),
            name: "X".to_string(),
            item_type: 1,
            login: Some(BwLogin {
                username: None,
                password: Some("login-pw".to_string()),
                uris: None,
            }),
            notes: Some("some notes".to_string()),
            fields: Some(vec![BwField {
                name: "field".to_string(),
                value: "field-val".to_string(),
                field_type: 0,
            }]),
        };
        let value = BitwardenBackend::extract_credential_value(&item).unwrap();
        assert_eq!(value, "login-pw", "login.password should take priority");
    }

    #[test]
    fn test_extract_credential_value_notes_over_fields() {
        let item = BwItem {
            id: "x".to_string(),
            name: "X".to_string(),
            item_type: 2,
            login: None,
            notes: Some("note-content".to_string()),
            fields: Some(vec![BwField {
                name: "f".to_string(),
                value: "field-val".to_string(),
                field_type: 0,
            }]),
        };
        let value = BitwardenBackend::extract_credential_value(&item).unwrap();
        assert_eq!(
            value, "note-content",
            "notes should take priority over fields"
        );
    }

    #[test]
    fn test_extract_credential_value_fields_fallback() {
        let item = BwItem {
            id: "x".to_string(),
            name: "X".to_string(),
            item_type: 1,
            login: Some(BwLogin {
                username: Some("user".to_string()),
                password: None, // no password
                uris: None,
            }),
            notes: None,
            fields: Some(vec![BwField {
                name: "api_key".to_string(),
                value: "key-from-field".to_string(),
                field_type: 0,
            }]),
        };
        let value = BitwardenBackend::extract_credential_value(&item).unwrap();
        assert_eq!(value, "key-from-field");
    }

    #[test]
    fn test_extract_credential_value_no_value_returns_error() {
        let item = BwItem {
            id: "empty".to_string(),
            name: "Empty".to_string(),
            item_type: 1,
            login: None,
            notes: None,
            fields: None,
        };
        let result = BitwardenBackend::extract_credential_value(&item);
        assert!(
            matches!(result, Err(VaultError::NotFound(_))),
            "expected NotFound"
        );
    }
}
