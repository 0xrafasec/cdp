//! Parent-side vault subprocess manager.
//!
//! Spawns a sandboxed child process that runs the Bitwarden CLI via
//! [`vault_worker_main`](crate::child_main::vault_worker_main). Communicates
//! over a Unix socket pair using the length-prefixed IPC protocol defined in
//! [`crate::protocol`].

use std::future::Future;
use std::pin::Pin;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use rand::Rng;
use serde_json::Value;
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::protocol::{VaultCommand, VaultResponse, read_message, write_message};
use crate::{CredentialRef, EncryptedCredential, RotationStream, VaultBackend, VaultError};

// ---------------------------------------------------------------------------
// VaultStatus
// ---------------------------------------------------------------------------

/// Lifecycle state of the vault subprocess.
pub enum VaultStatus {
    /// Subprocess is running but the vault is locked (not yet unlocked).
    Locked,
    /// Vault is unlocked and ready for credential operations.
    Unlocked,
    /// Subprocess has crashed or the socket was closed unexpectedly.
    Crashed(String),
}

// ---------------------------------------------------------------------------
// SubprocessManager
// ---------------------------------------------------------------------------

/// Manages a sandboxed vault subprocess and implements [`VaultBackend`].
///
/// All IPC is encrypted with a randomly-generated 32-byte key shared with the
/// subprocess via the `Init` command on startup.
pub struct SubprocessManager {
    inner: Mutex<SubprocessInner>,
    /// The shared IPC encryption key (needed by callers to decrypt
    /// [`EncryptedCredential`] values returned by [`VaultBackend::fetch`]).
    ipc_key: Zeroizing<[u8; 32]>,
}

struct SubprocessInner {
    status: VaultStatus,
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    /// Held to keep the child process alive and allow `wait()` on drop.
    #[allow(dead_code)]
    child: tokio::process::Child,
}

impl SubprocessManager {
    /// Spawn a vault subprocess and perform the `Init` handshake.
    ///
    /// `bw_cli_path` is the path to the `bw` CLI binary.
    /// `sandbox_enabled` controls whether seccomp and PID namespace isolation
    /// are applied in the child.
    pub async fn spawn(bw_cli_path: &str, sandbox_enabled: bool) -> Result<Self, VaultError> {
        use std::os::unix::io::IntoRawFd;

        // Create a Unix socket pair (parent_fd, child_fd).
        // Use SOCK_CLOEXEC so both fds are closed on exec by default;
        // the child fd is explicitly made inheritable before spawn.
        let (parent_fd, child_fd) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(|e| VaultError::Subprocess(format!("socketpair: {e}")))?;

        // Generate a random 32-byte IPC encryption key.
        let mut ipc_key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(ipc_key.as_mut());

        let child_fd_raw = child_fd.into_raw_fd();
        let parent_fd_raw = parent_fd.into_raw_fd();

        // Clear CLOEXEC on the child fd so the child process inherits it.
        // SAFETY: child_fd_raw is a valid fd we just obtained from socketpair.
        let flags = unsafe { libc::fcntl(child_fd_raw, libc::F_GETFD) };
        if flags >= 0 {
            unsafe { libc::fcntl(child_fd_raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        }

        // Spawn the child using /proc/self/exe re-exec pattern.
        let child = Command::new("/proc/self/exe")
            .arg("--vault-worker")
            .arg(child_fd_raw.to_string())
            .arg(bw_cli_path)
            .arg(if sandbox_enabled { "1" } else { "0" })
            // Make the child fd inheritable.
            .spawn()
            .map_err(|e| VaultError::Subprocess(format!("spawn vault worker: {e}")))?;

        // Close the child fd on the parent side — the child owns it now.
        // SAFETY: child_fd_raw is a valid fd; we transfer ownership to the child.
        unsafe { libc::close(child_fd_raw) };

        // Convert parent fd to a Tokio UnixStream.
        // SAFETY: parent_fd_raw is a valid, open, non-blocking-capable fd.
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(parent_fd_raw) };
        std_stream
            .set_nonblocking(true)
            .map_err(|e| VaultError::Subprocess(format!("set_nonblocking: {e}")))?;
        let stream = UnixStream::from_std(std_stream)
            .map_err(|e| VaultError::Subprocess(format!("UnixStream::from_std: {e}")))?;

        let (read_half, write_half) = stream.into_split();
        let reader = BufReader::new(read_half);

        // Encode the key before moving into the struct.
        let mut encoded_key = Zeroizing::new(BASE64.encode(ipc_key.as_ref()));

        let manager = SubprocessManager {
            inner: Mutex::new(SubprocessInner {
                status: VaultStatus::Locked,
                reader,
                writer: write_half,
                child,
            }),
            ipc_key,
        };
        let init_cmd = VaultCommand::Init {
            key: encoded_key.to_string(),
        };
        // Zeroize the base64-encoded key copy now that the command owns its own copy.
        zeroize::Zeroize::zeroize(encoded_key.as_mut());
        manager.send_command(init_cmd).await?;

        Ok(manager)
    }

    /// Return the IPC encryption key used to decrypt [`EncryptedCredential`]
    /// values returned by [`VaultBackend::fetch`].
    pub fn ipc_key(&self) -> &Zeroizing<[u8; 32]> {
        &self.ipc_key
    }

    /// Unlock the vault with the given master password.
    pub async fn unlock(&self, password: &str) -> Result<(), VaultError> {
        let cmd = VaultCommand::Unlock {
            password: password.to_string(),
        };
        self.send_command(cmd).await?;

        let mut inner = self.inner.lock().await;
        inner.status = VaultStatus::Unlocked;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Send a command to the subprocess and return the deserialized response.
    ///
    /// On I/O failure, marks the subprocess as crashed and returns
    /// `VaultError::Subprocess`.
    async fn send_command(&self, cmd: VaultCommand) -> Result<VaultResponse, VaultError> {
        let payload = serde_json::to_vec(&cmd)
            .map_err(|e| VaultError::Protocol(format!("serialize command: {e}")))?;

        let mut inner = self.inner.lock().await;

        // Check for prior crash.
        if let VaultStatus::Crashed(ref reason) = inner.status {
            return Err(VaultError::Locked(format!("subprocess crashed: {reason}")));
        }

        // Write command.
        if let Err(e) = write_message(&mut inner.writer, &payload).await {
            inner.status = VaultStatus::Crashed(e.to_string());
            return Err(VaultError::Subprocess(format!(
                "write to vault subprocess: {e}"
            )));
        }

        // Read response.
        let raw = match read_message(&mut inner.reader).await {
            Ok(r) => r,
            Err(e) => {
                inner.status = VaultStatus::Crashed(e.to_string());
                return Err(VaultError::Subprocess(format!(
                    "read from vault subprocess: {e}"
                )));
            }
        };

        let response: VaultResponse = serde_json::from_slice(&raw)
            .map_err(|e| VaultError::Protocol(format!("deserialize response: {e}")))?;

        Ok(response)
    }

    /// Extract a successful response value, converting errors to `VaultError`.
    fn ok_or_err(response: VaultResponse) -> Result<Value, VaultError> {
        match response {
            VaultResponse::Ok { data } => Ok(data),
            VaultResponse::Error { message } => Err(VaultError::Subprocess(message)),
        }
    }
}

// ---------------------------------------------------------------------------
// VaultBackend implementation
// ---------------------------------------------------------------------------

impl VaultBackend for SubprocessManager {
    fn list_credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<CredentialRef>, VaultError>> + Send + '_>> {
        Box::pin(async move {
            let response = self.send_command(VaultCommand::List).await?;
            let data = Self::ok_or_err(response)?;
            let refs: Vec<CredentialRef> = serde_json::from_value(data)
                .map_err(|e| VaultError::Protocol(format!("deserialize credential list: {e}")))?;
            Ok(refs)
        })
    }

    fn fetch(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<EncryptedCredential, VaultError>> + Send + '_>> {
        let ref_id = ref_id.to_string();
        Box::pin(async move {
            let cmd = VaultCommand::Fetch { ref_id };
            let response = self.send_command(cmd).await?;
            let data = Self::ok_or_err(response)?;

            let data_b64 = data["data"].as_str().ok_or_else(|| {
                VaultError::Protocol("missing 'data' in fetch response".to_string())
            })?;
            let nonce_b64 = data["nonce"].as_str().ok_or_else(|| {
                VaultError::Protocol("missing 'nonce' in fetch response".to_string())
            })?;

            let data_bytes = BASE64
                .decode(data_b64)
                .map_err(|e| VaultError::Protocol(format!("base64 decode 'data': {e}")))?;
            let nonce_bytes = BASE64
                .decode(nonce_b64)
                .map_err(|e| VaultError::Protocol(format!("base64 decode 'nonce': {e}")))?;

            if nonce_bytes.len() != 12 {
                return Err(VaultError::Protocol(format!(
                    "nonce must be 12 bytes, got {}",
                    nonce_bytes.len()
                )));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_bytes);

            Ok(EncryptedCredential {
                data: data_bytes,
                nonce,
            })
        })
    }

    fn exists(
        &self,
        ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, VaultError>> + Send + '_>> {
        let ref_id = ref_id.to_string();
        Box::pin(async move {
            let cmd = VaultCommand::Exists { ref_id };
            let response = self.send_command(cmd).await?;
            let data = Self::ok_or_err(response)?;
            let found = data.as_bool().ok_or_else(|| {
                VaultError::Protocol("exists response is not a boolean".to_string())
            })?;
            Ok(found)
        })
    }

    fn watch_rotation(
        &self,
        _ref_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<RotationStream, VaultError>> + Send + '_>> {
        Box::pin(async move {
            // Bitwarden CLI does not support rotation notifications.
            // Return a channel whose sender is immediately dropped — the receiver
            // will never yield a value and will return `None` when polled.
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            Ok(rx)
        })
    }
}

// Needed for `from_raw_fd` usage in spawn().
use std::os::unix::io::FromRawFd;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Note: Integration tests for SubprocessManager require a real vault binary
    // (the Gate re-exec'ing itself) and are covered by the integration test suite.
    // Unit tests here verify the helper logic.

    use super::*;

    #[test]
    fn test_ok_or_err_ok() {
        let resp = VaultResponse::Ok {
            data: serde_json::json!(true),
        };
        let val = SubprocessManager::ok_or_err(resp).expect("should be ok");
        assert_eq!(val, serde_json::json!(true));
    }

    #[test]
    fn test_ok_or_err_error() {
        let resp = VaultResponse::Error {
            message: "something went wrong".to_string(),
        };
        let result = SubprocessManager::ok_or_err(resp);
        assert!(
            matches!(result, Err(VaultError::Subprocess(_))),
            "expected Subprocess error"
        );
    }
}
