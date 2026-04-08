//! Unix socket listener with SO_PEERCRED extraction.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::error::GateError;
use crate::types::PeerInfo;

pub struct GateListener {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl GateListener {
    /// Bind a Unix socket at `socket_path`.
    ///
    /// - Removes any stale socket file.
    /// - Creates the parent directory with 0700 permissions if needed.
    /// - Sets the new socket file's permissions to 0660.
    pub async fn bind(socket_path: &Path) -> Result<Self, GateError> {
        // Remove stale socket file; ignore NotFound.
        match std::fs::remove_file(socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(GateError::Listener(format!(
                    "failed to remove stale socket: {e}"
                )));
            }
        }

        // Create parent directory with 0700 permissions if it doesn't exist.
        if let Some(parent) = socket_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                GateError::Listener(format!("failed to create socket directory: {e}"))
            })?;
            // Set 0700 permissions on the newly created directory.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| GateError::Listener(format!("failed to set directory permissions: {e}")),
            )?;
        }

        // Bind the Unix listener.
        let listener = UnixListener::bind(socket_path).map_err(|e| {
            GateError::Listener(format!(
                "failed to bind socket at {}: {e}",
                socket_path.display()
            ))
        })?;

        // Set socket file permissions to 0600 (owner-only access).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| GateError::Listener(format!("failed to set socket permissions: {e}")))?;

        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// Accept a connection and extract `SO_PEERCRED`.
    pub async fn accept(&self) -> Result<(UnixStream, PeerInfo), GateError> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| GateError::Listener(format!("accept failed: {e}")))?;

        let peer = extract_peer_info(&stream)?;
        Ok((stream, peer))
    }

    /// Return the socket path this listener is bound to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Extract `SO_PEERCRED` from a connected `UnixStream`.
fn extract_peer_info(stream: &UnixStream) -> Result<PeerInfo, GateError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::io::BorrowedFd;

    // SAFETY: stream is valid for the duration of this call.
    let borrowed = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let creds = getsockopt(&borrowed, PeerCredentials)
        .map_err(|e| GateError::Syscall(format!("getsockopt(SO_PEERCRED) failed: {e}")))?;

    let pid: u32 = creds.pid().try_into().map_err(|_| {
        GateError::Syscall(format!(
            "SO_PEERCRED returned negative PID: {}",
            creds.pid()
        ))
    })?;

    Ok(PeerInfo {
        pid,
        uid: creds.uid(),
        gid: creds.gid(),
    })
}

impl Drop for GateListener {
    fn drop(&mut self) {
        // Best-effort removal of the socket file.
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_in_tempdir_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let listener = GateListener::bind(&sock).await.unwrap();
        assert_eq!(listener.socket_path(), sock.as_path());
        assert!(sock.exists());
    }

    #[tokio::test]
    async fn bind_removes_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("stale.sock");
        // Create a stale file.
        std::fs::write(&sock, b"stale").unwrap();
        // Should succeed even with stale file present.
        let _listener = GateListener::bind(&sock).await.unwrap();
        assert!(sock.exists());
    }

    #[tokio::test]
    async fn accept_returns_peer_info_with_correct_pid_and_uid() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("peer.sock");
        let listener = GateListener::bind(&sock).await.unwrap();

        // Connect from the current process.
        let sock_path = sock.clone();
        let client_handle =
            tokio::spawn(async move { tokio::net::UnixStream::connect(&sock_path).await.unwrap() });

        let (_, peer) = listener.accept().await.unwrap();
        let _client = client_handle.await.unwrap();

        // The peer should be the current process.
        assert_eq!(peer.pid, std::process::id());
        assert_eq!(peer.uid, unsafe { libc::getuid() });
    }
}
