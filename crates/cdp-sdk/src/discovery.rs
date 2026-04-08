//! Gate discovery and identity verification.
//!
//! Discovery reads `~/.config/cdp/gate.fingerprint` (or uses `CDP_GATE_URL` to
//! override the socket path), then verifies the connected peer's PID against
//! the fingerprint using `SO_PEERCRED`.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{CdpError, Result};

/// Fingerprint file stored by the gate on startup.
///
/// Agents read this file to locate and authenticate the gate process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GateFingerprint {
    /// PID of the running gate process.
    pub gate_pid: u32,
    /// SHA-256 hex digest of the gate binary.
    pub gate_binary_hash: String,
    /// Ed25519 public key (base64) used for protocol-level signatures.
    pub public_key: String,
    /// Path to the gate's Unix domain socket.
    pub socket_path: String,
    /// RFC 3339 timestamp of when the gate started.
    pub started_at: String,
}

/// Return the default path to the gate fingerprint file.
///
/// Uses `$XDG_CONFIG_HOME/cdp/gate.fingerprint` if `XDG_CONFIG_HOME` is set,
/// otherwise falls back to `~/.config/cdp/gate.fingerprint`.
pub fn default_fingerprint_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("cdp").join("gate.fingerprint");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("cdp")
        .join("gate.fingerprint")
}

/// Discover the gate fingerprint.
///
/// 1. Check the `CDP_GATE_SOCKET` environment variable for a socket path
///    override; if set, construct a minimal fingerprint with that path.
/// 2. Otherwise read and parse `~/.config/cdp/gate.fingerprint`.
pub fn discover() -> Result<GateFingerprint> {
    // Allow socket path override via environment variable.
    if let Ok(socket_path) = std::env::var("CDP_GATE_SOCKET") {
        tracing::debug!(
            socket_path = %socket_path,
            "using CDP_GATE_SOCKET override"
        );
        return Ok(GateFingerprint {
            gate_pid: 0,
            gate_binary_hash: String::new(),
            public_key: String::new(),
            socket_path,
            started_at: String::new(),
        });
    }

    let path = default_fingerprint_path();
    tracing::debug!(path = %path.display(), "reading gate fingerprint");

    let contents = std::fs::read_to_string(&path).map_err(|e| {
        CdpError::GateNotFound(format!(
            "cannot read fingerprint file {}: {}",
            path.display(),
            e
        ))
    })?;

    let fingerprint: GateFingerprint = serde_json::from_str(&contents).map_err(|e| {
        CdpError::MalformedResponse(format!(
            "invalid fingerprint file {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(fingerprint)
}

/// Verify gate identity by checking the connected peer's PID via `SO_PEERCRED`.
///
/// This prevents an attacker from placing a rogue socket at the expected path.
/// If `fingerprint.gate_pid` is `0` (env-var override path), the check is
/// skipped — callers that need strict verification must supply a real fingerprint.
pub fn verify_gate(stream: &UnixStream, fingerprint: &GateFingerprint) -> Result<()> {
    if fingerprint.gate_pid == 0 {
        tracing::debug!("gate_pid is 0 (env override), skipping SO_PEERCRED check");
        return Ok(());
    }

    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let cred = getsockopt(
        // SAFETY: fd is valid for the lifetime of `stream`.
        &unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
        PeerCredentials,
    )
    .map_err(|e| CdpError::IdentityVerification(format!("getsockopt SO_PEERCRED failed: {e}")))?;

    let peer_pid = cred.pid() as u32;
    if peer_pid != fingerprint.gate_pid {
        return Err(CdpError::IdentityVerification(format!(
            "peer PID {peer_pid} does not match expected gate PID {}",
            fingerprint.gate_pid
        )));
    }

    tracing::debug!(pid = peer_pid, "gate identity verified via SO_PEERCRED");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fingerprint_path_uses_home() {
        // Ensure the returned path contains expected segments.
        let path = default_fingerprint_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("cdp"),
            "path should contain 'cdp': {path_str}"
        );
        assert!(
            path_str.ends_with("gate.fingerprint"),
            "path should end with 'gate.fingerprint': {path_str}"
        );
    }

    #[test]
    fn discover_uses_env_override() {
        // SAFETY: test-only, single-threaded at this point.
        unsafe { std::env::set_var("CDP_GATE_SOCKET", "/tmp/test.sock") };
        let fp = discover().expect("discover should succeed with env override");
        unsafe { std::env::remove_var("CDP_GATE_SOCKET") };

        assert_eq!(fp.socket_path, "/tmp/test.sock");
        assert_eq!(fp.gate_pid, 0, "env override sets gate_pid to 0");
    }

    #[test]
    fn discover_fails_when_no_file_and_no_env() {
        // SAFETY: test-only.
        unsafe {
            std::env::remove_var("CDP_GATE_SOCKET");
            // Use a non-existent XDG config dir so default path doesn't accidentally exist.
            std::env::set_var("XDG_CONFIG_HOME", "/tmp/cdp-sdk-test-nonexistent-xdg");
        }
        let result = discover();
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };

        assert!(
            matches!(result, Err(CdpError::GateNotFound(_))),
            "expected GateNotFound, got: {result:?}"
        );
    }

    #[test]
    fn discover_parses_fingerprint_file() {
        let fingerprint = GateFingerprint {
            gate_pid: 12345,
            gate_binary_hash: "abc123".to_string(),
            public_key: "base64pubkey".to_string(),
            socket_path: "/tmp/gate.sock".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&fingerprint).unwrap();

        // Write to the default location under a controlled HOME.
        let home_dir = tempfile::tempdir().expect("home tempdir");
        let config_dir = home_dir.path().join(".config").join("cdp");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("gate.fingerprint"), &json).unwrap();

        // SAFETY: test-only.
        unsafe {
            std::env::remove_var("CDP_GATE_SOCKET");
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("HOME", home_dir.path());
        }
        let parsed = discover().expect("should parse fingerprint file");
        unsafe { std::env::remove_var("HOME") };

        assert_eq!(parsed.gate_pid, 12345);
        assert_eq!(parsed.socket_path, "/tmp/gate.sock");
    }

    #[test]
    fn verify_gate_skips_check_when_pid_is_zero() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let fingerprint = GateFingerprint {
            gate_pid: 0,
            gate_binary_hash: String::new(),
            public_key: String::new(),
            socket_path: String::new(),
            started_at: String::new(),
        };
        // Should not error.
        verify_gate(&a, &fingerprint).expect("should skip check when gate_pid == 0");
    }

    #[test]
    fn verify_gate_rejects_wrong_pid() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let fingerprint = GateFingerprint {
            gate_pid: u32::MAX, // deliberately wrong
            gate_binary_hash: String::new(),
            public_key: String::new(),
            socket_path: String::new(),
            started_at: String::new(),
        };
        let result = verify_gate(&a, &fingerprint);
        assert!(
            matches!(result, Err(CdpError::IdentityVerification(_))),
            "expected IdentityVerification error, got: {result:?}"
        );
    }
}
