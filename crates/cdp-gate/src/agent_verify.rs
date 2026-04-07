//! Agent verification via /proc inspection and pidfd liveness monitoring.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::error::GateError;
use crate::types::{AgentFingerprint, DeathNotification};

/// Verify an agent process and construct its cryptographic fingerprint.
///
/// Opens a pidfd **first** to prevent PID recycling between credential
/// extraction and /proc reads.
pub async fn verify_agent(pid: u32, uid: u32) -> Result<AgentFingerprint, GateError> {
    // Open pidfd first — this pins the PID slot in the kernel so we cannot
    // be fooled by PID recycling while reading /proc.
    let pidfd = pidfd_open(pid)?;

    let binary_path = read_binary_path(pid)?;
    let binary_hash = hash_binary(&binary_path)?;
    let start_time = read_start_time(pid)?;
    let fingerprint_hash = compute_fingerprint(uid, pid, &binary_hash, start_time);

    Ok(AgentFingerprint {
        uid,
        pid,
        binary_path,
        binary_hash,
        start_time,
        fingerprint_hash,
        pidfd,
    })
}

/// Open a pidfd for the given PID via the `pidfd_open(2)` syscall (Linux 5.3+).
fn pidfd_open(pid: u32) -> Result<OwnedFd, GateError> {
    let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0 as libc::c_uint) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(GateError::Syscall(format!(
            "pidfd_open({pid}) failed: {err}"
        )));
    }

    // SAFETY: the kernel returned a valid fd.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Compute SHA-256 of the file at `path`.
///
/// `pub(crate)` so `fingerprint.rs` can reuse it for the gate's own binary hash.
pub(crate) fn hash_binary(path: &Path) -> Result<[u8; 32], GateError> {
    let data = std::fs::read(path).map_err(|e| {
        GateError::AgentVerification(format!("failed to read binary {}: {e}", path.display()))
    })?;
    let hash = Sha256::digest(&data);
    Ok(hash.into())
}

/// Resolve the binary path for a process by reading `/proc/<pid>/exe`.
fn read_binary_path(pid: u32) -> Result<PathBuf, GateError> {
    std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| {
        GateError::AgentVerification(format!("failed to read /proc/{pid}/exe: {e}"))
    })
}

/// Read `/proc/<pid>/stat` and extract field 22 (starttime).
///
/// The comm field (field 2) can contain spaces, closing parens, and other
/// characters. The correct parse strategy is to find the **last** `)` in the
/// line, then split everything after it by whitespace. Field 22 in the kernel's
/// 1-indexed numbering is at offset 19 in the 0-indexed post-comm array.
fn read_start_time(pid: u32) -> Result<u64, GateError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| {
        GateError::AgentVerification(format!("failed to read /proc/{pid}/stat: {e}"))
    })?;

    let last_paren = stat.rfind(')').ok_or_else(|| {
        GateError::AgentVerification(format!("/proc/{pid}/stat: no closing parenthesis"))
    })?;

    let remainder = &stat[last_paren + 1..];
    let fields: Vec<&str> = remainder.split_whitespace().collect();

    // After the closing paren we have fields 3..N (kernel 1-indexed).
    // Field 22 (starttime) is at index 22 - 3 = 19 in this 0-indexed array.
    const STARTTIME_INDEX: usize = 19;

    let field = fields.get(STARTTIME_INDEX).ok_or_else(|| {
        GateError::AgentVerification(format!(
            "/proc/{pid}/stat: not enough fields after comm (got {}, need {})",
            fields.len(),
            STARTTIME_INDEX + 1
        ))
    })?;

    field.parse::<u64>().map_err(|e| {
        GateError::AgentVerification(format!(
            "/proc/{pid}/stat: field 22 is not u64: {e} (raw: {field})"
        ))
    })
}

/// Compute the composite agent fingerprint.
///
/// `SHA-256(uid_le || pid_le || binary_hash || start_time_le)`
fn compute_fingerprint(uid: u32, pid: u32, binary_hash: &[u8; 32], start_time: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(uid.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(binary_hash);
    hasher.update(start_time.to_le_bytes());
    hasher.finalize().into()
}

/// Spawn a liveness monitor that detects when a process exits via its pidfd.
///
/// When the pidfd becomes readable the process has exited. A
/// `DeathNotification` is sent on `death_tx` so the router can deregister
/// the agent immediately.
pub fn spawn_liveness_monitor(
    pidfd: &OwnedFd,
    pid: u32,
    fingerprint_hash: [u8; 32],
    death_tx: mpsc::Sender<DeathNotification>,
) -> tokio::task::JoinHandle<()> {
    // Dup the fd so the original stays with AgentFingerprint.
    let dup_fd = unsafe {
        let raw = libc::dup(pidfd.as_raw_fd());
        if raw < 0 {
            tracing::error!(pid, "failed to dup pidfd — liveness monitor disabled");
            return tokio::spawn(async {});
        }
        OwnedFd::from_raw_fd(raw)
    };

    tokio::spawn(async move {
        // AsyncFd requires the fd to implement AsRawFd.
        use tokio::io::unix::AsyncFd;

        match AsyncFd::new(dup_fd) {
            Ok(async_fd) => {
                // readable() returns when the fd becomes readable (process exit).
                let _ = async_fd.readable().await;
                tracing::info!(pid, "agent process exited (pidfd readable)");
                let _ = death_tx
                    .send(DeathNotification {
                        pid,
                        fingerprint_hash,
                    })
                    .await;
            }
            Err(e) => {
                tracing::error!(pid, error = %e, "failed to create AsyncFd for pidfd");
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_fingerprint_determinism() {
        let binary_hash = [0xab; 32];
        let a = compute_fingerprint(1000, 42, &binary_hash, 123456);
        let b = compute_fingerprint(1000, 42, &binary_hash, 123456);
        assert_eq!(a, b);
    }

    #[test]
    fn compute_fingerprint_different_inputs() {
        let binary_hash = [0xab; 32];
        let a = compute_fingerprint(1000, 42, &binary_hash, 123456);
        let b = compute_fingerprint(1001, 42, &binary_hash, 123456); // different uid
        let c = compute_fingerprint(1000, 43, &binary_hash, 123456); // different pid
        let d = compute_fingerprint(1000, 42, &binary_hash, 123457); // different start_time
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn read_binary_path_self() {
        let path = read_binary_path(std::process::id()).unwrap();
        assert!(path.exists(), "binary path should exist: {}", path.display());
    }

    #[test]
    fn read_start_time_self() {
        let st = read_start_time(std::process::id()).unwrap();
        assert!(st > 0, "start time should be positive, got {st}");
    }

    #[test]
    fn hash_binary_self() {
        let binary_path = read_binary_path(std::process::id()).unwrap();
        let hash = hash_binary(&binary_path).unwrap();
        assert_eq!(hash.len(), 32);
        // Hash should be deterministic for the same binary.
        let hash2 = hash_binary(&binary_path).unwrap();
        assert_eq!(hash, hash2);
    }
}
