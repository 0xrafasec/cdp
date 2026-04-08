//! Process isolation utilities for the CLI wrapper.
//!
//! Provides `spawn_isolated` which attempts to run the child command in a new
//! PID namespace (via `CLONE_NEWPID` unshare) for additional process-level
//! isolation. If PID namespace creation fails (e.g. insufficient capabilities),
//! it falls back to a normal fork/exec.
//!
//! Security measures applied unconditionally:
//! - `PR_SET_DUMPABLE=0` on the child to prevent ptrace and /proc/pid/mem access.
//! - `RLIMIT_CORE=0` so core files cannot capture credential memory.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;

use nix::sys::resource::{Resource, setrlimit};
use tracing::{debug, warn};

use crate::WrapError;

/// Spawn `command args` with `env` set in the environment, inheriting `pipe_fd`
/// from the parent.
///
/// The child will have:
/// - `PR_SET_DUMPABLE=0` (best-effort; logs warning on failure).
/// - `RLIMIT_CORE=0`.
/// - The PID namespace unshared via `CLONE_NEWPID` (best-effort; falls back silently).
///
/// `pipe_fd` is the read end of the credential pipe. It must be kept open in
/// the child so the ASKPASS helper (a re-exec of this binary) can read from it.
///
/// The returned `Child` is managed by the standard library; the caller is
/// responsible for `wait`ing on it.
pub fn spawn_isolated(
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
    pipe_fd: Option<RawFd>,
) -> Result<Child, WrapError> {
    use std::process::Command;

    let mut cmd = Command::new(command);
    cmd.args(args);

    // Start from a clean environment, then overlay provided variables.
    // This avoids accidentally leaking sensitive variables from the parent.
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }

    // Inherit necessary system variables that programs often rely on.
    for var in &["PATH", "HOME", "USER", "LOGNAME", "TERM", "LANG", "LC_ALL"] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    // Apply pre-exec hooks for the child process.
    // SAFETY: The closure runs after fork() but before exec(). It must only
    // call async-signal-safe functions. libc::prctl and setrlimit are safe.
    unsafe {
        let pipe_fd_copy = pipe_fd;
        cmd.pre_exec(move || {
            // Attempt to unshare PID namespace (best-effort).
            #[cfg(target_os = "linux")]
            {
                use nix::sched::{CloneFlags, unshare};
                if let Err(e) = unshare(CloneFlags::CLONE_NEWPID) {
                    // Not fatal — secrecy still holds without PID namespace.
                    // eprintln is safe in pre_exec context.
                    eprintln!("cdp-wrap: CLONE_NEWPID failed (non-fatal): {e}");
                }
            }

            // Disable core dumps in the child.
            let rc = libc::prctl(libc::PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64);
            if rc != 0 {
                eprintln!("cdp-wrap: PR_SET_DUMPABLE=0 failed (non-fatal)");
            }

            // Set RLIMIT_CORE to zero.
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &zero);

            // Ensure the pipe fd is not marked close-on-exec so the ASKPASS
            // helper subprocess can inherit it.
            if let Some(fd) = pipe_fd_copy {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 {
                    // Clear FD_CLOEXEC.
                    libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
            }

            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .map_err(|e| WrapError::Child(format!("spawn {command}: {e}")))?;

    debug!(pid = child.id(), cmd = %command, "spawned child process");
    Ok(child)
}

/// Apply security restrictions to the current process.
///
/// Called in the parent after fork to ensure the parent also benefits from
/// `PR_SET_DUMPABLE=0` during credential handling.
pub fn harden_current_process() -> Result<(), WrapError> {
    // Disable core dumps.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64) };
    if rc != 0 {
        warn!("PR_SET_DUMPABLE=0 failed in parent process (non-fatal)");
    }

    // Set RLIMIT_CORE to zero (belt-and-suspenders).
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| WrapError::Namespace(format!("setrlimit RLIMIT_CORE: {e}")))?;

    Ok(())
}

/// Convert a Rust `&str` to a `CString`, returning a `WrapError` on embedded
/// NUL bytes (which would be a programming error or injection attempt).
pub fn to_cstring(s: &str) -> Result<CString, WrapError> {
    CString::new(s).map_err(|e| WrapError::Namespace(format!("invalid command string: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harden_current_process() {
        // Should not fail on a standard Linux system.
        let result = harden_current_process();
        assert!(
            result.is_ok(),
            "harden_current_process failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_to_cstring_valid() {
        let cs = to_cstring("echo").expect("should succeed");
        assert_eq!(cs.to_str().unwrap(), "echo");
    }

    #[test]
    fn test_to_cstring_nul_byte() {
        let result = to_cstring("echo\0injected");
        assert!(result.is_err(), "NUL byte should be rejected");
    }

    #[test]
    fn test_spawn_isolated_echo() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());

        let mut child = spawn_isolated("echo", &["hello".to_string()], &env, None)
            .expect("spawn echo should succeed");

        let status = child.wait().expect("wait should succeed");
        assert!(status.success(), "echo should exit 0");
    }

    #[test]
    fn test_spawn_isolated_nonexistent_command() {
        let env = HashMap::new();
        let result = spawn_isolated("/nonexistent/binary/cdp_test_xyz", &[], &env, None);
        assert!(result.is_err(), "spawning nonexistent binary should fail");
    }
}
