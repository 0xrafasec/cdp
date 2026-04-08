//! ASKPASS helper mode for cdp-wrap.
//!
//! When `cdp-wrap` is invoked as an ASKPASS helper (via the `--askpass` flag or
//! by detecting `argv[0]` contains "cdp-askpass"), it:
//!
//! 1. Reads the file descriptor number from the `CDP_PIPE_FD` environment variable.
//! 2. Reads the credential from that file descriptor.
//! 3. Writes it to stdout (which the calling program reads).
//! 4. Zeroizes the buffer before exit.
//!
//! This keeps credentials off the command line and out of environment variables
//! in the parent process. The pipe is write-once: the parent writes the
//! credential, then closes its write end; the child (this helper) reads exactly
//! what was written and exits.

use std::io::Write;
use std::os::unix::io::FromRawFd;

use tracing::debug;
use zeroize::Zeroizing;

use crate::WrapError;

/// Name of the environment variable carrying the readable pipe file descriptor.
pub const CDP_PIPE_FD_ENV: &str = "CDP_PIPE_FD";

/// Run the ASKPASS helper logic and write the credential to stdout.
///
/// Returns `Ok(())` on success. The caller should `std::process::exit(0)`.
/// On error the caller should `std::process::exit(1)`.
///
/// # Security
/// - The credential is read into a `Zeroizing<Vec<u8>>` and zeroed before
///   this function returns.
/// - Core dumps are disabled before reading the credential.
/// - No tracing of the credential value itself.
pub fn run_askpass() -> Result<(), WrapError> {
    // Disable core dumps immediately to protect the credential in memory.
    cdp_crypto::disable_core_dumps()
        .map_err(|e| WrapError::CredentialDelivery(format!("disable_core_dumps: {e}")))?;

    let fd_str = std::env::var(CDP_PIPE_FD_ENV).map_err(|_| {
        WrapError::CredentialDelivery(format!(
            "ASKPASS helper: {CDP_PIPE_FD_ENV} environment variable not set"
        ))
    })?;

    let fd: i32 = fd_str.parse().map_err(|_| {
        WrapError::CredentialDelivery(format!(
            "ASKPASS helper: {CDP_PIPE_FD_ENV} is not a valid integer: {fd_str}"
        ))
    })?;

    if fd < 0 {
        return Err(WrapError::CredentialDelivery(format!(
            "ASKPASS helper: {CDP_PIPE_FD_ENV} is negative: {fd}"
        )));
    }

    debug!("ASKPASS helper: reading credential from fd {fd}");

    // SAFETY: fd is a valid open file descriptor that we inherit from the
    // parent process. We take exclusive ownership — the parent has closed its
    // read end and we will close our end when the File is dropped.
    let mut pipe_file = unsafe { std::fs::File::from_raw_fd(fd) };

    let mut credential = Zeroizing::new(Vec::<u8>::with_capacity(256));
    use std::io::Read;
    pipe_file
        .read_to_end(&mut credential)
        .map_err(|e| WrapError::CredentialDelivery(format!("read from pipe fd {fd}: {e}")))?;

    // Drop the file (closes the fd) before writing to stdout.
    drop(pipe_file);

    if credential.is_empty() {
        return Err(WrapError::CredentialDelivery(
            "ASKPASS helper: received empty credential".to_string(),
        ));
    }

    // Write to stdout. Git/SSH reads one line; ensure we end with '\n'.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(&credential)
        .map_err(|e| WrapError::CredentialDelivery(format!("write credential to stdout: {e}")))?;

    // Ensure newline terminator.
    if credential.last().copied() != Some(b'\n') {
        out.write_all(b"\n")
            .map_err(|e| WrapError::CredentialDelivery(format!("write newline to stdout: {e}")))?;
    }
    out.flush()
        .map_err(|e| WrapError::CredentialDelivery(format!("flush stdout: {e}")))?;

    // credential is zeroized on drop by Zeroizing<T>.
    Ok(())
}

/// Determine whether `argv[0]` (or an explicit flag) requests ASKPASS mode.
///
/// Returns `true` if:
/// - `argv[0]` contains "cdp-askpass" (i.e. invoked via symlink), OR
/// - `args` contains `"--askpass"` as the first argument.
pub fn is_askpass_mode(argv0: &str, args: &[String]) -> bool {
    // Check if binary name suggests askpass mode.
    let name = std::path::Path::new(argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(argv0);

    if name.contains("cdp-askpass") || name.contains("askpass") {
        return true;
    }

    // Check for explicit --askpass flag as the first argument.
    args.first().map(|a| a == "--askpass").unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_askpass_mode_symlink_name() {
        assert!(is_askpass_mode("cdp-askpass", &[]));
        assert!(is_askpass_mode("/usr/local/bin/cdp-askpass", &[]));
        assert!(is_askpass_mode("askpass", &[]));
    }

    #[test]
    fn test_is_askpass_mode_flag() {
        assert!(is_askpass_mode("cdp-wrap", &["--askpass".to_string()]));
    }

    #[test]
    fn test_is_askpass_mode_false() {
        assert!(!is_askpass_mode("cdp-wrap", &[]));
        assert!(!is_askpass_mode(
            "cdp-wrap",
            &["git".to_string(), "push".to_string()]
        ));
    }

    #[test]
    fn test_run_askpass_missing_env() {
        // Remove CDP_PIPE_FD to simulate missing environment.
        unsafe { std::env::remove_var(CDP_PIPE_FD_ENV) };
        let result = run_askpass();
        assert!(
            matches!(result, Err(WrapError::CredentialDelivery(_))),
            "should fail when CDP_PIPE_FD is not set"
        );
    }

    #[test]
    fn test_run_askpass_invalid_fd_string() {
        unsafe { std::env::set_var(CDP_PIPE_FD_ENV, "not_a_number") };
        let result = run_askpass();
        // Restore env.
        unsafe { std::env::remove_var(CDP_PIPE_FD_ENV) };
        assert!(
            matches!(result, Err(WrapError::CredentialDelivery(_))),
            "should fail when CDP_PIPE_FD is not a number"
        );
    }

    #[test]
    fn test_run_askpass_negative_fd() {
        unsafe { std::env::set_var(CDP_PIPE_FD_ENV, "-1") };
        let result = run_askpass();
        unsafe { std::env::remove_var(CDP_PIPE_FD_ENV) };
        assert!(
            matches!(result, Err(WrapError::CredentialDelivery(_))),
            "should fail on negative fd"
        );
    }

    #[test]
    fn test_run_askpass_via_real_pipe() {
        use std::io::Write;
        use std::os::unix::io::IntoRawFd;

        // Create a pipe.
        let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe");

        // Write credential to write end.
        let credential = b"test-credential-value";
        {
            let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd.into_raw_fd()) };
            write_file.write_all(credential).expect("write");
            // write_file dropped here, closing the write end.
        }

        // Set env var so run_askpass can find the fd.
        let read_raw: i32 = read_fd.into_raw_fd();
        unsafe { std::env::set_var(CDP_PIPE_FD_ENV, read_raw.to_string()) };

        // run_askpass will write to stdout; in test context that's fine.
        // We primarily verify it returns Ok.
        let result = run_askpass();
        unsafe { std::env::remove_var(CDP_PIPE_FD_ENV) };

        assert!(result.is_ok(), "run_askpass failed: {:?}", result.err());
    }
}
