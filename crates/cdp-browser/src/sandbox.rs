//! Browser sandbox: spawn headless Chromium in an isolated environment.
//!
//! Tries bubblewrap (`bwrap`) first for full namespace isolation. Falls back
//! to `unshare` if bubblewrap is unavailable. Communication with the browser
//! controller is via an anonymous Unix socketpair using the same
//! length-prefixed JSON protocol as cdp-vault.
//!
//! Wire format: `4-byte big-endian len || JSON payload`. Maximum 16 MiB.
//!
//! After the snapshot is complete the subprocess is unconditionally SIGKILL'd.

use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Child;
use tracing::{debug, warn};

use crate::BrowserError;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Maximum allowed IPC message size (16 MiB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Sandbox configuration
// ---------------------------------------------------------------------------

/// Configuration for the browser sandbox subprocess.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Path to the bubblewrap (`bwrap`) binary.
    pub bwrap_path: String,
    /// Path to the headless Chromium binary.
    pub chromium_path: String,
    /// Enable seccomp BPF filtering in the subprocess (passed as a flag).
    pub enable_seccomp: bool,
    /// Enable PID namespace isolation via `--unshare-pid`.
    pub enable_pid_namespace: bool,
    /// Enable network namespace isolation with loopback only.
    pub enable_net_namespace: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            bwrap_path: "/usr/bin/bwrap".to_string(),
            chromium_path: "/usr/bin/chromium".to_string(),
            enable_seccomp: true,
            enable_pid_namespace: true,
            enable_net_namespace: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IPC protocol commands and responses
// ---------------------------------------------------------------------------

/// Commands sent from the parent process to the browser subprocess.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum BrowserCommand {
    /// Navigate to the given URL.
    Navigate { url: String },
    /// Fill credential fields using CSS selectors.
    FillCredentials {
        username: String,
        password: String,
        username_selector: String,
        password_selector: String,
    },
    /// Submit the login form by clicking the given selector.
    Submit { selector: String },
    /// Wait for login completion using the provided indicator.
    WaitForLogin {
        success_indicator: SuccessIndicatorMsg,
    },
    /// Extract all cookies from the current session.
    ExtractCookies,
    /// Submit a 2FA code.
    Enter2Fa { code: String },
    /// Shut down the browser subprocess cleanly.
    Shutdown,
}

/// Success indicator transmitted over IPC (mirrors the public API type).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SuccessIndicatorMsg {
    UrlChange { pattern: String },
    CookiePresent { name: String },
    SelectorAppears { selector: String },
}

/// Responses sent from the browser subprocess back to the parent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BrowserResponse {
    /// Success; optional `data` payload.
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    /// Error with a human-readable message.
    Error { message: String },
    /// 2FA challenge detected; parent should request code and send `Enter2FA`.
    TwoFaRequired { hint: String },
}

// ---------------------------------------------------------------------------
// BrowserSandbox
// ---------------------------------------------------------------------------

/// Factory for spawning sandboxed browser subprocesses.
pub struct BrowserSandbox {
    config: SandboxConfig,
}

impl BrowserSandbox {
    /// Create a new sandbox factory with the given configuration.
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Spawn a sandboxed browser subprocess.
    ///
    /// Creates an anonymous socketpair for IPC, then launches either
    /// bubblewrap or unshare depending on availability. Returns a
    /// [`SandboxedProcess`] that can send commands and receive responses.
    pub async fn spawn(&self, socket_fd: Option<RawFd>) -> Result<SandboxedProcess, BrowserError> {
        use std::os::unix::io::IntoRawFd;

        // Create socketpair for bidirectional IPC.
        let (parent_fd, child_fd) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .map_err(|e| BrowserError::Sandbox(format!("socketpair: {e}")))?;

        // If caller provided an external socket fd for data, we use ours for
        // control. For the browser case we only need one pair.
        let _ = socket_fd; // reserved for future extension

        let child_fd_raw: RawFd = child_fd.into_raw_fd();
        let parent_fd_raw: RawFd = parent_fd.into_raw_fd();

        // Try bubblewrap first; fall back to unshare.
        let child = if std::path::Path::new(&self.config.bwrap_path).exists() {
            self.spawn_with_bwrap(child_fd_raw).await?
        } else {
            warn!(
                "bwrap not found at '{}'; falling back to unshare",
                self.config.bwrap_path
            );
            self.spawn_with_unshare(child_fd_raw).await?
        };

        // Close child fd on the parent side.
        // SAFETY: child_fd_raw is valid; we transferred ownership to the child.
        unsafe { libc::close(child_fd_raw) };

        // Convert parent fd to Tokio UnixStream.
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(parent_fd_raw) };
        std_stream.set_nonblocking(true).map_err(BrowserError::Io)?;
        let stream = UnixStream::from_std(std_stream)
            .map_err(|e| BrowserError::Subprocess(format!("UnixStream::from_std: {e}")))?;

        let (read_half, write_half) = stream.into_split();

        let child_pid = child
            .id()
            .map(|id| Pid::from_raw(id as i32))
            .ok_or_else(|| BrowserError::Subprocess("child has no PID".to_string()))?;

        Ok(SandboxedProcess {
            child,
            child_pid,
            reader: BufReader::new(read_half),
            writer: write_half,
        })
    }

    /// Launch Chromium wrapped in bubblewrap with full namespace isolation.
    async fn spawn_with_bwrap(&self, child_fd: RawFd) -> Result<Child, BrowserError> {
        use tokio::process::Command;

        let mut cmd = Command::new(&self.config.bwrap_path);

        // Filesystem bindings.
        cmd.args(["--ro-bind", "/", "/"])
            .args(["--dev", "/dev"])
            .args(["--proc", "/proc"])
            .args(["--tmpfs", "/tmp"]);

        // PID namespace isolation.
        if self.config.enable_pid_namespace {
            cmd.arg("--unshare-pid");
        }

        // Network namespace (loopback only) for isolation.
        if self.config.enable_net_namespace {
            cmd.arg("--unshare-net");
        }

        // User namespace.
        cmd.arg("--unshare-user");

        // Die with parent to prevent orphaned processes.
        cmd.arg("--die-with-parent");

        // Pass the child socket fd to the subprocess.
        cmd.args(["--setenv", "CDP_BROWSER_FD", &child_fd.to_string()]);

        // Seccomp flag — the subprocess reads this from env.
        if self.config.enable_seccomp {
            cmd.args(["--setenv", "CDP_BROWSER_SECCOMP", "1"]);
        }

        // The actual command to run inside the sandbox.
        cmd.arg(&self.config.chromium_path).args([
            "--headless=new",
            "--no-sandbox", // bwrap provides sandboxing
            "--disable-gpu",
            "--remote-debugging-port=0",
            "--enable-automation",
            "--disable-extensions",
            "--disable-default-apps",
        ]);

        // Make child_fd inheritable.
        // SAFETY: We're setting close-on-exec = false for this specific fd.
        unsafe {
            libc::fcntl(child_fd, libc::F_SETFD, 0);
        }

        let child = cmd
            .spawn()
            .map_err(|e| BrowserError::Subprocess(format!("bwrap spawn: {e}")))?;

        debug!("spawned browser via bwrap, pid={:?}", child.id());
        Ok(child)
    }

    /// Fall back to `unshare` if bubblewrap is unavailable.
    async fn spawn_with_unshare(&self, child_fd: RawFd) -> Result<Child, BrowserError> {
        use tokio::process::Command;

        let mut cmd = Command::new("unshare");

        if self.config.enable_pid_namespace {
            cmd.arg("--pid");
            cmd.arg("--fork");
        }

        if self.config.enable_net_namespace {
            cmd.arg("--net");
        }

        // Pass socket fd and seccomp flag via environment.
        cmd.env("CDP_BROWSER_FD", child_fd.to_string());
        if self.config.enable_seccomp {
            cmd.env("CDP_BROWSER_SECCOMP", "1");
        }

        cmd.arg(&self.config.chromium_path).args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--remote-debugging-port=0",
            "--enable-automation",
            "--disable-extensions",
            "--disable-default-apps",
        ]);

        // Make child_fd inheritable.
        unsafe {
            libc::fcntl(child_fd, libc::F_SETFD, 0);
        }

        let child = cmd
            .spawn()
            .map_err(|e| BrowserError::Subprocess(format!("unshare spawn: {e}")))?;

        debug!("spawned browser via unshare, pid={:?}", child.id());
        Ok(child)
    }
}

// ---------------------------------------------------------------------------
// SandboxedProcess
// ---------------------------------------------------------------------------

/// A running sandboxed browser subprocess with an IPC channel.
///
/// Commands are sent as length-prefixed JSON frames; responses are read the
/// same way. Call [`kill`](SandboxedProcess::kill) when done — do not rely on
/// Drop for cleanup (it's synchronous).
pub struct SandboxedProcess {
    child: Child,
    child_pid: Pid,
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl SandboxedProcess {
    /// Send a command to the browser subprocess and wait for a response.
    pub async fn send_command(
        &mut self,
        cmd: &BrowserCommand,
    ) -> Result<BrowserResponse, BrowserError> {
        let payload = serde_json::to_vec(cmd)
            .map_err(|e| BrowserError::Protocol(format!("serialize command: {e}")))?;

        write_message(&mut self.writer, &payload).await?;

        let raw = read_message(&mut self.reader).await?;

        let response: BrowserResponse = serde_json::from_slice(&raw)
            .map_err(|e| BrowserError::Protocol(format!("deserialize response: {e}")))?;

        Ok(response)
    }

    /// SIGKILL the subprocess immediately.
    ///
    /// This must be called after cookie extraction — the browser is never left running.
    pub fn kill(&mut self) {
        // SAFETY: Sending SIGKILL to a child process we spawned.
        let ret = unsafe { libc::kill(self.child_pid.as_raw(), libc::SIGKILL) };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            warn!(
                "failed to SIGKILL browser subprocess (pid={}): {e}",
                self.child_pid
            );
        }
        // Also use tokio's kill to release resources.
        let _ = self.child.start_kill();
    }

    /// Return the child PID.
    pub fn pid(&self) -> Pid {
        self.child_pid
    }
}

impl Drop for SandboxedProcess {
    fn drop(&mut self) {
        // Belt-and-suspenders: always SIGKILL on drop.
        // SAFETY: Sending SIGKILL to a child process we spawned.
        unsafe { libc::kill(self.child_pid.as_raw(), libc::SIGKILL) };
    }
}

// ---------------------------------------------------------------------------
// IPC framing helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed message to an async writer.
async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), BrowserError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(BrowserError::Protocol(format!(
            "payload size {} exceeds max {}",
            payload.len(),
            MAX_MESSAGE_SIZE
        )));
    }
    let len = payload.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(BrowserError::Io)?;
    writer.write_all(payload).await.map_err(BrowserError::Io)?;
    writer.flush().await.map_err(BrowserError::Io)?;
    Ok(())
}

/// Read a length-prefixed message from an async reader.
async fn read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>, BrowserError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(BrowserError::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(BrowserError::Protocol(format!(
            "declared message length {len} exceeds maximum {MAX_MESSAGE_SIZE}"
        )));
    }

    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(BrowserError::Io)?;
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default() {
        let cfg = SandboxConfig::default();
        assert_eq!(cfg.bwrap_path, "/usr/bin/bwrap");
        assert_eq!(cfg.chromium_path, "/usr/bin/chromium");
        assert!(cfg.enable_seccomp);
        assert!(cfg.enable_pid_namespace);
        assert!(!cfg.enable_net_namespace);
    }

    #[test]
    fn test_browser_command_serde_navigate() {
        let cmd = BrowserCommand::Navigate {
            url: "https://example.com/login".to_string(),
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let decoded: BrowserCommand = serde_json::from_str(&json).expect("deserialize");
        assert!(
            matches!(decoded, BrowserCommand::Navigate { url } if url == "https://example.com/login")
        );
    }

    #[test]
    fn test_browser_command_serde_fill_credentials() {
        let cmd = BrowserCommand::FillCredentials {
            username: "alice".to_string(),
            password: "s3cr3t".to_string(),
            username_selector: "input[name=username]".to_string(),
            password_selector: "input[type=password]".to_string(),
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let decoded: BrowserCommand = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, BrowserCommand::FillCredentials { .. }));
    }

    #[test]
    fn test_browser_command_serde_shutdown() {
        let cmd = BrowserCommand::Shutdown;
        let json = serde_json::to_string(&cmd).expect("serialize");
        let decoded: BrowserCommand = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, BrowserCommand::Shutdown));
    }

    #[test]
    fn test_browser_response_serde_ok() {
        let resp = BrowserResponse::Ok { data: None };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: BrowserResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, BrowserResponse::Ok { .. }));
    }

    #[test]
    fn test_browser_response_serde_error() {
        let resp = BrowserResponse::Error {
            message: "navigation failed".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: BrowserResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(
            matches!(decoded, BrowserResponse::Error { message } if message == "navigation failed")
        );
    }

    #[test]
    fn test_browser_response_serde_twofa() {
        let resp = BrowserResponse::TwoFaRequired {
            hint: "Enter the code from your authenticator".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: BrowserResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, BrowserResponse::TwoFaRequired { .. }));
    }

    #[test]
    fn test_success_indicator_msg_serde() {
        let ind = SuccessIndicatorMsg::UrlChange {
            pattern: "dashboard".to_string(),
        };
        let json = serde_json::to_string(&ind).expect("serialize");
        let decoded: SuccessIndicatorMsg = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, SuccessIndicatorMsg::UrlChange { .. }));
    }

    #[tokio::test]
    async fn test_framing_roundtrip() {
        // Test write_message / read_message roundtrip using in-memory pipe.
        let (reader_half, writer_half) = tokio::io::duplex(1024);
        let (mut reader, mut writer) = (tokio::io::BufReader::new(reader_half), writer_half);

        let payload = b"hello browser";
        write_message(&mut writer, payload).await.expect("write");
        let decoded = read_message(&mut reader).await.expect("read");
        assert_eq!(&decoded, payload);
    }

    #[tokio::test]
    async fn test_framing_oversized_rejected() {
        // Construct a frame declaring > 16 MiB.
        let oversized_len: u32 = (MAX_MESSAGE_SIZE as u32) + 1;
        let mut framed = Vec::new();
        framed.extend_from_slice(&oversized_len.to_be_bytes());

        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(framed));
        let result = read_message(&mut cursor).await;
        assert!(
            matches!(result, Err(BrowserError::Protocol(_))),
            "expected Protocol error for oversized message"
        );
    }
}
