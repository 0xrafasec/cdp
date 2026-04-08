//! CDP CLI wrapper library — credential injection via the ASKPASS pipe pattern.
//!
//! Provides secure credential delivery to CLI tools (git, ssh, curl) without
//! exposing secrets in environment variables or process listings.

pub mod askpass;
pub mod exec;
pub mod gate_client;
pub mod namespace;
pub mod sanitize;

use thiserror::Error;

/// Errors produced by the cdp-cli-wrap crate.
#[derive(Debug, Error)]
pub enum WrapError {
    /// Gate connection or protocol error.
    #[error("gate error: {0}")]
    Gate(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Child process spawn or wait error.
    #[error("child process error: {0}")]
    Child(String),

    /// Credential delivery error (pipe write or memory handling).
    #[error("credential delivery error: {0}")]
    CredentialDelivery(String),

    /// Output sanitization error.
    #[error("sanitization error: {0}")]
    Sanitize(String),

    /// Namespace / isolation error.
    #[error("namespace error: {0}")]
    Namespace(String),

    /// Configuration error (e.g. missing fingerprint file).
    #[error("configuration error: {0}")]
    Config(String),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Signal handling error.
    #[error("signal error: {0}")]
    Signal(String),

    /// The child process exited with a non-zero status.
    #[error("child exited with status {0}")]
    ChildExitStatus(i32),
}

/// The method used to inject credentials into a child command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionMethod {
    /// Use GIT_ASKPASS environment variable (for `git`).
    GitAskpass,
    /// Use SSH_ASKPASS + SSH_ASKPASS_REQUIRE environment variables (for `ssh`).
    SshAskpass,
    /// Pipe credential via CDP_PIPE_FD, curl reads it via subshell (for `curl`).
    CurlPipe,
    /// Generic ASKPASS via CDP_PIPE_FD environment variable.
    GenericAskpass,
}

impl InjectionMethod {
    /// Determine the injection method from the command name.
    pub fn from_command(command: &str) -> Self {
        // Strip path prefix to get just the binary name.
        let name = std::path::Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);

        match name {
            "git" => Self::GitAskpass,
            "ssh" | "scp" | "sftp" => Self::SshAskpass,
            "curl" => Self::CurlPipe,
            _ => Self::GenericAskpass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_method_git() {
        assert_eq!(
            InjectionMethod::from_command("git"),
            InjectionMethod::GitAskpass
        );
        assert_eq!(
            InjectionMethod::from_command("/usr/bin/git"),
            InjectionMethod::GitAskpass
        );
    }

    #[test]
    fn test_injection_method_ssh() {
        assert_eq!(
            InjectionMethod::from_command("ssh"),
            InjectionMethod::SshAskpass
        );
        assert_eq!(
            InjectionMethod::from_command("scp"),
            InjectionMethod::SshAskpass
        );
        assert_eq!(
            InjectionMethod::from_command("sftp"),
            InjectionMethod::SshAskpass
        );
    }

    #[test]
    fn test_injection_method_curl() {
        assert_eq!(
            InjectionMethod::from_command("curl"),
            InjectionMethod::CurlPipe
        );
        assert_eq!(
            InjectionMethod::from_command("/usr/bin/curl"),
            InjectionMethod::CurlPipe
        );
    }

    #[test]
    fn test_injection_method_generic() {
        assert_eq!(
            InjectionMethod::from_command("aws"),
            InjectionMethod::GenericAskpass
        );
        assert_eq!(
            InjectionMethod::from_command("kubectl"),
            InjectionMethod::GenericAskpass
        );
    }
}
