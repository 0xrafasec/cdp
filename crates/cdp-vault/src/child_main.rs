//! Vault subprocess entry point.
//!
//! This module is invoked when the Gate binary is re-exec'd with
//! `--vault-worker <socket_fd> <bw_cli_path> <sandbox_enabled>`.
//!
//! The subprocess uses synchronous I/O only — no Tokio runtime — keeping the
//! implementation simple and reducing the attack surface. It reads
//! length-prefixed JSON commands from the socket, dispatches them to the
//! [`BitwardenBackend`], and writes length-prefixed JSON responses back.

use std::os::unix::io::FromRawFd;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroize;

use crate::bitwarden::{BitwardenBackend, BwCliExecutor};
use crate::protocol::{VaultCommand, VaultResponse, read_message_sync, write_message_sync};
use crate::sandbox::{apply_sandbox, close_extra_fds};

/// Entry point for the vault subprocess worker.
///
/// Called when the process is re-exec'd with
/// `--vault-worker <socket_fd> <bw_cli_path> <sandbox_enabled>`.
///
/// This function never returns; it exits via [`std::process::exit`].
pub fn vault_worker_main(socket_fd: i32, bw_cli_path: &str, sandbox_enabled: bool) -> ! {
    // Apply sandbox immediately: disable core dumps, optionally PID namespace
    // and seccomp filter.
    if let Err(e) = apply_sandbox(sandbox_enabled) {
        eprintln!("vault worker: sandbox setup failed: {e}");
        std::process::exit(1);
    }

    // Close all file descriptors except stdin, stdout, stderr, and the socket.
    close_extra_fds(socket_fd);

    // SAFETY: The parent has passed us a valid, open Unix socket fd.
    // We take ownership here and will not duplicate or close it elsewhere.
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(socket_fd) };

    let mut reader = std::io::BufReader::new(
        stream
            .try_clone()
            .expect("vault worker: failed to clone socket for reading"),
    );
    let mut writer = std::io::BufWriter::new(stream);

    let executor = BwCliExecutor::new(bw_cli_path);
    let mut backend = BitwardenBackend::new(Box::new(executor));

    // -----------------------------------------------------------------------
    // Command loop
    // -----------------------------------------------------------------------

    loop {
        let raw = match read_message_sync(&mut reader) {
            Ok(bytes) => bytes,
            Err(_) => {
                // Parent closed the connection or I/O error — clean exit.
                std::process::exit(0);
            }
        };

        let response = match serde_json::from_slice::<VaultCommand>(&raw) {
            Ok(cmd) => dispatch(&mut backend, cmd),
            Err(e) => VaultResponse::Error {
                message: format!("failed to deserialize command: {e}"),
            },
        };

        let response_bytes = match serde_json::to_vec(&response) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("vault worker: failed to serialize response: {e}");
                std::process::exit(1);
            }
        };

        if write_message_sync(&mut writer, &response_bytes).is_err() {
            // Parent has closed the connection.
            std::process::exit(0);
        }
    }
}

/// Dispatch a single [`VaultCommand`] to the backend and return a [`VaultResponse`].
fn dispatch(backend: &mut BitwardenBackend, cmd: VaultCommand) -> VaultResponse {
    match cmd {
        VaultCommand::Init { key } => match BASE64.decode(&key) {
            Ok(mut bytes) if bytes.len() == 32 => {
                let mut ipc_key = [0u8; 32];
                ipc_key.copy_from_slice(&bytes);
                bytes.zeroize();
                backend.set_ipc_key(ipc_key);
                VaultResponse::Ok {
                    data: serde_json::Value::Null,
                }
            }
            Ok(bytes) => VaultResponse::Error {
                message: format!("Init key must be 32 bytes, got {}", bytes.len()),
            },
            Err(e) => VaultResponse::Error {
                message: format!("Init key base64 decode error: {e}"),
            },
        },

        VaultCommand::Unlock { password } => match backend.unlock(&password) {
            Ok(()) => VaultResponse::Ok {
                data: serde_json::Value::Null,
            },
            Err(e) => VaultResponse::Error {
                message: e.to_string(),
            },
        },

        VaultCommand::List => match backend.list() {
            Ok(refs) => VaultResponse::Ok {
                data: serde_json::to_value(refs).unwrap_or(serde_json::Value::Null),
            },
            Err(e) => VaultResponse::Error {
                message: e.to_string(),
            },
        },

        VaultCommand::Fetch { ref_id } => match backend.fetch(&ref_id) {
            Ok(enc) => {
                let payload = serde_json::json!({
                    "data": BASE64.encode(&enc.data),
                    "nonce": BASE64.encode(enc.nonce),
                });
                VaultResponse::Ok { data: payload }
            }
            Err(e) => VaultResponse::Error {
                message: e.to_string(),
            },
        },

        VaultCommand::Exists { ref_id } => match backend.exists(&ref_id) {
            Ok(found) => VaultResponse::Ok {
                data: serde_json::Value::Bool(found),
            },
            Err(e) => VaultResponse::Error {
                message: e.to_string(),
            },
        },
    }
}
