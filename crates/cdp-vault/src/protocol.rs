//! IPC protocol types and framed message I/O for vault subprocess communication.
//!
//! Wire format: `4-byte big-endian length || JSON payload`.
//! Maximum message size: 16 MiB (prevents unbounded memory allocation).

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::VaultError;

/// Maximum allowed message payload size (16 MiB).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Protocol message types
// ---------------------------------------------------------------------------

/// Commands sent from the parent process to the vault subprocess.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum VaultCommand {
    /// Initialise the subprocess with the shared IPC encryption key.
    /// `key` is a base64-encoded 32-byte key.
    Init { key: String },
    /// Unlock the vault with the given master password.
    Unlock { password: String },
    /// List all credentials in the vault.
    List,
    /// Fetch a single credential by its vault-internal reference ID.
    Fetch { ref_id: String },
    /// Check whether a credential with the given ID exists.
    Exists { ref_id: String },
}

/// Responses sent from the vault subprocess back to the parent process.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VaultResponse {
    /// Successful response; `data` carries the operation-specific payload.
    Ok { data: serde_json::Value },
    /// Error response; `message` is a human-readable description.
    Error { message: String },
}

// ---------------------------------------------------------------------------
// Async I/O helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed message asynchronously.
///
/// Frame format: 4-byte big-endian `len` || `payload` (exactly `len` bytes).
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload exceeds max message size",
        ));
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed message asynchronously.
///
/// Returns `VaultError::Protocol` if the declared length exceeds [`MAX_MESSAGE_SIZE`].
pub async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, VaultError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(VaultError::Protocol(format!(
            "message length {len} exceeds maximum allowed size {MAX_MESSAGE_SIZE}"
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Synchronous I/O helpers (for use in the subprocess worker)
// ---------------------------------------------------------------------------

/// Write a length-prefixed message synchronously over a raw file descriptor.
///
/// Used inside the vault subprocess where Tokio is not available.
pub fn write_message_sync<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload exceeds max message size",
        ));
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed message synchronously from a raw file descriptor.
///
/// Returns `VaultError::Protocol` if the declared length exceeds [`MAX_MESSAGE_SIZE`].
pub fn read_message_sync<R: Read>(reader: &mut R) -> Result<Vec<u8>, VaultError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(VaultError::Protocol(format!(
            "message length {len} exceeds maximum allowed size {MAX_MESSAGE_SIZE}"
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        write_message_sync(&mut buf, payload).expect("write_message_sync");
        buf
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let payload = b"hello, vault!";
        let framed = make_message(payload);

        let mut cursor = std::io::Cursor::new(&framed);
        let decoded = read_message_sync(&mut cursor).expect("read_message_sync");
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn test_empty_message_roundtrip() {
        let payload = b"";
        let framed = make_message(payload);
        assert_eq!(&framed, &[0u8, 0, 0, 0]); // 4-byte zero length

        let mut cursor = std::io::Cursor::new(&framed);
        let decoded = read_message_sync(&mut cursor).expect("read_message_sync");
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_max_size_rejection() {
        // Construct a frame that declares a length exceeding 16 MiB.
        let oversized_len: u32 = (MAX_MESSAGE_SIZE as u32) + 1;
        let mut framed = Vec::new();
        framed.extend_from_slice(&oversized_len.to_be_bytes());
        // No actual payload needed — the rejection happens before reading payload.

        let mut cursor = std::io::Cursor::new(&framed);
        let result = read_message_sync(&mut cursor);
        assert!(
            matches!(result, Err(VaultError::Protocol(_))),
            "expected Protocol error for oversized message"
        );
    }

    #[test]
    fn test_vault_command_serde_roundtrip() {
        let cmd = VaultCommand::Fetch {
            ref_id: "abc-123".to_string(),
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let decoded: VaultCommand = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, VaultCommand::Fetch { ref_id } if ref_id == "abc-123"));
    }

    #[test]
    fn test_vault_response_ok_serde() {
        let resp = VaultResponse::Ok {
            data: serde_json::json!({"found": true}),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: VaultResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, VaultResponse::Ok { .. }));
    }

    #[test]
    fn test_vault_response_error_serde() {
        let resp = VaultResponse::Error {
            message: "vault locked".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: VaultResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(decoded, VaultResponse::Error { .. }));
    }

    #[tokio::test]
    async fn test_async_roundtrip() {
        use tokio::io::BufReader;

        let payload = b"async vault payload";
        let mut buf: Vec<u8> = Vec::new();
        write_message(&mut buf, payload).await.expect("write");

        let mut reader = BufReader::new(std::io::Cursor::new(&buf));
        let decoded = read_message(&mut reader).await.expect("read");
        assert_eq!(&decoded, payload);
    }

    #[tokio::test]
    async fn test_async_max_size_rejection() {
        let oversized_len: u32 = (MAX_MESSAGE_SIZE as u32) + 1;
        let mut framed = Vec::new();
        framed.extend_from_slice(&oversized_len.to_be_bytes());

        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(framed));
        let result = read_message(&mut cursor).await;
        assert!(
            matches!(result, Err(VaultError::Protocol(_))),
            "expected Protocol error"
        );
    }
}
