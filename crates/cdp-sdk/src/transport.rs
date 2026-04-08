//! Async JSON-RPC 2.0 transport over a Unix domain socket.
//!
//! Framing: each message is a single JSON object followed by a newline (`\n`).
//! Request IDs are monotonically incrementing `u64` values, unique per
//! `Transport` instance.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::types::{JsonRpcRequest, JsonRpcResponse};
use crate::{CdpError, Result};

/// Async JSON-RPC transport over a Unix domain socket.
pub struct Transport {
    writer: tokio::net::unix::OwnedWriteHalf,
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    id_counter: Arc<AtomicU64>,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("id_counter", &self.id_counter.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Connect to the gate Unix domain socket at `socket_path`.
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        tracing::debug!(path = %socket_path.display(), "connecting to gate socket");
        let stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| CdpError::Connection(format!("{}: {}", socket_path.display(), e)))?;

        let (read_half, write_half) = stream.into_split();
        Ok(Self {
            writer: write_half,
            reader: BufReader::new(read_half),
            id_counter: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Send a JSON-RPC request and wait for the response.
    ///
    /// Automatically injects a UUID v4 `nonce` and an RFC 3339 `timestamp`
    /// into `params` before sending. Returns the `result` field of the
    /// response, or an error if the gate returned an error object.
    pub async fn send(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.id_counter.fetch_add(1, Ordering::Relaxed);

        // Inject nonce and timestamp into params.
        let mut params = match params {
            Value::Object(map) => map,
            other => {
                return Err(CdpError::MalformedResponse(format!(
                    "params must be an object, got: {other}"
                )));
            }
        };
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        params.insert("nonce".to_string(), Value::String(nonce));
        params.insert("timestamp".to_string(), Value::String(timestamp));

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params: Value::Object(params),
            id,
        };

        let mut line = serde_json::to_string(&request)?;
        line.push('\n');

        tracing::trace!(method = method, id = id, "sending JSON-RPC request");
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(CdpError::Io)?;

        // Read response line.
        let mut response_line = String::new();
        self.reader
            .read_line(&mut response_line)
            .await
            .map_err(CdpError::Io)?;

        if response_line.is_empty() {
            return Err(CdpError::Connection(
                "gate closed the connection unexpectedly".to_string(),
            ));
        }

        let response: JsonRpcResponse = serde_json::from_str(response_line.trim())?;
        tracing::trace!(id = id, "received JSON-RPC response");

        if let Some(err) = response.error {
            return Err(CdpError::GateError {
                code: err.code,
                message: err.message,
            });
        }

        response
            .result
            .ok_or_else(|| CdpError::MalformedResponse("response missing 'result' field".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    /// Spin up a mock gate that reads one request and sends back a canned response.
    async fn mock_gate(
        listener: UnixListener,
        response: serde_json::Value,
    ) -> tokio::task::JoinHandle<String> {
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let resp = serde_json::to_string(&response).unwrap() + "\n";
            write_half.write_all(resp.as_bytes()).await.unwrap();
            line
        })
    }

    fn temp_socket_path() -> std::path::PathBuf {
        let id = uuid::Uuid::new_v4();
        std::env::temp_dir().join(format!("cdp-test-{id}.sock"))
    }

    #[tokio::test]
    async fn send_injects_nonce_and_timestamp() {
        let socket_path = temp_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();

        let response = json!({
            "jsonrpc": "2.0",
            "result": {"status": "ok"},
            "id": 1
        });

        let gate_handle = mock_gate(listener, response).await;
        let mut transport = Transport::connect(&socket_path).await.unwrap();

        let result = transport
            .send("cdp.test", json!({"key": "value"}))
            .await
            .unwrap();

        let received_line = gate_handle.await.unwrap();
        let received: serde_json::Value = serde_json::from_str(received_line.trim()).unwrap();

        // Verify nonce and timestamp were injected.
        assert!(
            received["params"]["nonce"].is_string(),
            "nonce should be injected"
        );
        assert!(
            received["params"]["timestamp"].is_string(),
            "timestamp should be injected"
        );
        assert_eq!(
            received["params"]["key"], "value",
            "original params preserved"
        );
        assert_eq!(result["status"], "ok");

        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn send_propagates_gate_error() {
        let socket_path = temp_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();

        let response = json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid Request"},
            "id": 1
        });

        let _gate_handle = mock_gate(listener, response).await;
        let mut transport = Transport::connect(&socket_path).await.unwrap();

        let result = transport.send("cdp.test", json!({})).await;

        assert!(
            matches!(result, Err(CdpError::GateError { code: -32600, .. })),
            "expected GateError(-32600), got: {result:?}"
        );

        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn send_increments_request_id() {
        let socket_path = temp_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Gate that handles two requests.
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut ids = vec![];
            for expected_id in 1u64..=2 {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                ids.push(req["id"].as_u64().unwrap());
                let resp = json!({
                    "jsonrpc": "2.0",
                    "result": {},
                    "id": expected_id
                });
                write_half
                    .write_all((serde_json::to_string(&resp).unwrap() + "\n").as_bytes())
                    .await
                    .unwrap();
            }
            ids
        });

        let mut transport = Transport::connect(&socket_path).await.unwrap();
        transport.send("cdp.test", json!({})).await.unwrap();
        transport.send("cdp.test", json!({})).await.unwrap();

        let ids = handle.await.unwrap();
        assert_eq!(ids, vec![1, 2], "request IDs should increment");

        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn send_rejects_non_object_params() {
        let socket_path = temp_socket_path();
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Gate that will never receive a request (we expect early error).
        let _gate_handle = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut transport = Transport::connect(&socket_path).await.unwrap();
        let result = transport.send("cdp.test", json!([1, 2, 3])).await;

        assert!(
            matches!(result, Err(CdpError::MalformedResponse(_))),
            "array params should be rejected: {result:?}"
        );

        std::fs::remove_file(&socket_path).ok();
    }
}
