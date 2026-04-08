"""
JSON-RPC 2.0 transport over a Unix domain socket.

Framing: each message is a single JSON object followed by '\\n'.
Nonce (UUID v4) and RFC 3339 timestamp are injected automatically.
"""

from __future__ import annotations

import json
import socket
import uuid
from datetime import datetime, timezone


class CdpError(Exception):
    """Raised when the CDP gate returns an error or communication fails."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class UnixSocketTransport:
    """Synchronous JSON-RPC transport over a Unix domain socket."""

    def __init__(self, socket_path: str) -> None:
        self._socket_path = socket_path
        self._sock: socket.socket | None = None
        self._id_counter = 0
        self._recv_buffer = b""

    def connect(self) -> None:
        """Connect to the Unix domain socket at `socket_path`."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self._socket_path)
        except OSError as exc:
            raise CdpError(f"connection failed: {exc}") from exc
        self._sock = sock

    def send(self, method: str, params: dict[str, object]) -> dict[str, object]:
        """Send a JSON-RPC request and return the result.

        Automatically injects a UUID v4 ``nonce`` and RFC 3339 ``timestamp``.
        Raises :class:`CdpError` on transport errors or gate-reported errors.
        """
        if self._sock is None:
            raise CdpError("transport not connected — call connect() first")

        self._id_counter += 1
        request_id = self._id_counter

        enriched_params: dict[str, object] = {
            **params,
            "nonce": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": enriched_params,
            "id": request_id,
        }

        line = json.dumps(request) + "\n"
        try:
            self._sock.sendall(line.encode("utf-8"))
        except OSError as exc:
            raise CdpError(f"send failed: {exc}") from exc

        response = self._read_line()
        parsed: dict[str, object] = json.loads(response)

        if "error" in parsed and parsed["error"] is not None:
            err = parsed["error"]
            if isinstance(err, dict):
                code = err.get("code")
                message = err.get("message", "unknown error")
                raise CdpError(
                    f"gate error {code}: {message}",
                    code=int(code) if code is not None else None,
                )
            raise CdpError(f"gate error: {err}")

        if "result" not in parsed or parsed["result"] is None:
            raise CdpError("response missing 'result' field")

        result = parsed["result"]
        if not isinstance(result, dict):
            raise CdpError(f"unexpected result type: {type(result)}")

        return result  # type: ignore[return-value]

    def close(self) -> None:
        """Close the connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _read_line(self) -> str:
        """Read a newline-terminated JSON line from the socket."""
        while b"\n" not in self._recv_buffer:
            try:
                chunk = self._sock.recv(4096)  # type: ignore[union-attr]
            except OSError as exc:
                raise CdpError(f"recv failed: {exc}") from exc
            if not chunk:
                raise CdpError("gate closed the connection unexpectedly")
            self._recv_buffer += chunk

        idx = self._recv_buffer.index(b"\n")
        line = self._recv_buffer[:idx].decode("utf-8").strip()
        self._recv_buffer = self._recv_buffer[idx + 1 :]
        return line
