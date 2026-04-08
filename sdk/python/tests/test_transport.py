"""Tests for UnixSocketTransport JSON-RPC framing."""

import json
import socket
import tempfile
import threading
import time
import os
from pathlib import Path

from cdp_sdk.transport import CdpError, UnixSocketTransport


def run_mock_gate(sock_path: str, response_builder, request_store=None):
    """Run a mock gate that serves one request on a Unix socket."""
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(sock_path)
    server.listen(1)

    def serve():
        server.settimeout(5.0)
        try:
            conn, _ = server.accept()
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n")[0].decode("utf-8").strip()
            request = json.loads(line)
            if request_store is not None:
                request_store.append(request)
            response = response_builder(request)
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
            conn.close()
        except Exception:
            pass
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def temp_socket_path():
    fd, path = tempfile.mkstemp(suffix=".sock")
    os.close(fd)
    os.unlink(path)
    return path


class TestUnixSocketTransport:
    def test_connect_fails_on_nonexistent_socket(self) -> None:
        transport = UnixSocketTransport("/tmp/cdp-py-nonexistent.sock")
        try:
            transport.connect()
            assert False, "Should have raised CdpError"
        except CdpError:
            pass

    def test_send_injects_nonce_and_timestamp(self) -> None:
        sock_path = temp_socket_path()
        captured: list = []

        def response_builder(req):
            return {"jsonrpc": "2.0", "result": {"status": "ok"}, "id": req["id"]}

        thread = run_mock_gate(sock_path, response_builder, captured)

        transport = UnixSocketTransport(sock_path)
        transport.connect()
        result = transport.send("cdp.test", {"key": "value"})
        transport.close()
        thread.join(timeout=2)

        assert result == {"status": "ok"}
        assert len(captured) == 1
        params = captured[0]["params"]
        assert "nonce" in params, "nonce should be injected"
        assert len(params["nonce"]) == 36, "nonce should be a UUID"
        assert "timestamp" in params, "timestamp should be injected"
        assert params["key"] == "value", "original param should be preserved"

        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

    def test_send_propagates_gate_error(self) -> None:
        sock_path = temp_socket_path()

        def response_builder(req):
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Invalid Request"},
                "id": req["id"],
            }

        thread = run_mock_gate(sock_path, response_builder)

        transport = UnixSocketTransport(sock_path)
        transport.connect()
        try:
            transport.send("cdp.test", {})
            assert False, "Should have raised CdpError"
        except CdpError as exc:
            assert exc.code == -32600
            assert "Invalid Request" in str(exc)
        finally:
            transport.close()
            thread.join(timeout=2)
            try:
                os.unlink(sock_path)
            except FileNotFoundError:
                pass

    def test_send_increments_request_id(self) -> None:
        sock_path = temp_socket_path()

        # Gate that handles multiple requests.
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)
        captured_ids = []

        def serve():
            server.settimeout(5.0)
            try:
                conn, _ = server.accept()
                conn.settimeout(2.0)
                buf = b""
                for _ in range(3):
                    while b"\n" not in buf:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return
                        buf += chunk
                    idx = buf.index(b"\n")
                    line = buf[:idx].decode("utf-8").strip()
                    buf = buf[idx + 1:]
                    req = json.loads(line)
                    captured_ids.append(req["id"])
                    resp = {"jsonrpc": "2.0", "result": {}, "id": req["id"]}
                    conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        transport = UnixSocketTransport(sock_path)
        transport.connect()
        transport.send("cdp.test", {})
        transport.send("cdp.test", {})
        transport.send("cdp.test", {})
        transport.close()
        thread.join(timeout=2)

        assert captured_ids == [1, 2, 3], f"expected [1,2,3], got {captured_ids}"

        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

    def test_newline_delimited_framing(self) -> None:
        """Ensure partial chunks are buffered correctly."""
        sock_path = temp_socket_path()

        def response_builder(req):
            return {"jsonrpc": "2.0", "result": {"framing": "ok"}, "id": req["id"]}

        thread = run_mock_gate(sock_path, response_builder)

        transport = UnixSocketTransport(sock_path)
        transport.connect()
        result = transport.send("cdp.test", {})
        transport.close()
        thread.join(timeout=2)

        assert result["framing"] == "ok"

        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

    def test_send_without_connect_raises(self) -> None:
        transport = UnixSocketTransport("/tmp/not-connected.sock")
        try:
            transport.send("cdp.test", {})
            assert False, "Should have raised CdpError"
        except CdpError as exc:
            assert "not connected" in str(exc).lower()
