"""
Top-level CDP client — gate discovery, connection, and agent registration.
"""

from __future__ import annotations

import json
import os
import pathlib

from .session import Session
from .transport import CdpError, UnixSocketTransport
from .types import GateFingerprint


class CdpClient:
    """Entry point for the CDP Python SDK.

    ``CdpClient`` handles gate discovery, connection, and registration. After
    a successful :meth:`register` call the caller receives a :class:`Session`
    that can be used to request credential leases.
    """

    def __init__(
        self,
        transport: UnixSocketTransport,
        fingerprint: GateFingerprint,
    ) -> None:
        self._transport = transport
        self._fingerprint = fingerprint

    @classmethod
    def discover(cls) -> "CdpClient":
        """Discover the gate automatically and connect to it.

        Reads ``~/.config/cdp/gate.fingerprint`` (or ``CDP_GATE_SOCKET`` env
        var) and connects to the Unix socket.

        :raises CdpError: If the fingerprint file cannot be read or is invalid.
        """
        env_socket = os.environ.get("CDP_GATE_SOCKET")
        if env_socket:
            return cls.connect(env_socket)

        fp_path = cls.default_fingerprint_path()
        try:
            contents = fp_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CdpError(
                f"cannot read fingerprint file {fp_path}: {exc}"
            ) from exc

        try:
            data = json.loads(contents)
        except json.JSONDecodeError as exc:
            raise CdpError(
                f"malformed fingerprint file {fp_path}: {exc}"
            ) from exc

        fingerprint = GateFingerprint(
            gate_pid=int(data["gate_pid"]),
            gate_binary_hash=str(data["gate_binary_hash"]),
            public_key=str(data["public_key"]),
            socket_path=str(data["socket_path"]),
            started_at=str(data["started_at"]),
        )

        transport = UnixSocketTransport(fingerprint.socket_path)
        transport.connect()
        return cls(transport, fingerprint)

    @classmethod
    def connect(cls, socket_path: str) -> "CdpClient":
        """Connect directly to the gate at ``socket_path``.

        Skips automatic gate discovery and identity verification.

        :raises CdpError: If the connection fails.
        """
        fingerprint = GateFingerprint(
            gate_pid=0,
            gate_binary_hash="",
            public_key="",
            socket_path=socket_path,
            started_at="",
        )
        transport = UnixSocketTransport(socket_path)
        transport.connect()
        return cls(transport, fingerprint)

    def register(
        self,
        agent_id: str,
        agent_version: str,
        capabilities: list[str] | None = None,
    ) -> Session:
        """Register the calling agent with the gate.

        :param agent_id: Stable, human-readable identifier for this agent.
        :param agent_version: Semver string for the agent binary.
        :param capabilities: List of capability strings the agent intends to use.
        :returns: An authenticated :class:`Session`.
        :raises CdpError: On gate communication errors or rejection.
        """
        params: dict[str, object] = {
            "agent_id": agent_id,
            "agent_version": agent_version,
            "capabilities": capabilities or [],
        }

        result = self._transport.send("cdp.register", params)

        if result.get("status") != "registered":
            raise CdpError(f"unexpected register status: {result.get('status')}")

        return Session(
            transport=self._transport,
            session_token=str(result["session_token"]),
            agent_fingerprint=str(result["agent_fingerprint"]),
        )

    @property
    def fingerprint(self) -> GateFingerprint:
        """Return the fingerprint of the connected gate."""
        return self._fingerprint

    @staticmethod
    def default_fingerprint_path() -> pathlib.Path:
        """Return the default path to the gate fingerprint file."""
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            return pathlib.Path(xdg) / "cdp" / "gate.fingerprint"
        return pathlib.Path.home() / ".config" / "cdp" / "gate.fingerprint"
