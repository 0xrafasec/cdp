"""
Shared types for the CDP Python SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GateFingerprint:
    """Fingerprint file written by the gate on startup."""

    gate_pid: int
    gate_binary_hash: str
    public_key: str
    socket_path: str
    started_at: str


@dataclass
class Scope:
    """Credential access scope."""

    hosts: list[str]
    methods: list[str]
    paths: list[str]
    ttl_seconds: int | None = None
    max_requests: int | None = None


@dataclass
class GrantedScope:
    """Scope as granted by the gate (may be narrower than requested)."""

    hosts: list[str]
    methods: list[str]
    paths: list[str]
    ttl_seconds: int | None = None
    max_requests: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "GrantedScope":
        return cls(
            hosts=list(data.get("hosts", [])),  # type: ignore[arg-type]
            methods=list(data.get("methods", [])),  # type: ignore[arg-type]
            paths=list(data.get("paths", [])),  # type: ignore[arg-type]
            ttl_seconds=data.get("ttl_seconds"),  # type: ignore[arg-type]
            max_requests=data.get("max_requests"),  # type: ignore[arg-type]
        )


@dataclass
class LeaseInfo:
    """Information about an active lease."""

    lease_id: str
    proxy_port: int
    lease_token: str
    channel_binding_nonce: str
    ttl_seconds: int
    granted_scope: GrantedScope


@dataclass
class FetchResponse:
    """HTTP response returned by Lease.fetch()."""

    status: int
    headers: dict[str, str]
    body: bytes


@dataclass
class LeaseRequest:
    """Parameters for requesting a credential lease."""

    credential_ref: str
    scope: Scope
    reason: str
