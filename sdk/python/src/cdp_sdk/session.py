"""
Post-registration session — holds the session token and issues lease requests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .lease import Lease
from .transport import CdpError, UnixSocketTransport
from .types import GrantedScope, LeaseRequest, Scope


class Session:
    """An authenticated session with the CDP gate.

    Obtained by calling :meth:`CdpClient.register`.
    Use :meth:`request_lease` to obtain credential leases.
    """

    def __init__(
        self,
        transport: UnixSocketTransport,
        session_token: str,
        agent_fingerprint: str,
    ) -> None:
        self._transport = transport
        self._session_token = session_token
        self._agent_fingerprint = agent_fingerprint

    @property
    def session_token(self) -> str:
        return self._session_token

    @property
    def agent_fingerprint(self) -> str:
        return self._agent_fingerprint

    def request_lease(
        self,
        credential_ref: str,
        scope: Scope,
        reason: str,
    ) -> Lease:
        """Request a credential lease from the gate.

        :param credential_ref: Opaque reference to the credential in the vault.
        :param scope: Requested access scope.
        :param reason: Human-readable justification shown in approval prompts.
        :returns: An active :class:`Lease`.
        :raises CdpError: If the gate denies or returns an error.
        """
        scope_dict: dict[str, object] = {
            "hosts": scope.hosts,
            "methods": scope.methods,
            "paths": scope.paths,
        }
        if scope.ttl_seconds is not None:
            scope_dict["ttl_seconds"] = scope.ttl_seconds
        if scope.max_requests is not None:
            scope_dict["max_requests"] = scope.max_requests

        result = self._transport.send(
            "cdp.requestCredential",
            {
                "session_token": self._session_token,
                "credential_ref": credential_ref,
                "scope": scope_dict,
                "reason": reason,
            },
        )

        if result.get("status") != "granted":
            raise CdpError(f"credential request denied: status={result.get('status')}")

        ttl_seconds = int(result["ttl_seconds"])  # type: ignore[arg-type]
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        granted_scope_raw = result.get("granted_scope", {})
        granted_scope = GrantedScope.from_dict(
            granted_scope_raw if isinstance(granted_scope_raw, dict) else {}
        )

        return Lease(
            lease_id=str(result["lease_id"]),
            proxy_port=int(result["proxy_port"]),  # type: ignore[arg-type]
            lease_token=str(result["lease_token"]),
            channel_binding_nonce=str(result["channel_binding_nonce"]),
            ttl_seconds=ttl_seconds,
            granted_scope=granted_scope,
            expires_at=expires_at,
            session_token=self._session_token,
            transport=self._transport,
        )
