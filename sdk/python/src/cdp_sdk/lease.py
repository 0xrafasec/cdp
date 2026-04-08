"""
Active credential lease — proxy-authenticated HTTP and lease lifecycle.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .transport import CdpError, UnixSocketTransport
from .types import FetchResponse, GrantedScope

if TYPE_CHECKING:
    pass


class Lease:
    """An active credential lease.

    Use :meth:`fetch` to make authenticated HTTP requests through the CDP
    proxy, :meth:`renew` to extend the lease, or :meth:`revoke` to
    terminate it early.
    """

    def __init__(
        self,
        lease_id: str,
        proxy_port: int,
        lease_token: str,
        channel_binding_nonce: str,
        ttl_seconds: int,
        granted_scope: GrantedScope,
        expires_at: datetime,
        session_token: str,
        transport: UnixSocketTransport,
    ) -> None:
        self._lease_id = lease_id
        self._proxy_port = proxy_port
        self._lease_token = lease_token
        self._channel_binding_nonce = channel_binding_nonce
        self._ttl_seconds = ttl_seconds
        self._granted_scope = granted_scope
        self._expires_at = expires_at
        self._session_token = session_token
        self._transport = transport

    # ── Accessors ─────────────────────────────────────────────────────────────

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def proxy_port(self) -> int:
        return self._proxy_port

    @property
    def lease_token(self) -> str:
        return self._lease_token

    @property
    def channel_binding_nonce(self) -> str:
        return self._channel_binding_nonce

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @property
    def granted_scope(self) -> GrantedScope:
        return self._granted_scope

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def is_expired(self) -> bool:
        """Returns True if the lease has passed its expiry time."""
        return datetime.now(timezone.utc) >= self._expires_at

    # ── HTTP proxy ────────────────────────────────────────────────────────────

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> FetchResponse:
        """Make an HTTP request through the CDP proxy with auth headers injected.

        The proxy listens at ``127.0.0.1:<proxy_port>``. CDP authentication
        headers are injected automatically.

        :raises CdpError: If the lease has expired or the request fails.
        """
        if self.is_expired:
            raise CdpError("lease has expired")

        # Build the proxy URL, routing to 127.0.0.1:<proxy_port>.
        # Parse the original URL to extract the path.
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise CdpError(f"invalid URL: {url}")

        proxy_url = f"http://127.0.0.1:{self._proxy_port}{parsed.path}"
        if parsed.query:
            proxy_url += f"?{parsed.query}"

        request_headers: dict[str, str] = {
            **(headers or {}),
            "Host": parsed.netloc,
            "X-CDP-Lease-Token": self._lease_token,
            "X-CDP-Channel-Binding": self._channel_binding_nonce,
            "X-CDP-Original-URL": url,
        }

        req = urllib.request.Request(
            proxy_url,
            data=body,
            headers=request_headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req) as resp:
                response_body = resp.read()
                response_headers: dict[str, str] = {
                    k.lower(): v for k, v in resp.headers.items()
                }
                return FetchResponse(
                    status=resp.status,
                    headers=response_headers,
                    body=response_body,
                )
        except urllib.error.HTTPError as exc:
            # HTTPError is also a valid response with a status code.
            body_bytes = exc.read()
            response_headers = {k.lower(): v for k, v in exc.headers.items()}
            return FetchResponse(
                status=exc.code,
                headers=response_headers,
                body=body_bytes,
            )
        except urllib.error.URLError as exc:
            raise CdpError(f"proxy request failed: {exc.reason}") from exc

    # ── Lease lifecycle ───────────────────────────────────────────────────────

    def renew(self, extend_seconds: int) -> dict[str, object]:
        """Renew the lease, extending it by ``extend_seconds`` seconds.

        :raises CdpError: On gate communication errors.
        """
        result = self._transport.send(
            "cdp.renewLease",
            {
                "session_token": self._session_token,
                "lease_id": self._lease_id,
                "extend_seconds": extend_seconds,
            },
        )
        # Update local expiry.
        new_expiry_str = result.get("new_expires_at")
        if isinstance(new_expiry_str, str):
            try:
                self._expires_at = datetime.fromisoformat(new_expiry_str)
            except ValueError:
                from datetime import timedelta

                self._expires_at = datetime.now(timezone.utc) + timedelta(
                    seconds=extend_seconds
                )
        return result

    def revoke(self, reason: str) -> None:
        """Revoke the lease immediately.

        :raises CdpError: On gate communication errors or unexpected response.
        """
        result = self._transport.send(
            "cdp.revokeLease",
            {
                "session_token": self._session_token,
                "lease_id": self._lease_id,
                "reason": reason,
            },
        )
        if result.get("status") != "revoked":
            raise CdpError(f"unexpected revoke status: {result}")
