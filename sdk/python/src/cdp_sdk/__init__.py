"""
CDP Python SDK — gate discovery, registration, lease management, and
authenticated HTTP proxy access.
"""

from .client import CdpClient
from .lease import Lease
from .session import Session
from .transport import CdpError
from .types import FetchResponse, GrantedScope, GateFingerprint, LeaseRequest, Scope

__all__ = [
    "CdpClient",
    "CdpError",
    "FetchResponse",
    "GateFingerprint",
    "GrantedScope",
    "Lease",
    "LeaseRequest",
    "Scope",
    "Session",
]
