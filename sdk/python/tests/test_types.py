"""Tests for CDP SDK type construction and serialization."""

import json
import dataclasses

from cdp_sdk.types import (
    FetchResponse,
    GateFingerprint,
    GrantedScope,
    LeaseRequest,
    Scope,
)


class TestGateFingerprint:
    def test_construction(self) -> None:
        fp = GateFingerprint(
            gate_pid=12345,
            gate_binary_hash="abc123",
            public_key="pubkey-b64",
            socket_path="/run/cdp/gate.sock",
            started_at="2026-01-01T00:00:00Z",
        )
        assert fp.gate_pid == 12345
        assert fp.gate_binary_hash == "abc123"
        assert fp.public_key == "pubkey-b64"
        assert fp.socket_path == "/run/cdp/gate.sock"
        assert fp.started_at == "2026-01-01T00:00:00Z"

    def test_is_dataclass(self) -> None:
        assert dataclasses.is_dataclass(GateFingerprint)

    def test_json_roundtrip(self) -> None:
        fp = GateFingerprint(
            gate_pid=99,
            gate_binary_hash="hash",
            public_key="pk",
            socket_path="/tmp/gate.sock",
            started_at="2026-04-07T00:00:00+00:00",
        )
        data = dataclasses.asdict(fp)
        serialized = json.dumps(data)
        parsed = json.loads(serialized)
        restored = GateFingerprint(**parsed)
        assert restored == fp


class TestScope:
    def test_construction_with_required_fields(self) -> None:
        scope = Scope(
            hosts=["api.example.com"],
            methods=["GET", "POST"],
            paths=["/v1/*"],
        )
        assert scope.hosts == ["api.example.com"]
        assert scope.methods == ["GET", "POST"]
        assert scope.paths == ["/v1/*"]
        assert scope.ttl_seconds is None
        assert scope.max_requests is None

    def test_construction_with_optional_fields(self) -> None:
        scope = Scope(
            hosts=["api.example.com"],
            methods=["GET"],
            paths=["/"],
            ttl_seconds=300,
            max_requests=100,
        )
        assert scope.ttl_seconds == 300
        assert scope.max_requests == 100

    def test_serialization(self) -> None:
        scope = Scope(hosts=["h"], methods=["GET"], paths=["/"], ttl_seconds=60)
        d = dataclasses.asdict(scope)
        assert d["ttl_seconds"] == 60
        assert d["max_requests"] is None


class TestGrantedScope:
    def test_from_dict(self) -> None:
        data = {
            "hosts": ["api.example.com"],
            "methods": ["GET"],
            "paths": ["/v1/*"],
            "ttl_seconds": 300,
        }
        gs = GrantedScope.from_dict(data)
        assert gs.hosts == ["api.example.com"]
        assert gs.ttl_seconds == 300
        assert gs.max_requests is None

    def test_from_dict_empty(self) -> None:
        gs = GrantedScope.from_dict({})
        assert gs.hosts == []
        assert gs.methods == []
        assert gs.paths == []


class TestLeaseRequest:
    def test_construction(self) -> None:
        scope = Scope(hosts=["h"], methods=["GET"], paths=["/"])
        req = LeaseRequest(
            credential_ref="my-cred",
            scope=scope,
            reason="testing",
        )
        assert req.credential_ref == "my-cred"
        assert req.reason == "testing"
        assert req.scope.hosts == ["h"]


class TestFetchResponse:
    def test_construction(self) -> None:
        resp = FetchResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=b'{"ok": true}',
        )
        assert resp.status == 200
        assert resp.headers["content-type"] == "application/json"
        assert resp.body == b'{"ok": true}'
