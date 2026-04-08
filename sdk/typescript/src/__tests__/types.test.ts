/**
 * Tests for type serialization / deserialization.
 */

import type {
  GateFingerprint,
  JsonRpcRequest,
  JsonRpcResponse,
  LeaseScope,
  RegisterResult,
  RequestCredentialResult,
} from "../types";

describe("GateFingerprint", () => {
  it("round-trips through JSON correctly", () => {
    const fp: GateFingerprint = {
      gate_pid: 12345,
      gate_binary_hash: "abc123",
      public_key: "pubkey-base64",
      socket_path: "/run/cdp/gate.sock",
      started_at: "2026-01-01T00:00:00Z",
    };
    const json = JSON.stringify(fp);
    const parsed = JSON.parse(json) as GateFingerprint;
    expect(parsed).toEqual(fp);
  });
});

describe("JsonRpcRequest", () => {
  it("serializes with required fields", () => {
    const req: JsonRpcRequest = {
      jsonrpc: "2.0",
      method: "cdp.register",
      params: { agent_id: "test", nonce: "n", timestamp: "t" },
      id: 1,
    };
    const json = JSON.stringify(req);
    const parsed = JSON.parse(json) as JsonRpcRequest;
    expect(parsed.jsonrpc).toBe("2.0");
    expect(parsed.method).toBe("cdp.register");
    expect(parsed.id).toBe(1);
  });
});

describe("JsonRpcResponse", () => {
  it("deserializes a success response", () => {
    const raw = JSON.stringify({
      jsonrpc: "2.0",
      result: { status: "registered", session_token: "tok", agent_fingerprint: "fp", capabilities_granted: [] },
      id: 1,
    });
    const resp = JSON.parse(raw) as JsonRpcResponse;
    expect(resp.result?.["status"]).toBe("registered");
    expect(resp.error).toBeUndefined();
  });

  it("deserializes an error response", () => {
    const raw = JSON.stringify({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Invalid Request" },
      id: 1,
    });
    const resp = JSON.parse(raw) as JsonRpcResponse;
    expect(resp.error?.code).toBe(-32600);
    expect(resp.error?.message).toBe("Invalid Request");
    expect(resp.result).toBeUndefined();
  });
});

describe("LeaseScope", () => {
  it("allows optional fields", () => {
    const scope: LeaseScope = {
      hosts: ["api.example.com"],
      methods: ["GET"],
      paths: ["/v1/*"],
    };
    expect(scope.ttl_seconds).toBeUndefined();
    expect(scope.max_requests).toBeUndefined();
  });

  it("serializes optional fields when present", () => {
    const scope: LeaseScope = {
      hosts: ["api.example.com"],
      methods: ["GET", "POST"],
      paths: ["/v1/*"],
      ttl_seconds: 300,
      max_requests: 100,
    };
    const json = JSON.stringify(scope);
    const parsed = JSON.parse(json) as LeaseScope;
    expect(parsed.ttl_seconds).toBe(300);
    expect(parsed.max_requests).toBe(100);
  });
});

describe("RegisterResult", () => {
  it("deserializes correctly", () => {
    const raw: RegisterResult = {
      status: "registered",
      agent_fingerprint: "fp-abc",
      session_token: "sess-tok",
      capabilities_granted: ["api:read"],
    };
    expect(raw.status).toBe("registered");
    expect(raw.capabilities_granted).toHaveLength(1);
  });
});

describe("RequestCredentialResult", () => {
  it("deserializes a full grant response", () => {
    const raw: RequestCredentialResult = {
      status: "granted",
      lease_id: "lease-abc",
      proxy_port: 9999,
      lease_token: "lt-tok",
      channel_binding_nonce: "nonce",
      ttl_seconds: 300,
      granted_scope: {
        hosts: ["api.example.com"],
        methods: ["GET"],
        paths: ["/v1/*"],
        ttl_seconds: 300,
      },
    };
    expect(raw.lease_id).toBe("lease-abc");
    expect(raw.proxy_port).toBe(9999);
    expect(raw.granted_scope.hosts).toContain("api.example.com");
  });
});
