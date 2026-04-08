/**
 * CDP Protocol shared types.
 */

/** Gate fingerprint file written by the gate on startup. */
export interface GateFingerprint {
  gate_pid: number;
  gate_binary_hash: string;
  public_key: string;
  socket_path: string;
  started_at: string;
}

/** JSON-RPC 2.0 request envelope. */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  method: string;
  params: Record<string, unknown>;
  id: number;
}

/** JSON-RPC 2.0 response envelope. */
export interface JsonRpcResponse {
  jsonrpc: "2.0";
  result?: Record<string, unknown>;
  error?: JsonRpcError;
  id: number | null;
}

/** JSON-RPC 2.0 error object. */
export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

/** Parameters for cdp.register. */
export interface RegisterParams {
  agent_id: string;
  agent_version: string;
  capabilities: string[];
  attestation?: Record<string, unknown>;
  nonce: string;
  timestamp: string;
}

/** Result of cdp.register. */
export interface RegisterResult {
  status: "registered";
  agent_fingerprint: string;
  session_token: string;
  capabilities_granted: string[];
}

/** Requested or granted credential access scope. */
export interface LeaseScope {
  hosts: string[];
  methods: string[];
  paths: string[];
  ttl_seconds?: number;
  max_requests?: number;
}

/** Scope as granted by the gate. */
export interface GrantedScope extends LeaseScope {}

/** Parameters for cdp.requestCredential. */
export interface RequestCredentialParams {
  session_token: string;
  credential_ref: string;
  scope: LeaseScope;
  reason: string;
  nonce: string;
  timestamp: string;
}

/** Result of cdp.requestCredential. */
export interface RequestCredentialResult {
  status: "granted";
  lease_id: string;
  proxy_port: number;
  lease_token: string;
  channel_binding_nonce: string;
  ttl_seconds: number;
  granted_scope: GrantedScope;
}

/** Parameters for cdp.renewLease. */
export interface RenewLeaseParams {
  session_token: string;
  lease_id: string;
  extend_seconds: number;
  nonce: string;
  timestamp: string;
}

/** Result of cdp.renewLease. */
export interface RenewLeaseResult {
  status: "renewed";
  new_expires_at: string;
  renewals_remaining: number;
}

/** Result of cdp.revokeLease. */
export interface RevokeLeasResult {
  status: "revoked";
}

/** Options for Lease.fetch(). */
export interface FetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
}

/** HTTP response returned by Lease.fetch(). */
export interface FetchResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

/** Parameters for requesting a lease. */
export interface LeaseRequest {
  credential_ref: string;
  scope: LeaseScope;
  reason: string;
}

/** Renewal information returned by Lease.renew(). */
export interface RenewalInfo {
  status: string;
  new_expires_at: string;
  renewals_remaining: number;
}
