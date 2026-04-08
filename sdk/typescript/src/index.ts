/**
 * @cdp-protocol/sdk — TypeScript SDK for the Credential Delegation Protocol.
 *
 * @example
 * ```typescript
 * import { CdpClient } from '@cdp-protocol/sdk';
 *
 * const client = await CdpClient.discover();
 * const session = await client.register('my-agent', '0.1.0', ['api:read']);
 * const lease = await session.requestLease({
 *   credential_ref: 'acme-api-key',
 *   scope: { hosts: ['api.acme.com'], methods: ['GET'], paths: ['/v1/*'] },
 *   reason: 'Fetching data',
 * });
 * const response = await lease.fetch('https://api.acme.com/v1/data');
 * console.log(response.status);
 * ```
 */

export { CdpClient } from "./client.js";
export { Session } from "./session.js";
export { Lease } from "./lease.js";
export { CdpError, UnixSocketTransport } from "./transport.js";
export type {
  FetchOptions,
  FetchResponse,
  GateFingerprint,
  GrantedScope,
  JsonRpcError,
  JsonRpcRequest,
  JsonRpcResponse,
  LeaseRequest,
  LeaseScope,
  RegisterParams,
  RegisterResult,
  RenewalInfo,
  RenewLeaseParams,
  RenewLeaseResult,
  RequestCredentialParams,
  RequestCredentialResult,
  RevokeLeasResult,
} from "./types.js";
