/**
 * Post-registration session — holds the session token and issues lease requests.
 */

import { Lease } from "./lease.js";
import type { UnixSocketTransport } from "./transport.js";
import { CdpError } from "./transport.js";
import type { LeaseRequest, RequestCredentialResult } from "./types.js";

export class Session {
  constructor(
    private readonly transport: UnixSocketTransport,
    public readonly sessionToken: string,
    public readonly agentFingerprint: string,
  ) {}

  /**
   * Request a credential lease from the gate.
   */
  async requestLease(params: LeaseRequest): Promise<Lease> {
    const result = (await this.transport.send("cdp.requestCredential", {
      session_token: this.sessionToken,
      credential_ref: params.credential_ref,
      scope: params.scope,
      reason: params.reason,
    })) as unknown as RequestCredentialResult;

    if (result.status !== "granted") {
      throw new CdpError(`credential request denied: status=${result.status}`);
    }

    const expiresAt = new Date(Date.now() + result.ttl_seconds * 1000);

    return new Lease(
      result.lease_id,
      result.proxy_port,
      result.lease_token,
      result.channel_binding_nonce,
      result.ttl_seconds,
      result.granted_scope,
      expiresAt,
      this.sessionToken,
      this.transport,
    );
  }
}
