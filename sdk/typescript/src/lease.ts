/**
 * Active credential lease — proxy-authenticated HTTP and lease lifecycle.
 */

import * as http from "node:http";
import type { UnixSocketTransport } from "./transport.js";
import type { FetchOptions, FetchResponse, GrantedScope, RenewalInfo } from "./types.js";
import { CdpError } from "./transport.js";

export class Lease {
  private readonly _expiresAt: Date;

  constructor(
    public readonly leaseId: string,
    public readonly proxyPort: number,
    public readonly leaseToken: string,
    public readonly channelBindingNonce: string,
    public readonly ttlSeconds: number,
    public readonly grantedScope: GrantedScope,
    expiresAt: Date,
    private readonly sessionToken: string,
    private readonly transport: UnixSocketTransport,
  ) {
    this._expiresAt = expiresAt;
  }

  /** Returns true if the lease has passed its expiry time. */
  get isExpired(): boolean {
    return Date.now() >= this._expiresAt.getTime();
  }

  /** UTC expiry time. */
  get expiresAt(): Date {
    return this._expiresAt;
  }

  /**
   * Make an HTTP request through the CDP proxy with auth headers injected.
   *
   * The proxy listens at 127.0.0.1:<proxyPort>. CDP authentication headers
   * (X-CDP-Lease-Token and X-CDP-Channel-Binding) are injected automatically.
   */
  fetch(url: string, options: FetchOptions = {}): Promise<FetchResponse> {
    if (this.isExpired) {
      return Promise.reject(new CdpError("lease has expired"));
    }

    return new Promise((resolve, reject) => {
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(url);
      } catch {
        reject(new CdpError(`invalid URL: ${url}`));
        return;
      }

      const method = options.method ?? "GET";
      const extraHeaders: Record<string, string> = options.headers ?? {};
      const body =
        options.body !== undefined
          ? typeof options.body === "string"
            ? Buffer.from(options.body, "utf8")
            : options.body
          : undefined;

      // Build request headers, injecting CDP auth headers.
      const requestHeaders: http.OutgoingHttpHeaders = {
        ...extraHeaders,
        host: parsedUrl.host,
        "x-cdp-lease-token": this.leaseToken,
        "x-cdp-channel-binding": this.channelBindingNonce,
        "x-cdp-original-url": url,
      };

      if (body !== undefined) {
        requestHeaders["content-length"] = String(body.length);
      }

      // Route through the CDP proxy at 127.0.0.1:<proxyPort>.
      // The proxy reads the Host header and X-CDP-* auth headers.
      const reqOptions: http.RequestOptions = {
        host: "127.0.0.1",
        port: this.proxyPort,
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: requestHeaders,
      };

      const req = http.request(reqOptions, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const responseBody = Buffer.concat(chunks);
          const responseHeaders: Record<string, string> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (value !== undefined) {
              responseHeaders[key] = Array.isArray(value) ? value.join(", ") : value;
            }
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: responseHeaders,
            body: responseBody,
          });
        });
        res.on("error", (err: Error) => {
          reject(new CdpError(`response error: ${err.message}`));
        });
      });

      req.on("error", (err: Error) => {
        reject(new CdpError(`request error: ${err.message}`));
      });

      if (body !== undefined) {
        req.write(body);
      }
      req.end();
    });
  }

  /**
   * Renew the lease, extending it by `extendSeconds` seconds.
   */
  async renew(extendSeconds: number): Promise<RenewalInfo> {
    const result = await this.transport.send("cdp.renewLease", {
      session_token: this.sessionToken,
      lease_id: this.leaseId,
      extend_seconds: extendSeconds,
    });
    return result as unknown as RenewalInfo;
  }

  /**
   * Revoke the lease immediately.
   */
  async revoke(reason: string): Promise<void> {
    const result = await this.transport.send("cdp.revokeLease", {
      session_token: this.sessionToken,
      lease_id: this.leaseId,
      reason,
    });
    if ((result as { status?: string }).status !== "revoked") {
      throw new CdpError(`unexpected revoke status: ${JSON.stringify(result)}`);
    }
  }
}
