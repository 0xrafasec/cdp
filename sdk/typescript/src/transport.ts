/**
 * JSON-RPC 2.0 transport over a Unix domain socket.
 *
 * Framing: each message is a single JSON object followed by '\n'.
 * Nonce (UUID v4) and RFC 3339 timestamp are injected automatically.
 */

import * as net from "node:net";
import { v4 as uuidv4 } from "uuid";
import type { JsonRpcResponse } from "./types.js";

export class CdpError extends Error {
  constructor(
    message: string,
    public readonly code?: number,
  ) {
    super(message);
    this.name = "CdpError";
  }
}

export class UnixSocketTransport {
  private socket: net.Socket | null = null;
  private idCounter = 0;
  private buffer = "";
  private pendingResolvers: Map<
    number,
    {
      resolve: (value: Record<string, unknown>) => void;
      reject: (reason: Error) => void;
    }
  > = new Map();

  constructor(private readonly socketPath: string) {}

  /**
   * Connect to the Unix domain socket at `socketPath`.
   */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ path: this.socketPath });

      sock.on("connect", () => {
        this.socket = sock;
        resolve();
      });

      sock.on("error", (err: Error) => {
        reject(new CdpError(`connection error: ${err.message}`));
      });

      sock.on("data", (chunk: Buffer) => {
        this.buffer += chunk.toString("utf8");
        this.processBuffer();
      });

      sock.on("close", () => {
        // Reject all pending requests.
        for (const { reject: rej } of this.pendingResolvers.values()) {
          rej(new CdpError("socket closed unexpectedly"));
        }
        this.pendingResolvers.clear();
        this.socket = null;
      });
    });
  }

  /**
   * Send a JSON-RPC request and wait for the response result.
   *
   * Automatically injects a UUID v4 `nonce` and RFC 3339 `timestamp`.
   */
  send(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (!this.socket) {
      return Promise.reject(new CdpError("transport not connected"));
    }

    const id = ++this.idCounter;
    const enrichedParams: Record<string, unknown> = {
      ...params,
      nonce: uuidv4(),
      timestamp: new Date().toISOString(),
    };

    const request = {
      jsonrpc: "2.0" as const,
      method,
      params: enrichedParams,
      id,
    };

    return new Promise((resolve, reject) => {
      this.pendingResolvers.set(id, { resolve, reject });

      const line = JSON.stringify(request) + "\n";
      this.socket!.write(line, "utf8", (err) => {
        if (err) {
          this.pendingResolvers.delete(id);
          reject(new CdpError(`write failed: ${err.message}`));
        }
      });
    });
  }

  /** Close the connection. */
  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }

  private processBuffer(): void {
    let newlineIndex: number;
    while ((newlineIndex = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, newlineIndex).trim();
      this.buffer = this.buffer.slice(newlineIndex + 1);

      if (!line) continue;

      let response: JsonRpcResponse;
      try {
        response = JSON.parse(line) as JsonRpcResponse;
      } catch {
        // Malformed response — reject the earliest pending request.
        const firstKey = this.pendingResolvers.keys().next().value;
        if (firstKey !== undefined) {
          const pending = this.pendingResolvers.get(firstKey)!;
          this.pendingResolvers.delete(firstKey);
          pending.reject(new CdpError(`malformed JSON from gate: ${line}`));
        }
        continue;
      }

      const id = response.id as number;
      const pending = this.pendingResolvers.get(id);
      if (!pending) continue;

      this.pendingResolvers.delete(id);

      if (response.error) {
        pending.reject(
          new CdpError(
            `gate error ${response.error.code}: ${response.error.message}`,
            response.error.code,
          ),
        );
      } else if (response.result !== undefined) {
        pending.resolve(response.result);
      } else {
        pending.reject(new CdpError("response missing result field"));
      }
    }
  }
}
