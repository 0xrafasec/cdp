/**
 * Tests for JSON-RPC framing in UnixSocketTransport.
 */

import * as net from "node:net";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { UnixSocketTransport, CdpError } from "../transport";

function tempSocketPath(): string {
  return path.join(os.tmpdir(), `cdp-ts-test-${Math.random().toString(36).slice(2)}.sock`);
}

/**
 * Helper: create a mock gate server that handles one request and sends a response.
 */
function createMockGate(
  socketPath: string,
  responseBuilder: (request: unknown) => unknown,
): net.Server {
  const server = net.createServer((conn) => {
    let buffer = "";
    conn.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex === -1) return;

      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);

      const request = JSON.parse(line);
      const response = responseBuilder(request);
      conn.write(JSON.stringify(response) + "\n");
    });
  });
  server.listen(socketPath);
  return server;
}

describe("UnixSocketTransport", () => {
  it("connects to a Unix socket", async () => {
    const socketPath = tempSocketPath();
    const server = net.createServer().listen(socketPath);

    const transport = new UnixSocketTransport(socketPath);
    await transport.connect();
    transport.close();
    server.close();
    fs.rmSync(socketPath, { force: true });
  });

  it("fails to connect to a non-existent socket", async () => {
    const transport = new UnixSocketTransport("/tmp/cdp-nonexistent.sock");
    await expect(transport.connect()).rejects.toThrow(CdpError);
  });

  it("injects nonce and timestamp into params", async () => {
    const socketPath = tempSocketPath();
    let capturedRequest: Record<string, unknown> | null = null;

    const server = createMockGate(socketPath, (req) => {
      capturedRequest = req as Record<string, unknown>;
      return {
        jsonrpc: "2.0",
        result: { status: "ok" },
        id: (req as { id: number }).id,
      };
    });

    const transport = new UnixSocketTransport(socketPath);
    await transport.connect();
    await transport.send("cdp.test", { key: "value" });
    transport.close();
    server.close();
    fs.rmSync(socketPath, { force: true });

    expect(capturedRequest).not.toBeNull();
    const params = (capturedRequest as unknown as { params: Record<string, unknown> }).params;
    expect(typeof params["nonce"]).toBe("string");
    expect(params["nonce"]).toHaveLength(36); // UUID v4
    expect(typeof params["timestamp"]).toBe("string");
    expect(params["key"]).toBe("value"); // original param preserved
  });

  it("propagates gate error responses", async () => {
    const socketPath = tempSocketPath();
    const server = createMockGate(socketPath, (req) => ({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Invalid Request" },
      id: (req as { id: number }).id,
    }));

    const transport = new UnixSocketTransport(socketPath);
    await transport.connect();

    await expect(transport.send("cdp.test", {})).rejects.toThrow(CdpError);
    await expect(transport.send("cdp.test", {})).rejects.toMatchObject({
      code: -32600,
    });

    transport.close();
    server.close();
    fs.rmSync(socketPath, { force: true });
  });

  it("increments request IDs", async () => {
    const socketPath = tempSocketPath();
    const capturedIds: number[] = [];

    const server = net.createServer((conn) => {
      let buffer = "";
      conn.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        let newlineIndex: number;
        while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
          const line = buffer.slice(0, newlineIndex).trim();
          buffer = buffer.slice(newlineIndex + 1);
          const req = JSON.parse(line) as { id: number };
          capturedIds.push(req.id);
          conn.write(
            JSON.stringify({ jsonrpc: "2.0", result: {}, id: req.id }) + "\n",
          );
        }
      });
    });
    server.listen(socketPath);

    const transport = new UnixSocketTransport(socketPath);
    await transport.connect();
    await transport.send("cdp.test", {});
    await transport.send("cdp.test", {});
    await transport.send("cdp.test", {});
    transport.close();
    server.close();
    fs.rmSync(socketPath, { force: true });

    expect(capturedIds).toEqual([1, 2, 3]);
  });

  it("handles newline-delimited framing correctly", async () => {
    const socketPath = tempSocketPath();

    // Server that sends the response in two chunks.
    const server = net.createServer((conn) => {
      let buffer = "";
      conn.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        if (buffer.includes("\n")) {
          const req = JSON.parse(buffer.trim()) as { id: number };
          const resp = JSON.stringify({ jsonrpc: "2.0", result: { ok: true }, id: req.id });
          // Send in two chunks to test buffering.
          conn.write(resp.slice(0, 5));
          conn.write(resp.slice(5) + "\n");
          buffer = "";
        }
      });
    });
    server.listen(socketPath);

    const transport = new UnixSocketTransport(socketPath);
    await transport.connect();
    const result = await transport.send("cdp.test", {});
    transport.close();
    server.close();
    fs.rmSync(socketPath, { force: true });

    expect(result["ok"]).toBe(true);
  });
});
