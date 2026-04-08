/**
 * Top-level CDP client — gate discovery, connection, and registration.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Session } from "./session.js";
import { CdpError, UnixSocketTransport } from "./transport.js";
import type { GateFingerprint, RegisterResult } from "./types.js";

export class CdpClient {
  private constructor(
    private readonly transport: UnixSocketTransport,
    public readonly fingerprint: GateFingerprint,
  ) {}

  /**
   * Discover the gate automatically and connect to it.
   *
   * Reads `~/.config/cdp/gate.fingerprint` (or `CDP_GATE_SOCKET` env var),
   * then connects to the Unix socket.
   */
  static async discover(): Promise<CdpClient> {
    // Allow socket path override via environment variable.
    const envSocket = process.env["CDP_GATE_SOCKET"];
    if (envSocket) {
      return CdpClient.connect(envSocket);
    }

    const fingerprintPath = CdpClient.defaultFingerprintPath();
    let contents: string;
    try {
      contents = fs.readFileSync(fingerprintPath, "utf8");
    } catch (err) {
      throw new CdpError(
        `cannot read fingerprint file ${fingerprintPath}: ${(err as Error).message}`,
      );
    }

    let fingerprint: GateFingerprint;
    try {
      fingerprint = JSON.parse(contents) as GateFingerprint;
    } catch (err) {
      throw new CdpError(
        `malformed fingerprint file ${fingerprintPath}: ${(err as Error).message}`,
      );
    }

    const transport = new UnixSocketTransport(fingerprint.socket_path);
    await transport.connect();
    return new CdpClient(transport, fingerprint);
  }

  /**
   * Connect directly to the gate at `socketPath`, skipping automatic discovery.
   */
  static async connect(socketPath: string): Promise<CdpClient> {
    const fingerprint: GateFingerprint = {
      gate_pid: 0,
      gate_binary_hash: "",
      public_key: "",
      socket_path: socketPath,
      started_at: "",
    };
    const transport = new UnixSocketTransport(socketPath);
    await transport.connect();
    return new CdpClient(transport, fingerprint);
  }

  /**
   * Register the calling agent with the gate.
   */
  async register(
    agentId: string,
    agentVersion: string,
    capabilities: string[] = [],
  ): Promise<Session> {
    const result = (await this.transport.send("cdp.register", {
      agent_id: agentId,
      agent_version: agentVersion,
      capabilities,
    })) as unknown as RegisterResult;

    if (result.status !== "registered") {
      throw new CdpError(`unexpected register status: ${result.status}`);
    }

    return new Session(this.transport, result.session_token, result.agent_fingerprint);
  }

  /** Return the default path to the gate fingerprint file. */
  static defaultFingerprintPath(): string {
    const xdg = process.env["XDG_CONFIG_HOME"];
    if (xdg) {
      return path.join(xdg, "cdp", "gate.fingerprint");
    }
    return path.join(os.homedir(), ".config", "cdp", "gate.fingerprint");
  }
}
