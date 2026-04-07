# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CDP (Credential Delegation Protocol) is an open protocol for secure credential delegation to AI agents. A local daemon (the "CDP Gate") mediates all credential access, injecting authentication at the transport layer so agents never see raw credentials. Think of it as what MCP is to tool communication, but for credential access.

**Current phase: Implementation (Phase 1 complete)** — Cargo workspace scaffolded, `cdp-crypto` crate implemented. The reference implementation is in Rust.

## Document Structure

- `CDP_WHITEPAPER.md` — the primary document: full protocol overview, architecture, threat model, and design rationale. Start here.
- `spec/PROTOCOL.md` — detailed JSON-RPC 2.0 message formats, flows, credential types, error codes. The normative specification.
- `spec/THREAT_MODEL.md` — 21 attack vectors with defenses. Follows STRIDE methodology. Covers agent spoofing, proxy hijacking, DNS rebinding, PID recycling, etc.
- `spec/ARCHITECTURE.md` — Rust crate structure, component design, deployment models, integration examples. Implementation blueprint.

## Key Design Decisions

All diagrams use **Mermaid** syntax (renders on GitHub). All documents are at version 0.2.0-draft.

### Security Model (non-negotiable invariants)

These are protocol-level security properties that must hold in any spec change or future implementation:

- **Agent identity is cryptographic**: derived from binary hash + PID + start time via `SO_PEERCRED`, not self-declared. Auto-approve policies require `agent_binary_hash`.
- **Proxy requires triple auth on every request**: lease_token (HMAC) + channel_binding nonce + `SO_PEERCRED`.
- **Browser sessions default to `proxy_only`**: agent never receives cookies; they exist only in the proxy.
- **Per-credential HKDF key isolation**: each credential encrypted with a unique derived key, not a shared session key.
- **DNS pinning at lease creation**: no redirect following by default.
- **Headless browser and vault run in sandboxed subprocesses**: PID namespace, seccomp, dropped caps, anonymous socket communication.
- **Credentials never pre-loaded into environment variables**: CLI wrapper uses ASKPASS/pipe pattern with `PR_SET_DUMPABLE=0`.
- **Bounded renewals**: max 3 renewals, max 4h cumulative TTL per lease.
- **Tamper-evident audit logs**: hash-chained, verified on startup.

### Planned Rust Crate Layout

```
cdp/crates/
  cdp-gate/      cdp-policy/    cdp-lease/     cdp-crypto/
  cdp-proxy/     cdp-browser/   cdp-cli-wrap/  cdp-vault/
  cdp-token/     cdp-audit/     cdp-sdk/
```

## Implementation Roadmap

See `ROADMAP.md` for the 11-phase implementation plan. Each phase has full context so an AI agent can implement it without re-reading the entire spec. Phases are dependency-ordered — the dependency graph is at the bottom of the file. Key parallelism: Phases 3+4 can run concurrently, and Phases 7+8+9 can run concurrently. When you finish implementing each phase, update the roadmap with check, marking as complete.

## When Editing Specs

- Keep all four documents consistent — a change in PROTOCOL.md likely requires updates to the whitepaper, architecture, and threat model.
- The whitepaper is the public-facing document; the spec files contain implementation detail. Don't put implementation-specific Rust details in the whitepaper.
- Never reference internal vulnerability IDs (VLN-XXX) in published documents. Present security properties as design decisions, not "fixes."
- The threat model uses "Attack → Defense" framing, not "Bug → Fix."
