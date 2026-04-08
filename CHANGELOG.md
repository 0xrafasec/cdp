# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-07

### Added

- **Core Cryptography** (`cdp-crypto`): mlock'd secure memory, HKDF-SHA256 key derivation, ChaCha20-Poly1305 AEAD encryption, HMAC-SHA256 token generation, core dump prevention.
- **CDP Gate** (`cdp-gate`): Main daemon with Unix socket transport, SO_PEERCRED agent verification, JSON-RPC 2.0 routing, replay protection, mTLS listener for remote agents, graceful shutdown.
- **Policy Engine** (`cdp-policy`): TOML-based policy parsing, three-tier matching (binary_hash > binary_path > agent_id), inotify hot-reload, interactive approval UI (kdialog/zenity/osascript).
- **Lease Manager** (`cdp-lease`): Lease lifecycle (create, renew, revoke, delegate), bounded renewals (max 3, max 4h cumulative), pidfd liveness monitoring, cascading revocation, DNS pinning, channel binding.
- **HTTP Proxy** (`cdp-proxy`): Triple authentication (lease_token + channel_binding + SO_PEERCRED), scope validation, credential injection, response sanitization, DNS pin verification, MITM CA generation.
- **Vault Backends** (`cdp-vault`): Bitwarden CLI subprocess with PID namespace + seccomp sandboxing, file-based encrypted dev vault (Argon2id + ChaCha20-Poly1305), IPC over anonymous socket pairs.
- **CLI Wrapper** (`cdp-cli-wrap`): ASKPASS pipe pattern for git/ssh/kubectl, PR_SET_DUMPABLE=0, PID namespace isolation, output sanitization with token redaction.
- **Browser Sessions** (`cdp-browser`): Headless browser sandbox (bubblewrap/PID namespace + seccomp), login automation, cookie extraction, 2FA detection.
- **AI-to-AI Tokens** (`cdp-token`): Ed25519-signed single-use JWTs, OIDC attestation verification (RS256), mTLS client certificate verification, token revocation list with background cleanup.
- **Audit Logger** (`cdp-audit`): JSONL format with SHA-256 hash chain, tamper detection on startup, 0600 file permissions.
- **Rust SDK** (`cdp-sdk`): Gate discovery, agent registration, lease management, proxy request builder.
- **TypeScript SDK** (`sdk/typescript/`): Unix socket transport, JSON-RPC client, lease management, proxy fetch.
- **Python SDK** (`sdk/python/`): Unix socket transport, JSON-RPC client, type hints, fingerprint discovery.
- **Integration Tests** (`cdp-integration-tests`): 15 end-to-end test scenarios covering full protocol flow.
- **Packaging**: Dockerfile (multi-stage build), systemd user service with security hardening, POSIX installer script.
- **CI**: GitHub Actions with build, test, clippy, fmt check, and cargo-audit.
- **Documentation**: Protocol specification, threat model (21 attack vectors), architecture document, user journey, implementation roadmap.
