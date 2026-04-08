# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in CDP, please report it responsibly:

1. **Email**: Send a detailed report to the maintainers via the contact method listed on the repository
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Security Design

CDP is a security-critical protocol. The implementation follows these principles:

### Threat Model

CDP operates under the **compromised agent** threat model: any AI agent may be fully controlled by an adversary via prompt injection, malicious plugins, or supply chain attacks. The protocol is designed so that even a fully compromised agent cannot exfiltrate credentials.

See [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md) for the full analysis covering 21 attack vectors.

### Cryptographic Primitives

| Purpose | Algorithm | Crate |
|---------|-----------|-------|
| Symmetric encryption | ChaCha20-Poly1305 (AEAD) | `chacha20poly1305` |
| Key derivation | HKDF-SHA256 | `hkdf` |
| Authentication tokens | HMAC-SHA256 | `hmac` |
| Token signing | Ed25519 | `ed25519-dalek` |
| Password hashing | Argon2id | `argon2` |
| Hashing | SHA-256 | `sha2` |

### Memory Protection

- All credentials are held in `mlock`'d memory (`SecureBuffer`) to prevent swap-to-disk
- Sensitive memory is zeroized on drop via the `zeroize` crate
- Core dumps are disabled via `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`
- Per-credential HKDF key isolation prevents cross-credential compromise

### Authentication

Every proxy request requires triple authentication:
1. HMAC-derived lease token
2. Channel binding nonce (constant-time comparison)
3. `SO_PEERCRED` process identity verification

### Sandboxing

- Vault subprocesses: PID namespace + seccomp-BPF + dropped capabilities
- Browser subprocesses: bubblewrap with isolated namespaces + seccomp
- CLI wrapper children: PID namespace + `PR_SET_DUMPABLE=0`

### Audit

All credential access is logged in a hash-chained, tamper-evident audit log. Chain integrity is verified on Gate startup.

## Dependency Auditing

The CI pipeline runs `cargo audit` on every push and pull request to check for known vulnerabilities in dependencies.

## Scope

The following are considered in-scope for security reports:

- Credential leakage to agents or third parties
- Authentication bypass (lease, proxy, or token verification)
- Privilege escalation (scope widening, TTL extension beyond bounds)
- Memory safety issues (use-after-free, buffer overflow, unzeroized secrets)
- Sandbox escape (vault or browser subprocess)
- Audit log tampering without detection
- Replay attacks against the JSON-RPC protocol
- DNS rebinding or redirect-based exfiltration

The following are out-of-scope:

- Denial of service against the local Gate (it runs on the user's own machine)
- Attacks requiring root access on the host
- Social engineering of the user's approval decisions
