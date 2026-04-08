# Contributing to CDP

Thank you for your interest in contributing to the Credential Delegation Protocol. CDP is a security-critical project, so contributions are held to a high standard.

## Getting Started

1. **Read the spec first.** Before writing code, familiarize yourself with:
   - [CDP Whitepaper](CDP_WHITEPAPER.md) — protocol overview and design rationale
   - [Protocol Specification](spec/PROTOCOL.md) — message formats and flows
   - [Threat Model](spec/THREAT_MODEL.md) — security constraints
   - [Architecture](spec/ARCHITECTURE.md) — crate structure and design

2. **Check existing issues** to see if someone is already working on what you have in mind.

3. **Open an issue first** for non-trivial changes. This avoids wasted effort if the approach doesn't align with the project direction.

## Development Setup

### Prerequisites

- Rust 1.85+ (2024 edition)
- Linux (kernel 5.3+ recommended for full pidfd support)
- `cargo-audit` (optional, for dependency auditing)

### Build and Test

```bash
# Build the entire workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Run lints
cargo clippy --workspace -- -D warnings

# Check formatting
cargo fmt --check
```

### Project Structure

```
crates/
├── cdp-gate/          # Main daemon
├── cdp-crypto/        # Core cryptographic primitives
├── cdp-policy/        # Policy engine
├── cdp-lease/         # Lease management
├── cdp-proxy/         # HTTP proxy with credential injection
├── cdp-vault/         # Vault backends
├── cdp-browser/       # Headless browser sessions
├── cdp-cli-wrap/      # CLI wrapper
├── cdp-token/         # JWT token issuance
├── cdp-audit/         # Audit logging
├── cdp-sdk/           # Rust client SDK
└── cdp-integration-tests/
sdk/
├── typescript/        # TypeScript SDK
└── python/            # Python SDK
```

## Code Standards

### Security Requirements

These are non-negotiable:

- **No stubs or placeholder code.** Every function must be fully implemented. Never use `todo!()`, `unimplemented!()`, or dummy return values in library/binary code.
- **Constant-time comparisons** for all secret values (tokens, nonces, HMACs).
- **Zeroize sensitive memory** on drop. Use `SecureBuffer` or `Zeroizing<T>` for credentials.
- **Validate all inputs** at system boundaries.
- **Never log credentials or secrets.** Audit events must not contain raw credential values.
- **No `.unwrap()` in library code.** Use proper error handling with `Result<T, E>`.

### Rust Conventions

- **Strong typing.** Use newtypes for domain concepts (`LeaseId`, fingerprint hashes).
- **Module-per-concern.** Match the style established in existing crates.
- **`thiserror` for error enums.** Follow the existing error patterns.
- **Length-prefixed hashing** to prevent field-boundary ambiguity.
- **Tests for every public function.** Unit tests in `#[cfg(test)]` modules, integration tests in `tests/`.

### Formatting

- Run `cargo fmt` before committing.
- Run `cargo clippy` and fix all warnings.

## Spec Changes

When modifying the protocol specification:

- **Keep all four documents consistent.** A change in `PROTOCOL.md` likely requires updates to:
  - `CDP_WHITEPAPER.md` (public-facing)
  - `spec/ARCHITECTURE.md` (implementation)
  - `spec/THREAT_MODEL.md` (security)
- **The whitepaper is public-facing.** Don't put Rust-specific implementation details in it.
- **Use "Attack -> Defense" framing** in the threat model, not "Bug -> Fix."

## Pull Request Process

1. **Fork the repository** and create a feature branch.
2. **Write tests** for new functionality.
3. **Ensure CI passes**: `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check`.
4. **Write a clear PR description** explaining what changed and why.
5. **One concern per PR.** Don't bundle unrelated changes.

### Commit Messages

Use concise, descriptive commit messages:

```
feat: add pidfd liveness monitoring to lease manager
fix: constant-time comparison in channel binding verification
docs: update threat model with DNS rebinding defense
test: add integration test for delegation cascade revocation
```

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, Rust version, kernel version)

## Reporting Security Vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0, consistent with the project license.
