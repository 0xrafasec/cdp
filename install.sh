#!/bin/sh
# CDP installation script.
# Installs cdp-gate and cdp-wrap binaries, creates configuration directories,
# optionally installs the systemd user service, and writes an example policy.
#
# Usage: ./install.sh [--no-systemd]
#
# Requirements: POSIX sh, a pre-built release directory at ./target/release/
# or binaries in the current directory.

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INSTALL_SYSTEMD=1
BINARY_DIR="./target/release"

for arg in "$@"; do
    case "$arg" in
        --no-systemd) INSTALL_SYSTEMD=0 ;;
        --binary-dir=*) BINARY_DIR="${arg#--binary-dir=}" ;;
    esac
done

# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)   ARCH_LABEL="x86_64" ;;
    aarch64)  ARCH_LABEL="aarch64" ;;
    arm64)    ARCH_LABEL="aarch64" ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

echo "Detected architecture: $ARCH_LABEL"

# ---------------------------------------------------------------------------
# Directory setup
# ---------------------------------------------------------------------------

LOCAL_BIN="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/cdp"
POLICY_DIR="${HOME}/.config/cdp/policies"
DATA_DIR="${HOME}/.local/share/cdp"

mkdir -p "$LOCAL_BIN"
mkdir -p "$CONFIG_DIR"
mkdir -p "$POLICY_DIR"
mkdir -p "$DATA_DIR"

# Restrict config and data directories: only owner can read/write.
chmod 0700 "$CONFIG_DIR"
chmod 0700 "$DATA_DIR"

echo "Created directories:"
echo "  $LOCAL_BIN"
echo "  $CONFIG_DIR"
echo "  $POLICY_DIR"
echo "  $DATA_DIR"

# ---------------------------------------------------------------------------
# Binary installation
# ---------------------------------------------------------------------------

for binary in cdp-gate cdp-wrap; do
    src="${BINARY_DIR}/${binary}"
    dst="${LOCAL_BIN}/${binary}"

    if [ -f "$src" ]; then
        cp "$src" "$dst"
        chmod 0755 "$dst"
        echo "Installed: $dst"
    else
        echo "WARNING: Binary not found: $src (skipping)" >&2
    fi
done

# ---------------------------------------------------------------------------
# systemd user service
# ---------------------------------------------------------------------------

if [ "$INSTALL_SYSTEMD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
    mkdir -p "$SYSTEMD_USER_DIR"

    SERVICE_SRC="./packaging/systemd/cdp-gate.service"
    SERVICE_DST="${SYSTEMD_USER_DIR}/cdp-gate.service"

    if [ -f "$SERVICE_SRC" ]; then
        cp "$SERVICE_SRC" "$SERVICE_DST"
        echo "Installed systemd user service: $SERVICE_DST"
        systemctl --user daemon-reload 2>/dev/null || true
        echo "To enable and start the service, run:"
        echo "  systemctl --user enable --now cdp-gate"
    else
        echo "WARNING: Service file not found: $SERVICE_SRC (skipping)" >&2
    fi
else
    echo "Skipping systemd service installation."
fi

# ---------------------------------------------------------------------------
# Example policy
# ---------------------------------------------------------------------------

EXAMPLE_POLICY="${POLICY_DIR}/example.toml"

if [ ! -f "$EXAMPLE_POLICY" ]; then
    cat > "$EXAMPLE_POLICY" << 'TOML'
# Example CDP policy file.
#
# Each [[policy]] block defines one rule. The gate evaluates rules in order
# and applies the first match. Rules that use mode = "auto" MUST specify
# agent_binary_hash — a cryptographic identity field — to prevent privilege
# escalation by a compromised agent.
#
# Replace the agent_binary_hash value with the SHA-256 hash of your agent binary:
#   sha256sum /path/to/your-agent | awk '{print "sha256:" $1}'

[[policy]]
name        = "example-github-readonly"
description = "Allow read-only GitHub API access for the example agent"

[policy.match]
# Cryptographic identity: SHA-256 hash of the agent binary.
# Replace with the real hash of your agent.
agent_binary_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
credential_ref    = "github_api_token"

[policy.allow]
hosts               = ["api.github.com"]
methods             = ["GET"]
paths               = ["/repos/**", "/users/**", "/orgs/**"]
forbidden_paths     = ["/repos/*/keys", "/repos/*/hooks"]
max_ttl_seconds     = 3600
max_renewals        = 3
max_cumulative_ttl_seconds = 14400
renewable           = true

[policy.approval]
# auto: no user prompt required (requires agent_binary_hash above).
# prompt: user must approve each request via a GUI dialog.
mode = "auto"

[policy.delegation]
allowed   = false
max_depth = 0
TOML
    chmod 0600 "$EXAMPLE_POLICY"
    echo "Created example policy: $EXAMPLE_POLICY"
else
    echo "Example policy already exists: $EXAMPLE_POLICY (not overwriting)"
fi

# ---------------------------------------------------------------------------
# PATH reminder
# ---------------------------------------------------------------------------

case ":${PATH}:" in
    *":${LOCAL_BIN}:"*) ;;
    *)
        echo ""
        echo "NOTE: ${LOCAL_BIN} is not in your PATH."
        echo "Add the following line to your shell profile (~/.profile or ~/.bashrc):"
        echo "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
        ;;
esac

echo ""
echo "CDP installation complete."
echo "Run 'cdp-gate --help' to get started."
