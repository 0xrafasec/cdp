# CDP Reference Architecture

**Version:** 0.2.0-draft
**Status:** Draft
**Date:** 2026-04-07

## 1. System Overview

```mermaid
graph TB
    subgraph "User Space"
        User["User"]
        PolicyFiles["Policy Files<br/>~/.config/cdp/policies/<br/>(signed, inotify-watched)"]
        ApprovalUI["Approval UI<br/>(kdialog/zenity/native)<br/>Shows binary hash, flags untrusted reason"]
        Fingerprint["Gate Fingerprint File<br/>~/.config/cdp/gate.fingerprint<br/>(0400 permissions)"]
    end

    subgraph "CDP Gate Daemon (minimal privileges, seccomp)"
        Listener["Transport Listener<br/>(Unix Socket + SO_PEERCRED)"]
        AgentVerifier["Agent Verifier<br/>(binary hash, pidfd, start_time)"]
        Router["JSON-RPC Router<br/>(nonce + timestamp replay protection)"]
        PolicyEngine["Policy Engine<br/>(match by binary_hash for auto-approve)"]
        LeaseManager["Lease Manager<br/>(bounded renewals, pidfd liveness)"]
        AuditLog["Audit Logger<br/>(hash chain, tamper-evident)"]

        subgraph "Credential Injection (per-credential keys via HKDF)"
            HTTPProxy["HTTP Proxy<br/>(lease_token + channel_binding<br/>+ SO_PEERCRED triple auth)"]
            CLIWrapper["CLI Wrapper<br/>(ASKPASS pipe pattern,<br/>PR_SET_DUMPABLE=0)"]
            TokenIssuer["Token Issuer<br/>(single-use JWTs)"]
        end

        subgraph "Secure Memory (mlock, zeroize)"
            EncMem["Encrypted Memory Pool<br/>(per-credential HKDF keys)"]
        end
    end

    subgraph "Sandboxed Subprocesses"
        BrowserSub["Browser Subprocess<br/>(PID namespace, seccomp,<br/>dropped caps, bubblewrap)"]
        VaultSub["Vault Subprocess<br/>(PID namespace, seccomp,<br/>anon socket to Gate)"]
    end

    subgraph "Vault Backends"
        BW["Bitwarden"]
        OP["1Password"]
        KR["System Keyring"]
        HCVault["HashiCorp Vault"]
    end

    subgraph "Agents (UNTRUSTED)"
        MCP["MCP Servers"]
        PW["Playwright / browserUse"]
        CLI["CLI Tools (git, ssh)"]
        Remote["Cloud Agents"]
    end

    User -->|configures + signs| PolicyFiles
    User -->|approves| ApprovalUI
    PolicyFiles --> PolicyEngine
    ApprovalUI --> PolicyEngine

    MCP & PW & CLI -->|Unix socket<br/>SO_PEERCRED verified| Listener
    Remote -->|mTLS + attestation| Listener
    Listener --> AgentVerifier
    AgentVerifier --> Router
    Router --> PolicyEngine --> LeaseManager
    LeaseManager --> EncMem
    EncMem --> HTTPProxy & CLIWrapper & TokenIssuer
    LeaseManager --> AuditLog

    Gate_to_Vault["anon socket pair"] --> VaultSub
    VaultSub --> BW & OP & KR & HCVault
    Gate_to_Browser["anon socket pair"] --> BrowserSub

    HTTPProxy -->|"DNS-pinned,<br/>no redirect following"| APIs["External APIs"]
    BrowserSub -->|"sandboxed login"| Websites["Websites"]
    HTTPProxy -->|"proxy_only browser mode<br/>(cookie injection)"| PW
    CLIWrapper --> Infra["Infrastructure"]
    TokenIssuer -->|single-use JWT| Remote

    style MCP fill:#f66,stroke:#333,color:#fff
    style PW fill:#f66,stroke:#333,color:#fff
    style CLI fill:#f66,stroke:#333,color:#fff
    style Remote fill:#f66,stroke:#333,color:#fff
    style EncMem fill:#4a9,stroke:#333,color:#fff
    style BrowserSub fill:#fa0,stroke:#333
    style VaultSub fill:#6a6,stroke:#333,color:#fff
```

## 2. Component Design

### 2.1 Transport Listener & Agent Verification

```mermaid
graph LR
    subgraph "Transport Layer"
        UnixSocket["Unix Socket<br/>/run/cdp/gate.sock"]
        mTLS["mTLS Listener<br/>localhost:9443"]
    end

    subgraph "Agent Verification Pipeline"
        PeerCred["SO_PEERCRED<br/>Extract PID, UID, GID"]
        ProcExe["/proc/PID/exe<br/>Resolve binary path"]
        BinaryHash["SHA-256(binary)<br/>Compute hash"]
        StartTime["/proc/PID/stat<br/>Extract start time"]
        PidFd["pidfd_open(PID)<br/>Hold process reference"]
        Fingerprint2["Agent Fingerprint<br/>SHA-256(UID||PID||hash||start_time)"]
    end

    subgraph "Connection Handler"
        JsonRPC["JSON-RPC 2.0<br/>+ nonce/timestamp check"]
        SessionToken["Issue session_token<br/>HMAC-bound to fingerprint"]
    end

    UnixSocket --> PeerCred
    mTLS --> PeerCred
    PeerCred --> ProcExe --> BinaryHash --> StartTime --> PidFd --> Fingerprint2
    Fingerprint2 --> JsonRPC --> SessionToken
```

**Implementation notes:**
- `SO_PEERCRED` extracts PID/UID from the Unix socket — agent cannot fake this
- Binary path resolved via `/proc/<PID>/exe` symlink — agent cannot spoof this
- Binary hash is SHA-256 of the actual binary file — not self-declared
- Process start time from `/proc/<PID>/stat` field 22 — prevents PID recycling
- `pidfd_open()` holds a kernel reference — instant death notification, no polling window
- Agent fingerprint is a composite hash of all verification data
- `session_token = HMAC-SHA256(gate_key, fingerprint || connection_id)` — must be presented on all subsequent calls

### 2.2 Policy Engine

```mermaid
flowchart TD
    Request["Lease Request + session_token"] --> VerifySession["Verify session_token HMAC"]
    VerifySession -->|Invalid| Reject["REJECT -32013"]
    VerifySession -->|Valid| CheckAlive["Check agent alive (pidfd)"]
    CheckAlive -->|Dead| Reject2["REJECT -32019"]
    CheckAlive -->|Alive| LoadPolicies["Load matching policies"]

    LoadPolicies --> HashMatch{"Match by<br/>agent_binary_hash?"}
    HashMatch -->|Yes| EvalScope["Evaluate scope constraints"]
    HashMatch -->|No| PathMatch{"Match by<br/>agent_binary_path?"}
    PathMatch -->|Yes| EvalScope
    PathMatch -->|No| IdMatch{"Match by<br/>agent_id?"}
    IdMatch -->|Yes| ForcePrompt["Force mode = prompt<br/>(auto-approve FORBIDDEN for id-only)"]
    IdMatch -->|No| DefaultDeny["DEFAULT DENY"]

    EvalScope --> ScopeCheck{"Requested ⊆ Allowed?"}
    ScopeCheck -->|Full match| CheckBody["Validate body constraints"]
    ScopeCheck -->|Partial| ReduceScope["Reduce to intersection"]
    ReduceScope --> CheckBody
    ScopeCheck -->|No overlap| DefaultDeny

    CheckBody --> BodyOK{"Body constraints pass?"}
    BodyOK -->|Yes| CheckApproval["Check approval mode"]
    BodyOK -->|No| DefaultDeny

    ForcePrompt --> CheckBody
    CheckApproval --> AutoMode{"mode = auto?"}
    AutoMode -->|Yes| Approved["APPROVED"]
    AutoMode -->|No| PromptUser["Prompt User<br/>(untrusted reason labeled,<br/>binary hash shown)"]
    PromptUser --> UserDecision{"User decision"}
    UserDecision -->|Allow Once| Approved
    UserDecision -->|Allow 10min| ApprovedTimed["APPROVED (time-boxed)"]
    UserDecision -->|Deny| Denied["DENIED"]
    UserDecision -->|Timeout| DefaultDeny

    style DefaultDeny fill:#f66,stroke:#333,color:#fff
    style Denied fill:#f66,stroke:#333,color:#fff
    style Reject fill:#f66,stroke:#333,color:#fff
    style Reject2 fill:#f66,stroke:#333,color:#fff
    style Approved fill:#6f6,stroke:#333
    style ApprovedTimed fill:#6f6,stroke:#333
```

**Policy integrity:**
- Policy directory watched via `inotify(IN_MODIFY | IN_CREATE | IN_DELETE)`
- On change: re-read all policies, check integrity
- If `policy_signing = true` in config: verify Ed25519 signature on each policy file
- Log the PID/binary of the process that made the modification
- Non-interactive modifier → SECURITY ALERT in audit log

### 2.3 Lease Manager

**Lease state machine:**

```mermaid
stateDiagram-v2
    [*] --> Requested: cdp.lease.request + session_token
    Requested --> PendingApproval: Policy requires prompt
    Requested --> Active: Policy auto-approves
    PendingApproval --> Active: User approves
    PendingApproval --> Denied: User denies / timeout
    Active --> Active: cdp.lease.renew (if renewals_remaining > 0)
    Active --> Revoked: cdp.lease.revoke
    Active --> Revoked: Agent process died (pidfd notification)
    Active --> Expired: TTL elapsed OR max_requests reached
    Active --> Delegated: cdp.lease.delegate (creates child)
    Delegated --> Active: Child lease independent
    Revoked --> [*]: Zero credentials immediately
    Expired --> [*]: Zero credentials immediately
    Denied --> [*]
```

**Key properties:**
- Leases stored in memory only (never persisted to disk)
- Each lease has a cryptographic ID (random 256-bit, not 128-bit)
- Lease includes: `agent_fingerprint`, `channel_binding_nonce`, `lease_token`, `dns_pinned_ips`, `renewals_remaining`, `cumulative_ttl_remaining`
- Process liveness via `pidfd` — immediate revocation on agent death, zero window
- Renewal hard limits: `max_renewals` (default 3), `max_cumulative_ttl` (default 4h)
- Parent revocation cascades to all children (depth-first traversal, immediate)

### 2.4 Encrypted Memory Pool

```mermaid
graph TD
    subgraph "Key Hierarchy"
        MasterKey["Master Session Key<br/>(Argon2id from vault auth)<br/>mlock'd, never written to disk"]
        PerCredKey1["HKDF(master, cred_ref_1 || lease_1)"]
        PerCredKey2["HKDF(master, cred_ref_2 || lease_2)"]
        PerCredKeyN["HKDF(master, cred_ref_N || lease_N)"]
    end

    subgraph "Encrypted Memory Pool (mlock'd)"
        Cred1["Credential 1<br/>(ChaCha20-Poly1305)"]
        Cred2["Credential 2<br/>(ChaCha20-Poly1305)"]
        CredN["Credential N<br/>(ChaCha20-Poly1305)"]
    end

    subgraph "Injection Hot Path"
        Derive["Derive per-credential key<br/>(HKDF, microseconds)"]
        Decrypt["Decrypt credential"]
        Inject["Inject into request"]
        Zero["Zeroize key + plaintext<br/>(guaranteed by Drop trait)"]
    end

    MasterKey --> PerCredKey1 & PerCredKey2 & PerCredKeyN
    PerCredKey1 --> Cred1
    PerCredKey2 --> Cred2
    PerCredKeyN --> CredN

    Cred1 -->|on request| Derive
    Derive --> Decrypt --> Inject --> Zero

    style MasterKey fill:#c33,stroke:#333,color:#fff
    style Derive fill:#fa0,stroke:#333
    style Zero fill:#6f6,stroke:#333
```

**Implementation details:**
- **Per-credential key isolation** — each credential encrypted with `HKDF-SHA256(master, credential_ref || lease_id)`. Compromising one key exposes one credential.
- All credential memory is `mlock()`'d (prevents swap)
- Uses `zeroize` crate for guaranteed memory clearing (Rust `Drop` trait)
- `ChaCha20-Poly1305` for authenticated encryption (detects tampering)
- Master key derived from vault authentication via `Argon2id`
- Decrypted credentials + derived keys exist in memory for microseconds, then zeroized
- Core dumps disabled: `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0`

### 2.5 HTTP Proxy

```mermaid
sequenceDiagram
    participant Agent
    participant Proxy as HTTP Proxy
    participant AuthCheck as Triple Auth Check
    participant LeaseCheck as Lease Validator
    participant DNSCheck as DNS Pin Check
    participant EncMem as Encrypted Memory
    participant Target as Target Service

    Agent->>Proxy: GET /repos/owner/repo<br/>+ X-CDP-Lease-Token<br/>+ X-CDP-Channel-Binding
    Proxy->>AuthCheck: Verify SO_PEERCRED (PID/UID match?)
    AuthCheck->>AuthCheck: Verify lease_token HMAC
    AuthCheck->>AuthCheck: Verify channel_binding_nonce
    AuthCheck-->>Proxy: AUTHENTICATED
    Proxy->>LeaseCheck: Validate scope (host, method, path, body)
    LeaseCheck->>LeaseCheck: Check forbidden_paths
    LeaseCheck->>LeaseCheck: Check forbidden_fields in body
    LeaseCheck->>LeaseCheck: Check rate limit (requests_remaining > 0)
    LeaseCheck->>LeaseCheck: Check TTL (not expired)
    LeaseCheck-->>Proxy: VALIDATED
    Proxy->>DNSCheck: Resolve target IP
    DNSCheck->>DNSCheck: Compare to pinned IPs from lease creation
    DNSCheck-->>Proxy: IP MATCHES
    Proxy->>EncMem: Derive per-credential key, decrypt
    EncMem-->>Proxy: Bearer token (plaintext, microseconds)
    Proxy->>Target: GET /repos/owner/repo + Authorization header
    Target-->>Proxy: 200 OK + response
    Proxy->>Proxy: Strip credential-echoing headers
    Proxy->>Proxy: Strip Set-Cookie headers
    Proxy->>Proxy: Block/log redirect if 3xx
    Proxy-->>Agent: 200 OK + sanitized response
    Proxy->>Proxy: Zeroize credential memory
    Proxy->>AuditLog: Log lease.used event
```

**Per-lease proxy design:**
- **Triple authentication** on every request: SO_PEERCRED + lease_token HMAC + channel_binding_nonce
- **Full scope validation**: host, path, method, body constraints, forbidden paths, content type
- **DNS pinning**: IPs resolved at lease creation, verified on every request
- **No redirect following** by default; if enabled, validates redirect target against allowed hosts
- **Response sanitization**: strips Authorization echoes, Set-Cookie, WWW-Authenticate credential hints
- Rate limiting per-lease with atomic counter

### 2.6 Browser Session Manager

```mermaid
graph TD
    subgraph "Gate Main Process"
        LeaseReq["Browser session lease request"]
        ProxySetup["Configure MITM proxy<br/>with session cookies"]
        CookieStore["Encrypted cookie store<br/>(per-credential HKDF key)"]
    end

    subgraph "Sandboxed Browser Subprocess"
        direction TB
        Sandbox["Bubblewrap / PID Namespace<br/>+ seccomp + dropped caps"]
        Headless["Headless Chromium<br/>(isolated profile)"]
        Login["Perform login flow"]
        TwoFA{"2FA required?"}
        Extract["Extract session cookies"]
    end

    subgraph "Anon Socket Pair"
        Pipe["Anonymous Unix Socket<br/>(no filesystem path)"]
    end

    LeaseReq -->|"1. Spawn sandboxed subprocess"| Sandbox
    Sandbox --> Headless
    LeaseReq -->|"2. Send login creds via anon socket"| Pipe
    Pipe -->|"3. Receive creds (encrypted)"| Login
    Login --> Headless
    Headless -->|"4. Navigate to login page"| Website["Target Website"]
    Website --> TwoFA
    TwoFA -->|No| Extract
    TwoFA -->|Yes| PromptUser["Prompt user for 2FA code"]
    PromptUser --> Extract
    Extract -->|"5. Send cookies via anon socket"| Pipe
    Pipe -->|"6. Receive cookies"| CookieStore
    CookieStore --> ProxySetup
    Sandbox -->|"7. Kill subprocess"| Dead["Process terminated"]

    style Sandbox fill:#fa0,stroke:#333
    style Headless fill:#fa0,stroke:#333
```

**Browser security design:**

**Subprocess sandboxing:**
- Browser subprocess launched via `bubblewrap` (or `unshare` fallback):
  - New PID namespace (`CLONE_NEWPID`)
  - New network namespace (only loopback + explicit proxy route)
  - Seccomp filter: block `ptrace`, `process_vm_readv`, `process_vm_writev`, `mount`, `pivot_root`
  - Dropped capabilities: no `CAP_SYS_PTRACE`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`
  - Read-only rootfs bind mount (no writes except `/tmp`)
- No access to Gate memory, vault subprocess, or Unix socket
- Communication ONLY via anonymous socket pair
- Subprocess killed immediately after cookie extraction — never kept alive

**Default proxy_only mode:**
- Agent's browser routes ALL traffic through CDP MITM proxy
- Proxy injects session cookies for matching origins
- Agent's browser context has NO cookies — they exist only in the proxy
- `Set-Cookie` response headers stripped before reaching agent
- Agent cannot exfiltrate what it does not have

**MITM CA protection:**
- CA key generated in memory, encrypted with per-lease HKDF key
- CA key exists ONLY in the MITM proxy subprocess memory
- CA certificate validity: 24 hours, auto-rotated
- CA is **name-constrained**: valid only for origins in active leases (e.g., if lease is for `app.example.com`, CA is valid only for `*.example.com`)
- CA added to browser context only — never system trust store
- All issued certificates logged in audit

### 2.7 CLI Wrapper

```mermaid
graph TD
    subgraph "Agent Process (UNTRUSTED)"
        AgentCmd["Agent calls:<br/>cdp-wrap git push origin main"]
    end

    subgraph "CDP Wrapper Process"
        Wrapper["cdp-wrap binary"]
        NewNS["Create PID namespace<br/>(if available)"]
        NoDump["Set PR_SET_DUMPABLE=0"]
    end

    subgraph "Child Process (Restricted)"
        ChildEnv["Environment:<br/>GIT_ASKPASS=cdp-askpass<br/>(helper path only, NO credentials)"]
        Git["git push origin main"]
    end

    subgraph "cdp-askpass Helper (Ephemeral)"
        AskPass["cdp-askpass"]
        PipeRead["Read credential from<br/>anonymous pipe (from Gate)"]
        WriteStdout["Write to stdout<br/>(git reads it)"]
        ZeroExit["Zeroize memory + exit(0)"]
    end

    subgraph "Gate Daemon"
        Gate["Decrypt credential<br/>via per-credential HKDF key"]
        AnonPipe["Write to anonymous pipe"]
    end

    AgentCmd --> Wrapper
    Wrapper --> NewNS --> NoDump
    NoDump --> ChildEnv --> Git
    Git -->|"calls GIT_ASKPASS"| AskPass
    AskPass --> PipeRead
    Gate --> AnonPipe --> PipeRead
    PipeRead --> WriteStdout --> Git
    WriteStdout --> ZeroExit
    Git -->|"output"| Wrapper
    Wrapper -->|"sanitized output<br/>(credential patterns removed)"| AgentCmd

    style AgentCmd fill:#f66,stroke:#333,color:#fff
    style Gate fill:#6f6,stroke:#333
    style ZeroExit fill:#6f6,stroke:#333
```

**CLI security design:**

| Security Property | How |
|---|---|
| Credentials not in CLI args | Never passed via command line (visible in `ps`) |
| Credentials not pre-loaded in env | `GIT_ASKPASS` points to helper binary, NOT the credential |
| `/proc/environ` not readable | `PR_SET_DUMPABLE=0` blocks `/proc/PID/environ` and `/proc/PID/mem` reads |
| Credential in memory briefly | `cdp-askpass` reads from pipe → writes to stdout → zeroizes → exits immediately |
| Output sanitized | Wrapper scans stdout/stderr for credential patterns before forwarding to agent |
| Process isolation | PID namespace when available; otherwise `PR_SET_DUMPABLE=0` is mandatory |

**Supported injection methods:**
| Tool | Injection Method | Credential Delivery |
|------|-----------------|---------------------|
| git | `GIT_ASKPASS` helper binary | Anonymous pipe from Gate |
| ssh | CDP-managed `SSH_AUTH_SOCK` (agent forwarding) | Gate implements SSH agent protocol on the socket |
| kubectl | Temporary `KUBECONFIG` (0600, tmpfs, deleted after exec) | Written by Gate, read by kubectl, shredded immediately |
| aws | CDP credential process (`credential_process` in config) | Gate implements the AWS credential process protocol |
| docker | Credential helper (`docker-credential-cdp`) | Gate implements Docker credential helper protocol |
| generic | cdp-askpass on anonymous pipe | Pipe from Gate, read on demand |

### 2.8 Token Issuer (AI-to-AI)

```mermaid
graph TD
    RemoteAgent["Remote Agent<br/>(Cloud-hosted)"]
    Gate["CDP Gate"]
    Attestation["Attestation Verifier"]
    Signer["JWT Signer<br/>(Ed25519, key in mlock'd memory)"]
    RevocationList["Revocation Endpoint<br/>(signed, append-only)"]
    TargetAPI["Target API"]

    RemoteAgent -->|"1. Register + mTLS + attestation"| Gate
    Gate -->|"2. Verify attestation"| Attestation
    Attestation -->|"3. Valid"| Gate
    RemoteAgent -->|"4. cdp.lease.request"| Gate
    Gate -->|"5. Sign single-use token"| Signer
    Signer -->|"6. JWT (single_use=true, 5min TTL)"| Gate
    Gate -->|"7. JWT + constraints"| RemoteAgent
    RemoteAgent -->|"8. API call with JWT"| TargetAPI
    TargetAPI -->|"9. Validate JWT:<br/>- check signature (Ed25519)<br/>- check audience<br/>- check scope<br/>- check expiry<br/>- check revocation list<br/>- check single_use (nonce)"| TargetAPI

    style RemoteAgent fill:#f66,stroke:#333,color:#fff
    style Gate fill:#6f6,stroke:#333
```

**Token security properties:**
- Ed25519 signed JWTs — signing key in mlock'd memory, never on disk
- `single_use = true` by default — JWT contains a nonce, target API checks for replay
- TTL: 1–5 minutes (configurable per policy)
- Contains: `aud` (audience), `scope`, `lease_id`, `agent_id`, `delegation_chain`, `jti` (unique ID)
- Revocation: Gate publishes signed revocation list at well-known endpoint
- Target APIs validate independently OR call Gate's introspection endpoint

## 3. Deployment Models

### 3.1 Local Desktop (Primary)

```mermaid
graph TD
    subgraph "User's Machine"
        subgraph "systemd user service"
            Gate["CDP Gate<br/>(dedicated user, seccomp)"]
        end
        subgraph "Sandboxed"
            VaultProc["Vault Subprocess<br/>(PID ns, seccomp)"]
            BrowserProc["Browser Subprocess<br/>(bubblewrap)"]
        end
        Socket["/run/cdp/gate.sock<br/>(0660, cdp group)"]
        FP["~/.config/cdp/gate.fingerprint<br/>(0400)"]
        Policies["~/.config/cdp/policies/<br/>(0700 dir, signed files)"]
        AuditLog2["~/.local/share/cdp/audit.jsonl<br/>(0600, hash chain)"]
        Agents2["Local Agents"]
    end

    Agents2 -->|"verify fingerprint<br/>then connect"| Socket --> Gate
    Gate --> VaultProc -->|"anon socket"| BW2["Bitwarden"]
    Gate --> BrowserProc

    style Gate fill:#6f6,stroke:#333
    style VaultProc fill:#6a6,stroke:#333,color:#fff
    style BrowserProc fill:#fa0,stroke:#333
```

### 3.2 Development Container

```mermaid
graph LR
    subgraph "Dev Container"
        Agent3["Agent"]
        Socket3["Forwarded socket"]
    end

    subgraph "Host"
        Gate4["CDP Gate"]
        Socket4["/run/cdp/gate.sock"]
        FP2["gate.fingerprint"]
    end

    Agent3 -->|"bind mount (read-only)"| Socket3 -->|"SO_PEERCRED verified"| Socket4 --> Gate4
    Agent3 -.->|"bind mount (read-only)"| FP2
```

- Gate runs on host, socket and fingerprint file bind-mounted into container (read-only)
- Agent verifies fingerprint, then connects
- `SO_PEERCRED` works across mount namespaces on Linux
- Credentials never enter the container filesystem

### 3.3 Remote / Multi-Machine

```mermaid
graph LR
    subgraph "User's Machine"
        Gate5["CDP Gate<br/>(mTLS on :9443)"]
        FW["Firewall:<br/>allow only known CIDRs"]
    end

    subgraph "Cloud VM / CI"
        RemoteAgent3["Remote Agent"]
        ClientCert["mTLS Client Certificate"]
    end

    RemoteAgent3 -->|"mTLS + attestation<br/>+ OIDC identity"| FW --> Gate5
    Gate5 -->|"single-use JWT<br/>(5min, rate-limited)"| RemoteAgent3
```

- mTLS mandatory for all remote connections
- Attestation required (OIDC, enclave, signed_code)
- Firewall restricts source IPs
- All tokens single-use, 5-minute TTL
- No delegation capability for remote agents by default

## 4. Rust Crate Structure

```
cdp/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── cdp-gate/               # Main daemon binary
│   │   ├── src/
│   │   │   ├── main.rs         # Entry point, systemd integration, seccomp setup
│   │   │   ├── listener.rs     # Unix socket + mTLS listener
│   │   │   ├── agent_verify.rs # SO_PEERCRED, binary hash, pidfd, fingerprint
│   │   │   ├── router.rs       # JSON-RPC routing, nonce/timestamp checks
│   │   │   ├── fingerprint.rs  # Gate fingerprint file management
│   │   │   └── config.rs       # Configuration loading
│   │   └── Cargo.toml
│   │
│   ├── cdp-policy/             # Policy engine
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── parser.rs       # TOML policy parsing + validation
│   │   │   ├── verifier.rs     # Ed25519 signature verification
│   │   │   ├── evaluator.rs    # Policy evaluation (binary_hash matching)
│   │   │   ├── watcher.rs      # inotify policy file monitoring
│   │   │   └── approval.rs     # User approval flows (untrusted reason display)
│   │   └── Cargo.toml
│   │
│   ├── cdp-lease/              # Lease lifecycle management
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── manager.rs      # Lease create/renew/revoke (bounded renewals)
│   │   │   ├── delegation.rs   # Delegation chain logic
│   │   │   ├── liveness.rs     # pidfd/proc agent liveness monitoring
│   │   │   ├── channel_bind.rs # Channel binding nonce generation/verification
│   │   │   └── dns_pin.rs      # DNS resolution pinning at lease creation
│   │   └── Cargo.toml
│   │
│   ├── cdp-crypto/             # Encrypted memory + crypto
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── mempool.rs      # mlock'd encrypted credential store
│   │   │   ├── hkdf.rs         # Per-credential HKDF key derivation
│   │   │   ├── cipher.rs       # ChaCha20-Poly1305 encrypt/decrypt
│   │   │   ├── hmac.rs         # Lease token + session token generation
│   │   │   └── zeroize.rs      # Guaranteed memory zeroing
│   │   └── Cargo.toml
│   │
│   ├── cdp-proxy/              # HTTP/MITM proxy
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── auth.rs         # Triple auth: SO_PEERCRED + lease_token + channel_bind
│   │   │   ├── http.rs         # HTTP proxy with header injection
│   │   │   ├── scope.rs        # Request scope validation (host, path, method, body)
│   │   │   ├── redirect.rs     # Redirect blocking/validation
│   │   │   ├── dns.rs          # DNS pin verification
│   │   │   ├── websocket.rs    # WebSocket upgrade + lifecycle management
│   │   │   ├── mitm.rs         # MITM proxy for browser sessions
│   │   │   ├── mitm_ca.rs      # Name-constrained, short-lived CA management
│   │   │   └── sanitizer.rs    # Response credential stripping
│   │   └── Cargo.toml
│   │
│   ├── cdp-browser/            # Browser session management
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── sandbox.rs      # Bubblewrap/unshare subprocess spawning
│   │   │   ├── snapshot.rs     # Session snapshot login flow (in subprocess)
│   │   │   ├── cookies.rs      # Cookie extraction/filtering
│   │   │   └── twofa.rs        # 2FA handling (user prompt)
│   │   └── Cargo.toml
│   │
│   ├── cdp-cli-wrap/           # CLI wrapper binary
│   │   ├── src/
│   │   │   ├── main.rs         # cdp-wrap entry point
│   │   │   ├── namespace.rs    # PID namespace + PR_SET_DUMPABLE setup
│   │   │   ├── exec.rs         # Wrapped command execution
│   │   │   ├── askpass.rs      # cdp-askpass helper (pipe-based, ephemeral)
│   │   │   └── sanitize.rs     # Output sanitization (credential pattern removal)
│   │   └── Cargo.toml
│   │
│   ├── cdp-vault/              # Vault backend trait + implementations
│   │   ├── src/
│   │   │   ├── lib.rs          # VaultBackend trait
│   │   │   ├── subprocess.rs   # Sandboxed vault subprocess management
│   │   │   ├── bitwarden.rs    # Bitwarden implementation (session in subprocess only)
│   │   │   ├── onepassword.rs  # 1Password implementation
│   │   │   ├── keyring.rs      # System keyring implementation
│   │   │   └── file.rs         # File-based (dev/testing only)
│   │   └── Cargo.toml
│   │
│   ├── cdp-token/              # JWT token issuance (AI-to-AI)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── issuer.rs       # JWT signing (single-use nonce)
│   │   │   ├── validator.rs    # JWT validation
│   │   │   └── revocation.rs   # Signed, append-only revocation list
│   │   └── Cargo.toml
│   │
│   ├── cdp-audit/              # Audit logging
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── logger.rs       # Structured event logging (hash chain)
│   │   │   ├── integrity.rs    # Hash chain verification on startup
│   │   │   └── export.rs       # Log export (JSON, syslog, remote SIEM)
│   │   └── Cargo.toml
│   │
│   └── cdp-sdk/                # Client SDK for agent developers
│       ├── src/
│       │   ├── lib.rs
│       │   ├── client.rs       # CDP Gate client
│       │   ├── discover.rs     # Gate discovery + fingerprint verification
│       │   ├── lease.rs        # Lease request helpers (with lease_token management)
│       │   └── proxy.rs        # Proxy request helpers (auto-inject CDP headers)
│       └── Cargo.toml
│
├── cdp-askpass/                 # GIT_ASKPASS helper binary (minimal, ephemeral)
├── policies/                    # Example policy files (with signatures)
└── docs/                        # Additional documentation
```

## 5. Key Dependencies (Rust)

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `hyper` | HTTP proxy implementation |
| `rustls` | TLS (proxy + mTLS listener) |
| `chacha20poly1305` | Credential encryption |
| `hkdf` + `sha2` | Per-credential key derivation |
| `hmac` | Lease token + session token generation |
| `zeroize` | Guaranteed memory zeroing |
| `jsonrpsee` | JSON-RPC 2.0 server/client |
| `serde` / `toml` | Policy file parsing |
| `ed25519-dalek` | JWT signing + policy signing |
| `tracing` | Structured logging |
| `headless_chrome` | Browser session management (in subprocess) |
| `argon2` | Master session key derivation |
| `nix` | Unix socket, mlock, SO_PEERCRED, pidfd, namespaces |
| `inotify` | Policy file monitoring |
| `seccomp-sys` | System call filtering |
| `bubblewrap` (system) | Browser subprocess sandboxing |
| `uuid` | Nonce generation (v4) |

## 6. Configuration

```toml
# ~/.config/cdp/gate.toml

[gate]
socket_path = "/run/cdp/gate.sock"
log_level = "info"
audit_log_path = "~/.local/share/cdp/audit.jsonl"
fingerprint_path = "~/.config/cdp/gate.fingerprint"

[gate.tls]
enabled = false  # Enable for remote access
cert_path = "~/.config/cdp/gate.crt"
key_path = "~/.config/cdp/gate.key"
client_ca_path = "~/.config/cdp/client-ca.crt"

[vault]
backend = "bitwarden"
subprocess_sandbox = true  # Run vault in isolated subprocess

[vault.bitwarden]
cli_path = "/usr/bin/bw"
session_timeout_minutes = 60

[approval]
default_method = "gui"
gui_command = "kdialog"
timeout_seconds = 30
cooldown_seconds = 5           # Min time between approval prompts (anti-fatigue)
show_binary_hash = true        # Show agent binary hash in approval dialog
label_reason_untrusted = true  # Mark agent-provided reason as unverified
max_reason_length = 200        # Truncate reason field

[security]
max_delegation_depth = 3
default_lease_ttl_seconds = 3600
max_lease_ttl_seconds = 86400
max_renewals_per_lease = 3
max_cumulative_ttl_seconds = 14400  # 4 hours
remote_max_ttl_seconds = 300
remote_single_use = true
encrypted_memory = true
per_credential_keys = true     # HKDF per-credential key derivation
disable_core_dumps = true
require_binary_hash_for_auto = true  # Reject auto-approve without binary hash
policy_signing = false         # Enable Ed25519 policy signing
policy_signing_key = ""
nonce_window_seconds = 300     # Replay detection window
nonce_max_entries = 100000     # Max stored nonces

[security.dns]
pin_at_lease_creation = true   # Pin DNS resolutions
allow_dynamic_dns = false      # Require explicit policy opt-in for dynamic DNS

[security.proxy]
follow_redirects = false       # Default: block redirects
strip_set_cookie = true        # Strip Set-Cookie from proxy responses
strip_auth_echo = true         # Strip Authorization echoes from responses

[proxy]
bind_address = "127.0.0.1"
port_range = "19000-19999"

[browser]
sandbox_method = "bubblewrap"  # "bubblewrap", "unshare", "none" (not recommended)
default_mode = "proxy_only"    # "proxy_only", "scoped_snapshot", "full_snapshot"
mitm_ca_validity_hours = 24
mitm_ca_name_constrained = true
kill_after_snapshot = true     # Kill browser subprocess after cookie extraction
```

## 7. Integration Examples

### 7.1 MCP Server Using CDP

```typescript
import { CdpClient } from '@cdp-protocol/sdk';

// SDK auto-discovers Gate via socket, verifies fingerprint file
const cdp = new CdpClient();

const lease = await cdp.requestLease({
  credentialRef: 'github_api',
  scope: {
    hosts: ['api.github.com'],
    methods: ['GET'],
    paths: ['/repos/**'],
    forbiddenPaths: ['/repos/*/keys', '/repos/*/hooks'],
    ttlSeconds: 600,
  },
  reason: 'Fetching repository information for user query',
});

// SDK auto-includes X-CDP-Lease-Token and X-CDP-Channel-Binding
const response = await lease.fetch('/repos/owner/repo');
// Equivalent to:
// fetch(`${lease.proxyUrl}/repos/owner/repo`, {
//   headers: {
//     'X-CDP-Lease-Token': lease.leaseToken,
//     'X-CDP-Channel-Binding': lease.channelBindingNonce,
//   }
// });
```

### 7.2 Playwright Using CDP (proxy_only mode)

```typescript
import { chromium } from 'playwright';
import { CdpClient } from '@cdp-protocol/sdk';

const cdp = new CdpClient();

// Gate logs in via sandboxed subprocess, configures MITM proxy
// NO cookies returned to agent — all injected via proxy
const session = await cdp.requestBrowserSession({
  credentialRef: 'app_login',
  origins: ['https://app.example.com'],
  mode: 'proxy_only',  // DEFAULT — agent never sees cookies
  ttlSeconds: 1800,
});

const browser = await chromium.launch();
const context = await browser.newContext({
  proxy: { server: session.proxyUrl },  // Route ALL traffic through CDP proxy
  // NO cookies injected — proxy handles authentication
});

const page = await context.newPage();
await page.goto('https://app.example.com/dashboard');
// Agent is authenticated. Proxy injected cookies transparently.
// Agent has NO cookies, NO credentials, NO session tokens.
```

### 7.3 CLI Tool Using CDP

```bash
# cdp-wrap handles everything securely:
# 1. Requests CLI lease (verified by binary hash)
# 2. Spawns git in PID namespace with PR_SET_DUMPABLE=0
# 3. GIT_ASKPASS helper reads credentials from anonymous pipe
# 4. Helper zeroes memory and exits immediately after
# 5. Output sanitized before returning to caller
cdp-wrap git push origin main
```
