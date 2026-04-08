//! Triple authentication for proxied requests.
//!
//! Every request reaching the proxy listener must pass three independent
//! checks before the credential is injected:
//!
//! 1. **Lease token** — HMAC-SHA256 covering lease_id + agent fingerprint +
//!    channel binding nonce.  Presented in the `X-CDP-Lease-Token` header.
//! 2. **Channel binding** — the raw 32-byte nonce from the lease, hex-encoded
//!    in `X-CDP-Channel-Binding`.  Prevents token replay from a different
//!    channel.
//! 3. **OS peer identity** — the agent's PID and UID are resolved via
//!    `/proc/net/tcp` + `/proc/<pid>/fd/` symlink scanning, then compared
//!    against the values recorded in the lease.

use std::net::SocketAddr;

use cdp_lease::{Lease, LeaseId};

use crate::ProxyError;

// ---------------------------------------------------------------------------
// Header name constants
// ---------------------------------------------------------------------------

pub const HEADER_LEASE_TOKEN: &str = "x-cdp-lease-token";
pub const HEADER_CHANNEL_BINDING: &str = "x-cdp-channel-binding";

// ---------------------------------------------------------------------------
// Public authenticate entry point
// ---------------------------------------------------------------------------

/// Authenticate an incoming proxy request using triple auth.
///
/// # Errors
///
/// Returns [`ProxyError::AuthFailed`] if any of the three checks fail.
/// Returns [`ProxyError::Io`] for OS-level errors during peer resolution.
pub async fn authenticate(
    remote_addr: SocketAddr,
    headers: &http::HeaderMap,
    lease_id: &LeaseId,
    lease: &Lease,
    gate_key: &[u8],
) -> Result<(), ProxyError> {
    // 1. Extract headers.
    let token_str = extract_header(headers, HEADER_LEASE_TOKEN)
        .ok_or_else(|| ProxyError::AuthFailed("missing X-CDP-Lease-Token header".to_string()))?;

    let cb_hex = extract_header(headers, HEADER_CHANNEL_BINDING).ok_or_else(|| {
        ProxyError::AuthFailed("missing X-CDP-Channel-Binding header".to_string())
    })?;

    // 2. Decode channel binding nonce from hex.
    let cb_bytes = hex_to_bytes(cb_hex).ok_or_else(|| {
        ProxyError::AuthFailed("X-CDP-Channel-Binding is not valid hex".to_string())
    })?;

    // 3. Verify lease token (HMAC, constant-time).
    if !cdp_crypto::verify_lease_token(
        gate_key,
        lease_id.as_str(),
        &lease.agent_fingerprint_hash,
        &lease.channel_binding_nonce,
        token_str,
    ) {
        return Err(ProxyError::AuthFailed(
            "lease token verification failed".to_string(),
        ));
    }

    // 4. Verify channel binding (constant-time XOR comparison).
    if !cdp_lease::channel_bind::verify_binding(&lease.channel_binding_nonce, &cb_bytes) {
        return Err(ProxyError::AuthFailed(
            "channel binding nonce mismatch".to_string(),
        ));
    }

    // 5. Resolve OS peer identity and compare with lease.
    let (peer_pid, peer_uid) = resolve_tcp_peer(remote_addr).await?;

    if peer_pid != lease.agent_pid {
        return Err(ProxyError::AuthFailed(format!(
            "peer PID {peer_pid} does not match lease PID {}",
            lease.agent_pid
        )));
    }
    if peer_uid != lease.agent_uid {
        return Err(ProxyError::AuthFailed(format!(
            "peer UID {peer_uid} does not match lease UID {}",
            lease.agent_uid
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// /proc/net/tcp peer resolution
// ---------------------------------------------------------------------------

/// Resolve the PID and UID of the process that owns the TCP socket
/// corresponding to `remote_addr` (the peer address as seen by the proxy).
///
/// Reads `/proc/net/tcp` (IPv4) to find the socket inode, then scans
/// `/proc/<pid>/fd/` symlinks to find the owning process.
pub async fn resolve_tcp_peer(remote_addr: SocketAddr) -> Result<(u32, u32), ProxyError> {
    let inode = find_socket_inode(remote_addr)?;
    let pid = find_pid_for_inode(inode)?;
    let uid = read_uid_for_pid(pid)?;
    Ok((pid, uid))
}

/// Find the socket inode for the connection whose local address (from the
/// kernel's perspective) matches `remote_addr`.
///
/// `remote_addr` is the peer address as the proxy sees it — i.e. the agent's
/// local IP:ephemeral-port.  In `/proc/net/tcp`, that entry appears as the
/// `local_address` column. Reads `/proc/net/tcp` for IPv4 addresses and
/// `/proc/net/tcp6` for IPv6.
pub fn find_socket_inode(remote_addr: SocketAddr) -> Result<u64, ProxyError> {
    let proc_path = match remote_addr.ip() {
        std::net::IpAddr::V4(_) => "/proc/net/tcp",
        std::net::IpAddr::V6(_) => "/proc/net/tcp6",
    };
    let content = std::fs::read_to_string(proc_path)
        .map_err(|e| ProxyError::AuthFailed(format!("cannot read {proc_path}: {e}")))?;
    parse_proc_net_tcp(&content, remote_addr)
}

/// Parse the contents of `/proc/net/tcp` (or `/proc/net/tcp6`) and return the
/// inode for the entry whose `local_address` column matches `target_addr`.
///
/// This function is public so that it can be tested with synthetic content
/// without requiring real network connections.
pub fn parse_proc_net_tcp(content: &str, target_addr: SocketAddr) -> Result<u64, ProxyError> {
    let target_local = match target_addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let ip_hex = ipv4_to_proc_hex(v4);
            let port_hex = format!("{:04X}", target_addr.port());
            format!("{ip_hex}:{port_hex}")
        }
        std::net::IpAddr::V6(v6) => {
            let ip_hex = ipv6_to_proc_hex(v6);
            let port_hex = format!("{:04X}", target_addr.port());
            format!("{ip_hex}:{port_hex}")
        }
    };

    for line in content.lines().skip(1) {
        // Columns: sl local_address rem_address st tx_queue rx_queue tr ... uid ... inode
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let local_addr = fields[1];
        if local_addr == target_local {
            // inode is field index 9 (0-based).
            let inode = fields[9].parse::<u64>().map_err(|_| {
                ProxyError::AuthFailed(format!(
                    "cannot parse inode {:?} in /proc/net/tcp",
                    fields[9]
                ))
            })?;
            return Ok(inode);
        }
    }

    Err(ProxyError::AuthFailed(format!(
        "no /proc/net/tcp entry found for {target_addr}"
    )))
}

/// Scan `/proc/<pid>/fd/` symlinks to find the process whose file descriptor
/// points to socket inode `target_inode`.
pub fn find_pid_for_inode(target_inode: u64) -> Result<u32, ProxyError> {
    let target_link = format!("socket:[{target_inode}]");

    let proc_dir = std::fs::read_dir("/proc")
        .map_err(|e| ProxyError::AuthFailed(format!("cannot read /proc: {e}")))?;

    for entry in proc_dir.flatten() {
        // Only examine numeric directories (PIDs).
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // Process may have exited.
        };

        for fd_entry in fds.flatten() {
            let fd_path = fd_entry.path();
            match std::fs::read_link(&fd_path) {
                Ok(target) if target.to_string_lossy() == target_link => {
                    return Ok(pid);
                }
                _ => continue,
            }
        }
    }

    Err(ProxyError::AuthFailed(format!(
        "no process found owning socket inode {target_inode}"
    )))
}

/// Read the effective UID of `pid` from `/proc/<pid>/status`.
///
/// Parses the `Uid:` line, which contains four UIDs separated by tabs:
/// real, effective, saved-set, filesystem.  We return the effective UID
/// (second field) since that is what `SO_PEERCRED` returns.
pub fn read_uid_for_pid(pid: u32) -> Result<u32, ProxyError> {
    let status_path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&status_path)
        .map_err(|e| ProxyError::AuthFailed(format!("cannot read {status_path}: {e}")))?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Fields: real effective saved-set filesystem, separated by tabs.
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if fields.len() < 2 {
                return Err(ProxyError::AuthFailed(format!(
                    "unexpected Uid: line format in {status_path}"
                )));
            }
            let uid = fields[1].parse::<u32>().map_err(|_| {
                ProxyError::AuthFailed(format!("cannot parse effective UID from {status_path}"))
            })?;
            return Ok(uid);
        }
    }

    Err(ProxyError::AuthFailed(format!(
        "Uid: line not found in {status_path}"
    )))
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Extract a header value as a `&str`, returning `None` on missing or non-ASCII.
fn extract_header<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Decode a lowercase/uppercase hex string to bytes.  Returns `None` on error.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Encode an IPv4 address as the 8-character uppercase hex string used in
/// `/proc/net/tcp` on little-endian x86 systems.
///
/// The kernel stores the address as a 32-bit host-endian integer, so on
/// little-endian systems the bytes are reversed compared to network order.
/// Example: 127.0.0.1 (0x7F000001 in network order) → 0x0100007F → "0100007F".
fn ipv4_to_proc_hex(ip: std::net::Ipv4Addr) -> String {
    // `to_bits()` gives the u32 in network byte order (big-endian).
    // On little-endian hosts the kernel stores it byte-reversed.
    let be_bytes = ip.to_bits().to_be_bytes(); // [a, b, c, d]
    // Reverse to get little-endian host order.
    let le_u32 = u32::from_le_bytes(be_bytes);
    format!("{le_u32:08X}")
}

/// Encode an IPv6 address as the 32-character uppercase hex string used in
/// `/proc/net/tcp6`.
///
/// The kernel stores IPv6 addresses as four 32-bit words in host byte order.
/// On little-endian x86, each 4-byte group is byte-reversed compared to
/// network order.
fn ipv6_to_proc_hex(ip: std::net::Ipv6Addr) -> String {
    let octets = ip.octets(); // 16 bytes in network order
    let mut result = String::with_capacity(32);
    // Process in 4-byte groups, byte-reversing each group for little-endian.
    for chunk in octets.chunks(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        use std::fmt::Write;
        let _ = write!(result, "{word:08X}");
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // --- Hex addr encoding ---

    #[test]
    fn test_hex_addr_encoding_loopback() {
        // 127.0.0.1 → 0x0100007F on little-endian x86
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(ipv4_to_proc_hex(ip), "0100007F");
    }

    #[test]
    fn test_hex_addr_encoding_all_zeros() {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        assert_eq!(ipv4_to_proc_hex(ip), "00000000");
    }

    #[test]
    fn test_hex_addr_encoding_192_168_1_1() {
        // 192.168.1.1 = 0xC0A80101 in network order
        // reversed bytes: 01 01 A8 C0 = 0x0101A8C0
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(ipv4_to_proc_hex(ip), "0101A8C0");
    }

    // --- parse_proc_net_tcp ---

    const SAMPLE_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                               0: 0100007F:4E24 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n\
                               1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn test_parse_proc_net_tcp_finds_matching_entry() {
        // Port 0x4E24 = 19988 decimal
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0x4E24);
        let inode = parse_proc_net_tcp(SAMPLE_TCP, addr).expect("should find entry");
        assert_eq!(inode, 12345);
    }

    #[test]
    fn test_parse_proc_net_tcp_no_match() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
        let err = parse_proc_net_tcp(SAMPLE_TCP, addr).expect_err("no match must return error");
        assert!(matches!(err, ProxyError::AuthFailed(_)));
    }

    #[test]
    fn test_parse_proc_net_tcp_second_entry() {
        // Port 0x1F90 = 8080 decimal
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0x1F90);
        let inode = parse_proc_net_tcp(SAMPLE_TCP, addr).expect("should find second entry");
        assert_eq!(inode, 67890);
    }

    // --- IPv6 support ---

    // Sample /proc/net/tcp6 content. ::1 in proc format is
    // 00000000000000000000000001000000 (four 32-bit LE words).
    const SAMPLE_TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                               0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn test_parse_proc_net_tcp6_loopback() {
        let addr: SocketAddr = "[::1]:8080".parse().expect("valid addr");
        let inode = parse_proc_net_tcp(SAMPLE_TCP6, addr).expect("should find IPv6 entry");
        assert_eq!(inode, 55555);
    }

    #[test]
    fn test_parse_proc_net_tcp6_no_match_in_v4_data() {
        // IPv6 address should not match IPv4 /proc/net/tcp data.
        let addr: SocketAddr = "[::1]:8080".parse().expect("valid addr");
        let err = parse_proc_net_tcp(SAMPLE_TCP, addr).expect_err("IPv6 in v4 data should fail");
        assert!(matches!(err, ProxyError::AuthFailed(_)));
    }

    #[test]
    fn test_ipv6_to_proc_hex_loopback() {
        let ip: std::net::Ipv6Addr = "::1".parse().expect("valid");
        assert_eq!(ipv6_to_proc_hex(ip), "00000000000000000000000001000000");
    }

    // --- hex_to_bytes ---

    #[test]
    fn test_hex_to_bytes_valid() {
        let bytes = hex_to_bytes("deadbeef").expect("valid hex");
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_to_bytes_empty() {
        let bytes = hex_to_bytes("").expect("empty is valid");
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_hex_to_bytes_odd_length() {
        assert!(hex_to_bytes("abc").is_none());
    }

    #[test]
    fn test_hex_to_bytes_invalid_char() {
        assert!(hex_to_bytes("gggg").is_none());
    }

    // --- authenticate: missing headers ---

    #[tokio::test]
    async fn test_authenticate_missing_lease_token_header() {
        let lease = make_test_lease();
        let lease_id = lease.lease_id.clone();

        let headers = http::HeaderMap::new(); // no headers at all
        let addr: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");

        let err = authenticate(addr, &headers, &lease_id, &lease, b"gate-key")
            .await
            .expect_err("missing header must fail");
        assert!(matches!(err, ProxyError::AuthFailed(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("X-CDP-Lease-Token"),
            "error must name the missing header"
        );
    }

    #[tokio::test]
    async fn test_authenticate_missing_channel_binding_header() {
        let lease = make_test_lease();
        let lease_id = lease.lease_id.clone();
        let gate_key = b"test-gate-key";

        let token = cdp_crypto::generate_lease_token(
            gate_key,
            lease_id.as_str(),
            &lease.agent_fingerprint_hash,
            &lease.channel_binding_nonce,
        );

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_LEASE_TOKEN),
            token.parse().expect("valid header value"),
        );
        // No channel binding header.

        let addr: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");
        let err = authenticate(addr, &headers, &lease_id, &lease, gate_key)
            .await
            .expect_err("missing CB header must fail");
        assert!(matches!(err, ProxyError::AuthFailed(_)));
    }

    #[tokio::test]
    async fn test_authenticate_bad_lease_token() {
        let lease = make_test_lease();
        let lease_id = lease.lease_id.clone();
        let gate_key = b"test-gate-key";

        // Nonce as hex for channel binding.
        let cb_hex = bytes_to_hex(&lease.channel_binding_nonce);

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_LEASE_TOKEN),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .parse()
                .expect("valid header value"),
        );
        headers.insert(
            http::header::HeaderName::from_static(HEADER_CHANNEL_BINDING),
            cb_hex.parse().expect("valid header value"),
        );

        let addr: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");
        let err = authenticate(addr, &headers, &lease_id, &lease, gate_key)
            .await
            .expect_err("bad token must fail");
        assert!(matches!(err, ProxyError::AuthFailed(_)));
        assert!(err.to_string().contains("lease token verification failed"));
    }

    #[tokio::test]
    async fn test_authenticate_bad_channel_binding() {
        let lease = make_test_lease();
        let lease_id = lease.lease_id.clone();
        let gate_key = b"test-gate-key";

        let token = cdp_crypto::generate_lease_token(
            gate_key,
            lease_id.as_str(),
            &lease.agent_fingerprint_hash,
            &lease.channel_binding_nonce,
        );

        // Wrong nonce (all zeros instead of the real one).
        let wrong_nonce = [0u8; 32];
        let cb_hex = bytes_to_hex(&wrong_nonce);

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::HeaderName::from_static(HEADER_LEASE_TOKEN),
            token.parse().expect("valid header value"),
        );
        headers.insert(
            http::header::HeaderName::from_static(HEADER_CHANNEL_BINDING),
            cb_hex.parse().expect("valid header value"),
        );

        let addr: SocketAddr = "127.0.0.1:12345".parse().expect("valid addr");
        let err = authenticate(addr, &headers, &lease_id, &lease, gate_key)
            .await
            .expect_err("bad channel binding must fail");
        assert!(matches!(err, ProxyError::AuthFailed(_)));
        assert!(err.to_string().contains("channel binding nonce mismatch"));
    }

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    fn make_test_lease() -> Lease {
        use cdp_lease::LeaseId;
        use cdp_policy::Scope;
        use chrono::Utc;
        use std::collections::HashMap;

        Lease {
            lease_id: LeaseId::generate(),
            credential_ref: "cred-001".to_string(),
            policy_name: "test-policy".to_string(),
            approval_method: "auto".to_string(),
            agent_fingerprint_hash: [0xab; 32],
            agent_binary_path: "/usr/bin/agent".to_string(),
            agent_uid: 1000,
            agent_pid: 42,
            granted_scope: Scope::default(),
            lease_token: "placeholder".to_string(),
            channel_binding_nonce: [0xcd; 32],
            dns_pinned_ips: HashMap::new(),
            status: cdp_lease::LeaseStatus::Active,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ttl_seconds: 3600,
            cumulative_ttl_seconds: 3600,
            max_requests: None,
            requests_used: 0,
            renewals_used: 0,
            max_renewals: 3,
            max_cumulative_ttl_seconds: 14400,
            renewable: true,
            parent_lease_id: None,
            child_lease_ids: Vec::new(),
            delegation_depth: 0,
            delegation_allowed: false,
            delegation_max_depth: None,
            follow_redirects: false,
        }
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").expect("infallible");
            s
        })
    }
}
