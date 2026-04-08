//! DNS pin verification for outbound proxy connections.
//!
//! At lease creation time the gate resolves all allowed hostnames and records
//! the resulting IP addresses in [`Lease::dns_pinned_ips`].  Before the proxy
//! opens a connection to any upstream host it must verify that the resolved IP
//! is still in the pinned set, preventing DNS rebinding attacks.

use std::net::IpAddr;

use cdp_lease::Lease;

use crate::ProxyError;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify that `resolved_ip` is in the DNS pin set recorded for `host` in
/// the given `lease`.
///
/// # Errors
///
/// Returns [`ProxyError::DnsPinMismatch`] when the resolved IP is not in the
/// pinned set, or when `host` was never pinned (i.e. not present in
/// `lease.dns_pinned_ips`).
pub fn verify_pinned_ip(
    lease: &Lease,
    host: &str,
    resolved_ip: IpAddr,
) -> Result<(), ProxyError> {
    match lease.dns_pinned_ips.get(host) {
        Some(pinned_ips) if pinned_ips.contains(&resolved_ip) => Ok(()),
        Some(pinned_ips) => Err(ProxyError::DnsPinMismatch {
            host: host.to_string(),
            resolved: resolved_ip,
            pinned: pinned_ips.clone(),
        }),
        None => Err(ProxyError::DnsPinMismatch {
            host: host.to_string(),
            resolved: resolved_ip,
            pinned: vec![],
        }),
    }
}

/// Resolve `host` to its IP address(es) and verify each against the lease pin.
///
/// The DNS lookup is performed via the system resolver (same resolver that
/// was used at lease creation time).  All resolved addresses must be in the
/// pinned set; if any is not, the connection is rejected.
///
/// In practice a hostname should resolve to the same set of IPs as it did at
/// lease creation time, since DNS TTLs are short and we re-verify on every
/// connection attempt.
pub async fn resolve_and_verify(
    lease: &Lease,
    host: &str,
) -> Result<Vec<IpAddr>, ProxyError> {
    // Append `:0` to satisfy `lookup_host`'s socket-address requirement.
    let addr_str = format!("{host}:0");
    let resolved_addrs = tokio::net::lookup_host(addr_str)
        .await
        .map_err(|e| ProxyError::Upstream(format!("DNS resolution failed for {host}: {e}")))?;

    let ips: Vec<IpAddr> = resolved_addrs.map(|sa| sa.ip()).collect();

    if ips.is_empty() {
        return Err(ProxyError::Upstream(format!(
            "DNS resolution for {host} returned no addresses"
        )));
    }

    // Every resolved IP must be in the pinned set.
    for ip in &ips {
        verify_pinned_ip(lease, host, *ip)?;
    }

    Ok(ips)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_lease_with_pins(pins: HashMap<String, Vec<IpAddr>>) -> Lease {
        use cdp_lease::{LeaseId, LeaseStatus};
        use cdp_policy::Scope;
        use chrono::Utc;

        Lease {
            lease_id: LeaseId::generate(),
            credential_ref: "cred-001".to_string(),
            policy_name: "test-policy".to_string(),
            approval_method: "auto".to_string(),
            agent_fingerprint_hash: [0u8; 32],
            agent_binary_path: "/usr/bin/agent".to_string(),
            agent_uid: 1000,
            agent_pid: 42,
            granted_scope: Scope::default(),
            lease_token: "tok".to_string(),
            channel_binding_nonce: [0u8; 32],
            dns_pinned_ips: pins,
            status: LeaseStatus::Active,
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

    #[test]
    fn test_verify_pinned_ip_match() {
        let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut pins = HashMap::new();
        pins.insert("api.example.com".to_string(), vec![loopback]);
        let lease = make_lease_with_pins(pins);

        verify_pinned_ip(&lease, "api.example.com", loopback)
            .expect("matching pinned IP must pass");
    }

    #[test]
    fn test_verify_pinned_ip_mismatch() {
        let pinned = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let resolved = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let mut pins = HashMap::new();
        pins.insert("api.example.com".to_string(), vec![pinned]);
        let lease = make_lease_with_pins(pins);

        let err = verify_pinned_ip(&lease, "api.example.com", resolved)
            .expect_err("mismatched IP must fail");
        match err {
            ProxyError::DnsPinMismatch { host, resolved: r, pinned: p } => {
                assert_eq!(host, "api.example.com");
                assert_eq!(r, resolved);
                assert_eq!(p, vec![pinned]);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_verify_pinned_ip_unknown_host() {
        let lease = make_lease_with_pins(HashMap::new());
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let err = verify_pinned_ip(&lease, "unknown.example.com", ip)
            .expect_err("unknown host must fail");
        match err {
            ProxyError::DnsPinMismatch { host, pinned, .. } => {
                assert_eq!(host, "unknown.example.com");
                assert!(pinned.is_empty());
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_verify_pinned_ip_multiple_allowed_ips() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut pins = HashMap::new();
        pins.insert("api.example.com".to_string(), vec![ip1, ip2]);
        let lease = make_lease_with_pins(pins);

        verify_pinned_ip(&lease, "api.example.com", ip1)
            .expect("first pinned IP must pass");
        verify_pinned_ip(&lease, "api.example.com", ip2)
            .expect("second pinned IP must pass");
    }

    #[tokio::test]
    async fn test_resolve_and_verify_localhost() {
        let mut pins = HashMap::new();
        // Resolve localhost first to get its actual IP.
        let resolved: Vec<IpAddr> = tokio::net::lookup_host("localhost:0")
            .await
            .expect("localhost must resolve")
            .map(|sa| sa.ip())
            .collect();
        assert!(!resolved.is_empty());
        pins.insert("localhost".to_string(), resolved);
        let lease = make_lease_with_pins(pins);

        let ips = resolve_and_verify(&lease, "localhost")
            .await
            .expect("localhost must verify against its own pinned IPs");
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_and_verify_pin_mismatch() {
        // Pin a wrong IP so that verification always fails.
        let wrong_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let mut pins = HashMap::new();
        pins.insert("localhost".to_string(), vec![wrong_ip]);
        let lease = make_lease_with_pins(pins);

        let err = resolve_and_verify(&lease, "localhost")
            .await
            .expect_err("wrong pin must cause error");
        assert!(matches!(err, ProxyError::DnsPinMismatch { .. }));
    }
}
