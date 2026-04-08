//! DNS pinning — resolve and lock hostnames at lease creation time.
//!
//! The CDP proxy must only connect to the IPs that were pinned at the moment
//! the lease was granted.  This prevents DNS rebinding attacks where an
//! attacker changes DNS records after the proxy has validated the target host.

use std::{collections::HashMap, net::IpAddr};

use crate::LeaseError;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolve `hosts` to IP addresses and return the pinned mapping.
///
/// Every entry in `hosts` is resolved via the system resolver.  If any host
/// fails to resolve, the entire operation fails with [`LeaseError::DnsResolution`]
/// so that leases are never created with incomplete DNS state.
///
/// The port `:0` is appended to each hostname to satisfy
/// [`tokio::net::lookup_host`]'s `ToSocketAddrs` requirement; the port is
/// stripped from the returned addresses.
pub async fn pin_dns(hosts: &[String]) -> Result<HashMap<String, Vec<IpAddr>>, LeaseError> {
    let mut pinned: HashMap<String, Vec<IpAddr>> = HashMap::with_capacity(hosts.len());

    for host in hosts {
        let addr_str = format!("{host}:0");
        let resolved =
            tokio::net::lookup_host(addr_str)
                .await
                .map_err(|e| LeaseError::DnsResolution {
                    host: host.clone(),
                    reason: e.to_string(),
                })?;

        let ips: Vec<IpAddr> = resolved.map(|sa| sa.ip()).collect();

        if ips.is_empty() {
            return Err(LeaseError::DnsResolution {
                host: host.clone(),
                reason: "no addresses returned".to_string(),
            });
        }

        pinned.insert(host.clone(), ips);
    }

    Ok(pinned)
}

/// Return `true` if `resolved_ip` is in the pinned set for `host`.
///
/// Returns `false` when:
/// - `host` is not present in the pinned map (unrecognised target), or
/// - `resolved_ip` is not one of the pinned addresses for that host.
pub fn verify_dns(pinned: &HashMap<String, Vec<IpAddr>>, host: &str, resolved_ip: IpAddr) -> bool {
    match pinned.get(host) {
        Some(ips) => ips.contains(&resolved_ip),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_pin_dns_localhost() {
        let hosts = vec!["localhost".to_string()];
        let result = pin_dns(&hosts).await;
        assert!(
            result.is_ok(),
            "expected localhost to resolve, got: {result:?}"
        );
        let pinned = result.unwrap();
        assert!(pinned.contains_key("localhost"));
        assert!(!pinned["localhost"].is_empty());
    }

    #[tokio::test]
    async fn test_verify_dns_matching_ip() {
        let hosts = vec!["localhost".to_string()];
        let pinned = pin_dns(&hosts).await.expect("localhost must resolve");
        // localhost resolves to 127.0.0.1 on all standard systems.
        let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(verify_dns(&pinned, "localhost", loopback));
    }

    #[tokio::test]
    async fn test_verify_dns_non_matching_ip() {
        let hosts = vec!["localhost".to_string()];
        let pinned = pin_dns(&hosts).await.expect("localhost must resolve");
        let google_dns = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!verify_dns(&pinned, "localhost", google_dns));
    }

    #[test]
    fn test_verify_dns_unknown_host() {
        let pinned: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!verify_dns(&pinned, "not-pinned.example.com", ip));
    }

    #[tokio::test]
    async fn test_pin_dns_unknown_host_fails() {
        let hosts = vec!["this.host.definitely.does.not.exist.invalid".to_string()];
        let result = pin_dns(&hosts).await;
        assert!(
            matches!(result, Err(LeaseError::DnsResolution { .. })),
            "expected DnsResolution error, got: {result:?}"
        );
    }
}
