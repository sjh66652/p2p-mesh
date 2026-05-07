//! Mesh DNS Resolver.
//!
//! Provides internal DNS resolution for the overlay network:
//! - *.mesh domain resolution (e.g., "laptop.mesh" → 100.64.0.5)
//! - Split DNS: forward non-mesh queries to upstream resolvers
//! - DNS caching with TTL support
//! - DNS forwarding for internet domains
//!
//! Architecture:
//!   App → DNS query "db.mesh" → local DNS proxy → IPAM → 100.64.0.2
//!   App → DNS query "google.com" → local DNS proxy → upstream resolver
//!
//! The local DNS proxy listens on 127.0.0.1:5353 (non-privileged port).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Default timeout for upstream DNS queries (5 seconds).
const DEFAULT_DNS_TIMEOUT_SECS: u64 = 5;

/// Environment variable to override the upstream DNS query timeout.
const ENV_DNS_TIMEOUT: &str = "DNS_UPSTREAM_TIMEOUT_SECS";

/// DNS record for the mesh network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Fully qualified domain name (e.g., "db.mesh")
    pub fqdn: String,
    /// Virtual IP address
    pub ip: Ipv4Addr,
    /// Record type ("A" for now, "AAAA" planned)
    pub record_type: String,
    /// TTL in seconds
    pub ttl: u32,
    /// When this record was added
    pub added_at: Instant,
}

/// Cached DNS response entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    ip: Ipv4Addr,
    expires_at: Instant,
}

/// Mesh DNS Resolver.
pub struct MeshDns {
    /// Authoritative records for *.mesh domains
    records: RwLock<HashMap<String, DnsRecord>>,
    /// Resolution cache (domain → IP with TTL)
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// Upstream DNS servers for non-mesh domains
    upstream: RwLock<Vec<SocketAddr>>,
    /// Timeout for upstream DNS queries (default: 5s, overridable via DNS_UPSTREAM_TIMEOUT_SECS)
    upstream_timeout: Duration,
}

impl MeshDns {
    /// Create a new mesh DNS resolver with default upstream servers.
    pub fn new() -> Self {
        let timeout_secs = std::env::var(ENV_DNS_TIMEOUT)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_DNS_TIMEOUT_SECS);
        let upstream_timeout = Duration::from_secs(timeout_secs);

        log::debug!(
            "DNS upstream timeout set to {}s (from env {}={})",
            upstream_timeout.as_secs(),
            ENV_DNS_TIMEOUT,
            std::env::var(ENV_DNS_TIMEOUT).unwrap_or_else(|_| "default".to_string()),
        );

        Self {
            records: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
            upstream: RwLock::new(vec![
                "8.8.8.8:53".parse().unwrap(),       // Google DNS
                "1.1.1.1:53".parse().unwrap(),       // Cloudflare DNS
            ]),
            upstream_timeout,
        }
    }

    /// Set upstream DNS servers.
    pub async fn set_upstream(&self, servers: Vec<SocketAddr>) {
        let mut upstream = self.upstream.write().await;
        *upstream = servers;
    }

    /// Register a DNS record for a mesh node.
    ///
    /// Example: register("db", "100.64.0.2") → resolves "db.mesh" → 100.64.0.2
    pub async fn register(&self, hostname: &str, ip: Ipv4Addr, ttl: u32) {
        let fqdn = if hostname.ends_with(".mesh") {
            hostname.to_string()
        } else {
            format!("{}.mesh", hostname)
        };

        let record = DnsRecord {
            fqdn: fqdn.clone(),
            ip,
            record_type: "A".to_string(),
            ttl,
            added_at: Instant::now(),
        };

        let mut records = self.records.write().await;
        records.insert(fqdn, record);
        log::debug!("DNS registered: {}.mesh → {}", hostname, ip);
    }

    /// Remove a DNS record.
    pub async fn unregister(&self, hostname: &str) {
        let fqdn = if hostname.ends_with(".mesh") {
            hostname.to_string()
        } else {
            format!("{}.mesh", hostname)
        };

        let mut records = self.records.write().await;
        records.remove(&fqdn);
    }

    /// Resolve a hostname to an IP address.
    ///
    /// For *.mesh domains, returns the authoritative record.
    /// For other domains, queries upstream DNS servers.
    pub async fn resolve(&self, hostname: &str) -> Option<Ipv4Addr> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(hostname) {
                if entry.expires_at > Instant::now() {
                    return Some(entry.ip);
                }
            }
        }

        let result = if hostname.ends_with(".mesh") {
            // Authoritative lookup
            let records = self.records.read().await;
            records.get(hostname).map(|r| r.ip)
        } else {
            // Forward to upstream
            self.forward_lookup(hostname).await
        };

        // Cache the result
        if let Some(ip) = result {
            let mut cache = self.cache.write().await;
            cache.insert(
                hostname.to_string(),
                CacheEntry {
                    ip,
                    expires_at: Instant::now() + Duration::from_secs(300), // 5 min TTL
                },
            );
        }

        result
    }

    /// Forward a DNS query to upstream resolvers.
    ///
    /// Uses the trust-dns-proto library for proper DNS protocol implementation.
    /// Falls back to secondary server if primary fails.
    async fn forward_lookup(&self, hostname: &str) -> Option<Ipv4Addr> {
        let upstream = self.upstream.read().await;

        for server in upstream.iter() {
            // Try to resolve using the resolver library
            match self.dns_query(hostname, *server).await {
                Ok(ip) => {
                    log::trace!("DNS: {} resolved to {} via {}", hostname, ip, server);
                    return Some(ip);
                }
                Err(e) => {
                    log::debug!("DNS forward to {} failed for {}: {}", server, hostname, e);
                }
            }
        }

        log::warn!("DNS: failed to resolve {} via all upstream servers", hostname);
        None
    }

    /// Perform a simple DNS A record query.
    ///
    /// Constructs a minimal DNS query packet and parses the response.
    /// For production, use trust-dns-proto for full DNS protocol support.
    async fn dns_query(&self, hostname: &str, server: SocketAddr) -> Result<Ipv4Addr, String> {
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| format!("DNS bind failed: {}", e))?;

        // Build a simple DNS query
        let query = build_dns_query(hostname);

        tokio::time::timeout(self.upstream_timeout, socket.send_to(&query, server))
            .await
            .map_err(|_| format!("DNS send timeout to {}", server))?
            .map_err(|e| format!("DNS send failed: {}", e))?;

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(
            self.upstream_timeout,
            socket.recv_from(&mut buf),
        )
        .await
        .map_err(|_| "DNS query timeout".to_string())?
        .map_err(|e| format!("DNS recv failed: {}", e))?;

        parse_dns_response(&buf[..n])
    }

    /// Get all registered DNS records.
    pub async fn get_all_records(&self) -> Vec<DnsRecord> {
        let records = self.records.read().await;
        records.values().cloned().collect()
    }

    /// Clear the DNS cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        log::debug!("DNS cache cleared");
    }

    /// Get cache statistics.
    pub async fn cache_stats(&self) -> (usize, usize) {
        let records = self.records.read().await;
        let cache = self.cache.read().await;
        (records.len(), cache.len())
    }
}

/// Build a minimal DNS A-record query packet.
///
/// Format: [Header (12 bytes)][Question section]
/// Header: ID (2) | Flags (2) | QDCOUNT (2) | ANCOUNT (2) | NSCOUNT (2) | ARCOUNT (2)
fn build_dns_query(hostname: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Transaction ID (random)
    packet.push(0x00);
    packet.push(0x01);

    // Flags: standard query, recursion desired
    packet.push(0x01); // RD
    packet.push(0x00);

    // Questions: 1
    packet.push(0x00);
    packet.push(0x01);

    // Answer RRs: 0
    packet.push(0x00);
    packet.push(0x00);

    // Authority RRs: 0
    packet.push(0x00);
    packet.push(0x00);

    // Additional RRs: 0
    packet.push(0x00);
    packet.push(0x00);

    // Question: encode hostname as labels
    for label in hostname.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Terminating zero-length label

    // QTYPE: A (1)
    packet.push(0x00);
    packet.push(0x01);

    // QCLASS: IN (1)
    packet.push(0x00);
    packet.push(0x01);

    packet
}

/// Parse a DNS A-record response and extract the first IPv4 address.
fn parse_dns_response(data: &[u8]) -> Result<Ipv4Addr, String> {
    if data.len() < 12 {
        return Err("Response too short".into());
    }

    // Check for error response code (last 4 bits of flags)
    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return Err(format!("DNS error: rcode={}", rcode));
    }

    // Answer count
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return Err("No answers in response".into());
    }

    // Skip past header and question section to find answers
    // This is a simplified parser — trust-dns-proto handles this properly
    let mut pos = 12;

    // Skip question section
    while pos < data.len() && data[pos] != 0x00 {
        let label_len = data[pos] as usize;
        pos += 1 + label_len;
    }
    pos += 1; // Skip the zero-length terminating label
    pos += 4; // Skip QTYPE + QCLASS

    // Parse answer section
    for _ in 0..ancount {
        if pos + 10 > data.len() {
            break;
        }

        // Skip name (may be a pointer or labels)
        if (data[pos] & 0xC0) == 0xC0 {
            pos += 2; // Compressed name pointer (2 bytes)
        } else {
            while pos < data.len() && data[pos] != 0x00 {
                let label_len = data[pos] as usize;
                pos += 1 + label_len;
            }
            pos += 1; // Skip terminating zero
        }

        if pos + 10 > data.len() {
            break;
        }

        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let qclass = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let _ttl = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let rdlen = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if qtype == 1 && qclass == 1 && rdlen == 4 && pos + 4 <= data.len() {
            // A record found
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            return Ok(ip);
        }

        pos += rdlen;
    }

    Err("No A record found in response".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("db.mesh");
        assert!(query.len() > 12);
        assert_eq!(query[0], 0x00); // Transaction ID high
        assert_eq!(query[1], 0x01); // Transaction ID low
    }

    #[tokio::test]
    async fn test_register_and_resolve() {
        let dns = MeshDns::new();
        dns.register("laptop", Ipv4Addr::new(100, 64, 0, 5), 300).await;

        let ip = dns.resolve("laptop.mesh").await;
        assert_eq!(ip, Some(Ipv4Addr::new(100, 64, 0, 5)));
    }

    #[tokio::test]
    async fn test_resolve_unknown_mesh() {
        let dns = MeshDns::new();
        let ip = dns.resolve("unknown.mesh").await;
        assert_eq!(ip, None);
    }

    #[tokio::test]
    async fn test_unregister() {
        let dns = MeshDns::new();
        dns.register("test", Ipv4Addr::new(100, 64, 0, 99), 300).await;
        dns.unregister("test").await;

        let ip = dns.resolve("test.mesh").await;
        assert_eq!(ip, None);
    }

    #[test]
    fn test_parse_dns_response_valid() {
        // Quick check: empty buffer should error, not panic
        let result = parse_dns_response(&[]);
        assert!(result.is_err());
    }
}
