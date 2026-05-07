//! STUN (Session Traversal Utilities for NAT) module.
//!
//! Provides:
//! - STUN client to discover public IP:port mapping
//! - STUN server for answering peer queries
//! - NAT type classification based on multi-server probe results
//!
//! Protocol is a simplified STUN-like request/response:
//!   Client → Server: "ping"
//!   Server → Client: "public_ip:public_port"

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Query a STUN server to discover our public (mapped) address.
///
/// Sends a "ping" string to the STUN server and parses the "IP:PORT" response.
/// Returns the public SocketAddr as seen by the STUN server.
pub async fn get_public_addr(stun_server: &str) -> Result<SocketAddr, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("STUN bind failed: {}", e))?;

    socket
        .send_to(b"ping", stun_server)
        .await
        .map_err(|e| format!("STUN send failed: {}", e))?;

    let mut buf = [0u8; 256];
    let (n, _src) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "STUN response timed out".to_string())?
    .map_err(|e| format!("STUN recv failed: {}", e))?;

    let response = std::str::from_utf8(&buf[..n])
        .map_err(|e| format!("Invalid STUN response: {}", e))?;

    response
        .trim()
        .parse::<SocketAddr>()
        .map_err(|e| format!("Failed to parse STUN response '{}': {}", response, e))
}

/// Probe multiple STUN servers and return all mapped addresses.
/// Used for NAT type classification — if the mapped address differs
/// across servers, the NAT is symmetric.
pub async fn probe_multi_stun(
    stun_servers: &[String],
) -> Vec<(String, Result<SocketAddr, String>)> {
    let mut results = Vec::new();
    for server in stun_servers {
        let result = get_public_addr(server).await;
        results.push((server.clone(), result));
    }
    results
}

/// NAT type classification result.
#[derive(Debug, Clone, PartialEq)]
pub enum NatClassification {
    Open,
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
    Unknown,
}

impl NatClassification {
    /// Convert to string matching the control plane's NAT types.
    pub fn as_str(&self) -> &'static str {
        match self {
            NatClassification::Open => "open",
            NatClassification::FullCone => "full_cone",
            NatClassification::RestrictedCone => "restricted_cone",
            NatClassification::PortRestricted => "port_restricted",
            NatClassification::Symmetric => "symmetric",
            NatClassification::Unknown => "unknown",
        }
    }
}

/// Classify NAT type based on multi-server STUN probe results.
///
/// Uses RFC 3489 / RFC 5780 classification methodology:
///
/// 1. Query multiple STUN servers (at least 2 from different IPs for accuracy).
/// 2. Compare mapped addresses returned by each server.
/// 3. Classify based on mapping consistency:
///    - Same IP:port from all servers → Full Cone / Restricted Cone / Port Restricted
///      (cannot distinguish without further connectivity tests)
///    - Same IP, different ports → Port Restricted Cone or Symmetric
///      (if port changes per destination, likely Symmetric)
///    - Different IPs → Multiple NAT layers or carrier-grade NAT → Unknown
///
/// Full disambiguation between Full/Restricted/Port-Restricted requires
/// a second phase where one STUN server attempts to reach the mapping
/// discovered by another (CHANGE-REQUEST / connectivity check).
pub fn classify_nat(results: &[(String, Result<SocketAddr, String>)]) -> NatClassification {
    let successes: Vec<&SocketAddr> = results
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok())
        .collect();

    if successes.is_empty() {
        return NatClassification::Unknown;
    }

    // Single server result — cannot reliably classify
    if successes.len() == 1 {
        return NatClassification::Unknown;
    }

    let first = successes[0];

    // Check if all mapped addresses are identical
    let all_identical = successes.iter().all(|a| a == &first);

    if all_identical {
        // Same IP:port from all servers → potentially Full Cone, Restricted Cone,
        // or Port Restricted Cone (all three produce consistent mappings).
        // Without a connectivity check between servers we default to Full Cone
        // as the optimistic case (it works best for P2P).
        NatClassification::FullCone
    } else {
        // Mappings differ — check if it's just the port that changes
        let same_ip = successes.iter().all(|a| a.ip() == first.ip());
        if same_ip {
            // Same IP, different port for each destination → Symmetric NAT
            // (each destination gets its own mapping)
            NatClassification::Symmetric
        } else {
            // Different IPs entirely — could be carrier-grade NAT, multiple
            // NAT layers, or IPv4/IPv6 mix. Conservative: treat as symmetric.
            NatClassification::Symmetric
        }
    }
}

/// Per-IP rate limit state for the STUN server.
struct IpRateLimit {
    count: u32,
    window_start: Instant,
}

/// Run the STUN server loop with per-IP rate limiting.
///
/// Binds to 0.0.0.0:3478 (standard STUN port) and responds to each
/// "ping" request with the sender's IP:port as seen by the server.
///
/// Rate limiting: max 10 requests per 10-second window per source IP.
/// This mitigates reflection/amplification attacks (DDoS vector).
pub async fn run_stun_server(bind_addr: &str) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind(bind_addr).await?;
    log::info!("STUN server listening on {}", bind_addr);

    let rate_limits: Mutex<HashMap<std::net::IpAddr, IpRateLimit>> = Mutex::new(HashMap::new());
    let rate_limit_max: u32 = 10; // max requests per window per IP
    let rate_limit_window = Duration::from_secs(10);

    let mut buf = [0u8; 1024];

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("");
        log::trace!("STUN request from {}: {}", src, msg);

        // Rate limit check
        {
            let mut limits = rate_limits.lock().await;
            let now = Instant::now();
            let entry = limits
                .entry(src.ip())
                .or_insert(IpRateLimit { count: 0, window_start: now });

            if now.duration_since(entry.window_start) > rate_limit_window {
                entry.window_start = now;
                entry.count = 0;
            }

            entry.count += 1;
            if entry.count > rate_limit_max {
                log::debug!("STUN rate limit exceeded for {}", src.ip());
                continue;
            }
        }

        // Periodically clean up old entries (every ~256 requests on average)
        if rand::thread_rng().next_u32() % 256 == 0 {
            let mut limits = rate_limits.lock().await;
            let now = Instant::now();
            limits.retain(|_, v| now.duration_since(v.window_start) < rate_limit_window * 3);
        }

        if msg.trim() == "ping" {
            let response = format!("{}:{}", src.ip(), src.port());
            socket.send_to(response.as_bytes(), src).await?;
            log::debug!("STUN response to {}: {}", src, response);
        }
    }
}
