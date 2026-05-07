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

use std::net::SocketAddr;
use tokio::net::UdpSocket;

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
/// Logic:
/// - If all servers return the same IP:port → Full Cone or Open
/// - If same IP but different port → Symmetric
/// - Additional classification requires connectivity checks
pub fn classify_nat(results: &[(String, Result<SocketAddr, String>)]) -> NatClassification {
    let addrs: Vec<SocketAddr> = results
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok().copied())
        .collect();

    if addrs.is_empty() {
        return NatClassification::Unknown;
    }

    if addrs.len() == 1 {
        return NatClassification::FullCone;
    }

    // Check if all mapped addresses are the same
    let first = addrs[0];
    let all_same = addrs.iter().all(|a| a == &first);

    if all_same {
        NatClassification::FullCone
    } else {
        // Different ports → likely symmetric
        let same_ip = addrs.iter().all(|a| a.ip() == first.ip());
        if same_ip {
            NatClassification::Symmetric
        } else {
            NatClassification::Unknown
        }
    }
}

/// Run the STUN server loop.
///
/// Binds to 0.0.0.0:3478 (standard STUN port) and responds to each
/// "ping" request with the sender's IP:port as seen by the server.
pub async fn run_stun_server(bind_addr: &str) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind(bind_addr).await?;
    log::info!("STUN server listening on {}", bind_addr);

    let mut buf = [0u8; 1024];

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("");
        log::trace!("STUN request from {}: {}", src, msg);

        if msg.trim() == "ping" {
            let response = format!("{}:{}", src.ip(), src.port());
            socket.send_to(response.as_bytes(), src).await?;
            log::debug!("STUN response to {}: {}", src, response);
        }
    }
}
