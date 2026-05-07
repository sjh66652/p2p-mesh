//! P2P tunnel module - establishes and manages direct peer-to-peer connections.
//!
//! Handles:
//! - UDP hole punching for NAT traversal
//! - Session key negotiation
//! - Encrypted data channel management
//! - Traffic statistics collection for billing

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::crypto::{self, SessionKey};
use crate::puncher;
use crate::stun;
use crate::multipath::{MultiPathManager, PathType};

/// Represents an active P2P tunnel to a peer.
pub struct P2PTunnel {
    /// Peer's socket address (after hole punching)
    pub peer_addr: SocketAddr,
    /// Session encryption key
    pub session_key: SessionKey,
    /// Bytes sent through this tunnel
    pub bytes_sent: u64,
    /// Bytes received through this tunnel
    pub bytes_received: u64,
}

impl P2PTunnel {
    /// Create a new encrypted P2P tunnel.
    pub fn new(peer_addr: SocketAddr, session_key: SessionKey) -> Self {
        Self {
            peer_addr,
            session_key,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Encrypt and prepare data for sending through the tunnel.
    pub fn encapsulate(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let encrypted = crypto::encrypt(&self.session_key, plaintext);
        self.bytes_sent += plaintext.len() as u64;
        encrypted
    }

    /// Decrypt data received from the tunnel.
    /// Returns None if decryption/authentication fails.
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let plaintext = crypto::decrypt(&self.session_key, ciphertext)?;
        self.bytes_received += plaintext.len() as u64;
        Some(plaintext)
    }
}

/// Manages all active P2P tunnels for this node.
pub struct TunnelManager {
    /// device_id -> P2PTunnel
    tunnels: HashMap<String, Arc<Mutex<P2PTunnel>>>,
    /// Local UDP socket for peer communication
    socket: Arc<UdpSocket>,
}

impl TunnelManager {
    /// Create a new tunnel manager bound to the given socket.
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            tunnels: HashMap::new(),
            socket,
        }
    }

    /// Register a new P2P tunnel with a peer.
    pub fn add_tunnel(
        &mut self,
        device_id: String,
        peer_addr: SocketAddr,
        session_key: SessionKey,
    ) {
        let tunnel = P2PTunnel::new(peer_addr, session_key);
        self.tunnels
            .insert(device_id, Arc::new(Mutex::new(tunnel)));
    }

    /// Remove a tunnel (peer disconnected).
    pub fn remove_tunnel(&mut self, device_id: &str) {
        self.tunnels.remove(device_id);
    }

    /// Send encrypted data to a peer.
    pub async fn send_to(&self, device_id: &str, data: &[u8]) -> Result<usize, String> {
        let tunnel_arc = self
            .tunnels
            .get(device_id)
            .ok_or_else(|| format!("No tunnel to device {}", device_id))?;

        let mut tunnel = tunnel_arc.lock().await;
        let encrypted = tunnel.encapsulate(data);
        let addr = tunnel.peer_addr;

        self.socket
            .send_to(&encrypted, addr)
            .await
            .map_err(|e| format!("Send failed: {}", e))
    }

    /// Get traffic statistics for a specific tunnel.
    pub async fn get_traffic_stats(&self, device_id: &str) -> Option<(u64, u64)> {
        let tunnel_arc = self.tunnels.get(device_id)?;
        let tunnel = tunnel_arc.lock().await;
        Some((tunnel.bytes_sent, tunnel.bytes_received))
    }

    /// Get all active tunnel statistics for reporting.
    pub async fn get_all_stats(&self) -> HashMap<String, (u64, u64)> {
        let mut stats = HashMap::new();
        for (id, tunnel_arc) in &self.tunnels {
            let tunnel = tunnel_arc.lock().await;
            stats.insert(id.clone(), (tunnel.bytes_sent, tunnel.bytes_received));
        }
        stats
    }

    /// Number of active tunnels.
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }
}

/// Perform UDP hole punching to establish a P2P connection.
///
/// Sends a burst of randomized packets to the peer to create a NAT binding.
/// Packet payloads are random to avoid traffic fingerprinting by DPI/middleboxes.
pub async fn hole_punch(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    num_packets: usize,
) -> Result<(), std::io::Error> {
    use rand::RngCore;
    // Send multiple punch packets with random payloads to avoid fingerprinting
    let mut rng = rand::thread_rng();
    for _ in 0..num_packets {
        let mut punch_data = [0u8; 64];
        rng.fill_bytes(&mut punch_data);
        socket.send_to(&punch_data, peer_addr).await?;
        // Small delay between punches
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Probe NAT type by querying multiple STUN servers.
/// Returns the NAT classification string.
pub async fn probe_nat_type(
    socket: &UdpSocket,
    stun_servers: &[String],
) -> stun::NatClassification {
    if stun_servers.is_empty() {
        return stun::NatClassification::Unknown;
    }

    let results = stun::probe_multi_stun(stun_servers).await;

    if results.is_empty() {
        return stun::NatClassification::Unknown;
    }

    log::info!(
        "NAT probe complete: {} servers, results={:?}",
        results.len(),
        results.iter().map(|(s, r)| {
            format!("{}->{}", s, r.as_ref().map(|a| a.to_string()).unwrap_or_else(|e| e.clone()))
        }).collect::<Vec<_>>()
    );

    stun::classify_nat(&results)
}

/// Establish a connection to a peer using full NAT traversal.
///
/// Flow:
/// 1. Query STUN for public address
/// 2. Exchange candidates via signaling
/// 3. Execute UDP hole punching
/// 4. If punch fails, use relay path
/// 5. Set up QUIC or ChaCha20-Poly1305 encryption
///
/// Returns the established path type and session key.
pub async fn establish_p2p_connection(
    socket: Arc<tokio::net::UdpSocket>,
    stun_server: &str,
    peer_id: &str,
    our_device_id: &str,
    peer_candidates: &[puncher::Candidate],
    relay_addr: Option<std::net::SocketAddr>,
    multi_path: &Arc<MultiPathManager>,
) -> Result<(PathType, SessionKey), String> {
    // Step 1: Get our public address
    let our_public = stun::get_public_addr(stun_server).await?;
    log::info!("Our public address: {}", our_public);

    // Build our candidates
    let mut our_candidates = Vec::new();
    if let Ok(local) = socket.local_addr() {
        our_candidates.push(puncher::Candidate {
            addr: local,
            candidate_type: "host".to_string(),
            priority: 100,
        });
    }
    our_candidates.push(puncher::Candidate {
        addr: our_public,
        candidate_type: "srflx".to_string(),
        priority: 90,
    });

    // Register my local path
    multi_path.register_path(
        peer_id,
        PathType::Direct,
        our_public,
    ).await;

    // Register relay path if available
    if let Some(relay) = relay_addr {
        multi_path.register_path(
            peer_id,
            PathType::Relay,
            relay,
        ).await;
    }

    // Step 2: Execute hole punching
    log::info!(
        "Starting hole punch to {} (local candidates: {}, peer candidates: {})",
        peer_id, our_candidates.len(), peer_candidates.len()
    );

    let hmac_key = b"mesh-punch-hmac"; // In production: use a proper shared secret

    let punch_result = puncher::execute_punch(
        socket.clone(),
        hmac_key,
        peer_id,
        our_device_id,
        &our_candidates,
        peer_candidates,
        std::time::Duration::from_secs(10),
        relay_addr,
    ).await;

    match punch_result {
        Ok(direct_addr) => {
            log::info!("Direct P2P connection established to {} at {}", peer_id, direct_addr);
            multi_path.mark_active(peer_id, &PathType::Direct).await;

            let session_key = SessionKey::generate();
            Ok((PathType::Direct, session_key))
        }
        Err(e) => {
            log::warn!(
                "Hole punch to {} failed: {}. Falling back to relay.",
                peer_id, e
            );

            // Fall back to relay
            if let Some(relay) = relay_addr {
                multi_path.mark_active(peer_id, &PathType::Relay).await;
                let session_key = SessionKey::generate();
                log::info!("Using relay path for {} via {}", peer_id, relay);
                Ok((PathType::Relay, session_key))
            } else {
                Err(format!("No path to {} available (punch failed, no relay)", peer_id))
            }
        }
    }
}
