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
/// Sends a burst of packets to the peer to create a NAT binding,
/// enabling direct communication even behind NAT.
pub async fn hole_punch(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    num_packets: usize,
) -> Result<(), std::io::Error> {
    // Send multiple punch packets to establish NAT binding
    let punch_data = b"P2P_MESH_PUNCH";
    for _ in 0..num_packets {
        socket.send_to(punch_data, peer_addr).await?;
        // Small delay between punches
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Probe NAT type by sending STUN-like requests.
/// Returns a classification string matching the control plane's NAT types.
pub async fn probe_nat_type(_socket: &UdpSocket) -> &'static str {
    // In a full implementation, this would:
    // 1. Send STUN binding requests to multiple STUN servers
    // 2. Compare mapped addresses across servers
    // 3. Classify NAT type (open, full_cone, restricted_cone, port_restricted, symmetric)
    //
    // For now, return unknown — the control plane will try P2P first.
    "unknown"
}
