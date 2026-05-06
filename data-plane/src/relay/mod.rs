//! Relay node module - high-performance packet forwarding for the mesh network.
//!
//! When direct P2P is not possible (e.g., symmetric NAT on both ends),
//! the relay node acts as a transparent forwarder. It does NOT decrypt
//! traffic — packets are forwarded end-to-end encrypted (zero-trust).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// A routing entry mapping a device ID to its current UDP socket address.
#[derive(Clone, Debug)]
struct RoutingEntry {
    device_id: String,
    addr: SocketAddr,
}

/// The relay's forwarding table.
/// Maps source address -> destination routing entry.
pub struct ForwardingTable {
    /// (src_device, dst_device) -> dst_addr
    routes: RwLock<HashMap<(String, String), SocketAddr>>,
    /// device_id -> current SocketAddr
    device_addrs: RwLock<HashMap<String, SocketAddr>>,
    /// device_id -> (bytes_forwarded, packets_forwarded)
    stats: RwLock<HashMap<String, (u64, u64)>>,
}

impl ForwardingTable {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            device_addrs: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
        }
    }

    /// Register a device's current address.
    pub async fn register_device(&self, device_id: &str, addr: SocketAddr) {
        let mut addrs = self.device_addrs.write().await;
        addrs.insert(device_id.to_string(), addr);
    }

    /// Remove a device registration.
    pub async fn unregister_device(&self, device_id: &str) {
        let mut addrs = self.device_addrs.write().await;
        addrs.remove(device_id);
    }

    /// Add a forwarding route between two devices.
    pub async fn add_route(&self, src_device: &str, dst_device: &str) {
        let addrs = self.device_addrs.read().await;
        if let Some(dst_addr) = addrs.get(dst_device) {
            let mut routes = self.routes.write().await;
            routes.insert(
                (src_device.to_string(), dst_device.to_string()),
                *dst_addr,
            );
        }
    }

    /// Remove a forwarding route.
    pub async fn remove_route(&self, src_device: &str, dst_device: &str) {
        let mut routes = self.routes.write().await;
        routes.remove(&(src_device.to_string(), dst_device.to_string()));
    }

    /// Look up the destination address for a forwarding operation.
    pub async fn lookup(&self, src_device: &str, dst_device: &str) -> Option<SocketAddr> {
        let routes = self.routes.read().await;
        routes
            .get(&(src_device.to_string(), dst_device.to_string()))
            .copied()
    }

    /// Update forwarding statistics.
    pub async fn record_forward(&self, device_id: &str, bytes: u64) {
        let mut stats = self.stats.write().await;
        let entry = stats
            .entry(device_id.to_string())
            .or_insert((0, 0));
        entry.0 += bytes;
        entry.1 += 1;
    }

    /// Get current load statistics.
    pub async fn get_stats(&self) -> (u64, u64, usize) {
        let stats = self.stats.read().await;
        let total_bytes: u64 = stats.values().map(|(b, _)| b).sum();
        let total_packets: u64 = stats.values().map(|(_, p)| p).sum();
        let device_count = self.device_addrs.read().await.len();
        (total_bytes, total_packets, device_count)
    }
}

/// Run the relay forwarding loop.
///
/// Continuously receives packets and forwards them to the destination
/// based on the routing table. This is the core relay function.
pub async fn relay_loop(
    socket: Arc<UdpSocket>,
    forwarding_table: Arc<ForwardingTable>,
) {
    let mut buf = vec![0u8; 65536]; // Max UDP packet size

    log::info!("Relay forwarding loop started");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                let data = &buf[..n];

                // The first 32 bytes of each relayed packet contain
                // the source and destination device IDs (16 bytes each, UUID)
                if data.len() < 32 {
                    log::warn!("Received short packet from {}: {} bytes", src_addr, n);
                    continue;
                }

                let src_id = String::from_utf8_lossy(&data[..16])
                    .trim_end_matches('\0')
                    .to_string();
                let dst_id = String::from_utf8_lossy(&data[16..32])
                    .trim_end_matches('\0')
                    .to_string();
                let payload = &data[32..];

                // Look up the destination
                if let Some(dst_addr) = forwarding_table.lookup(&src_id, &dst_id).await {
                    // Forward payload (encrypted, relay doesn't decrypt)
                    match socket.send_to(payload, dst_addr).await {
                        Ok(sent) => {
                            forwarding_table
                                .record_forward(&src_id, sent as u64)
                                .await;
                            log::trace!(
                                "Forwarded {} bytes: {} -> {}",
                                sent, src_id, dst_id
                            );
                        }
                        Err(e) => {
                            log::error!("Forward failed from {} to {}: {}", src_id, dst_id, e);
                        }
                    }
                } else {
                    log::debug!("No route for {} -> {}", src_id, dst_id);

                    // Try to auto-register the source device
                    forwarding_table.register_device(&src_id, src_addr).await;
                }
            }
            Err(e) => {
                log::error!("Receive error in relay loop: {}", e);
                break;
            }
        }
    }
}
