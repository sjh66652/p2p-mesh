//! Overlay Network — the core virtual network layer.
//!
//! Ties together:
//! - TUN interface (captures/injects IP packets)
//! - Route table (decides where to send packets)
//! - Peer tunnels (encrypted transport)
//!
//! This is the main packet processing loop:
//! 1. Read IP packet from TUN
//! 2. Extract destination IP from IP header
//! 3. Look up route in route table (LPM)
//! 4. Encrypt and send via peer tunnel
//! 5. Receive encrypted packet from peer
//! 6. Decrypt and inject into TUN
//!
//! Protocol constants for IP header parsing:
//! - IPv4 header: version (4) IHL (4) DSCP (6) ECN (2) total_len (16)
//! - Destination IP is at offset 16 in the IPv4 header

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use crate::router::{Route, RouteTable, RouteType};
use crate::tunnel::TunnelManager;

/// Extract the destination IPv4 address from a raw IP packet.
///
/// The destination address is at byte offset 16 in the IPv4 header.
/// Returns None if the packet is too short or not IPv4.
pub fn extract_dst_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    // Check IP version (first nibble)
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let dst_bytes: [u8; 4] = [packet[16], packet[17], packet[18], packet[19]];
    Some(Ipv4Addr::from(dst_bytes))
}

/// Overlay Network Manager.
///
/// Orchestrates the TUN ↔ Route Table ↔ Peer Tunnel pipeline.
pub struct OverlayNetwork {
    /// TUN interface for OS integration
    tun: Arc<crate::tun::TunInterface>,
    /// Route table for LPM lookups
    route_table: Arc<RouteTable>,
    /// Peer tunnel manager
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    /// Peer ID → virtual IP mapping
    peer_ips: RwLock<HashMap<String, Ipv4Addr>>,
    /// virtual IP → peer ID reverse mapping
    ip_to_peer: RwLock<HashMap<Ipv4Addr, String>>,
    /// Our virtual IP on the overlay network
    our_virtual_ip: Ipv4Addr,
    /// Our device ID
    our_device_id: String,
    /// Handle for the packet processing loop
    process_handle: Option<JoinHandle<()>>,
}

impl OverlayNetwork {
    /// Create a new overlay network.
    pub fn new(
        tun: crate::tun::TunInterface,
        route_table: RouteTable,
        tunnel_manager: TunnelManager,
        our_virtual_ip: Ipv4Addr,
        our_device_id: String,
    ) -> Self {
        Self {
            tun: Arc::new(tun),
            route_table: Arc::new(route_table),
            tunnel_manager: Arc::new(Mutex::new(tunnel_manager)),
            peer_ips: RwLock::new(HashMap::new()),
            ip_to_peer: RwLock::new(HashMap::new()),
            our_virtual_ip,
            our_device_id,
            process_handle: None,
        }
    }

    /// Register a peer's virtual IP address.
    pub async fn register_peer(&self, peer_id: &str, virtual_ip: Ipv4Addr) {
        let mut peer_ips = self.peer_ips.write().await;
        let mut ip_to_peer = self.ip_to_peer.write().await;
        peer_ips.insert(peer_id.to_string(), virtual_ip);
        ip_to_peer.insert(virtual_ip, peer_id.to_string());
    }

    /// Add a route to the overlay route table.
    pub async fn add_route(&self, route: Route) {
        self.route_table.add_route(route).await;
    }

    /// Remove a peer registration.
    pub async fn unregister_peer(&self, peer_id: &str) {
        let mut peer_ips = self.peer_ips.write().await;
        let mut ip_to_peer = self.ip_to_peer.write().await;
        if let Some(ip) = peer_ips.remove(peer_id) {
            ip_to_peer.remove(&ip);
        }
    }

    /// Get a peer's virtual IP.
    pub async fn get_peer_ip(&self, peer_id: &str) -> Option<Ipv4Addr> {
        let peer_ips = self.peer_ips.read().await;
        peer_ips.get(peer_id).copied()
    }

    /// Look up a peer ID by virtual IP.
    pub async fn get_peer_by_ip(&self, ip: Ipv4Addr) -> Option<String> {
        let ip_to_peer = self.ip_to_peer.read().await;
        ip_to_peer.get(&ip).cloned()
    }

    /// Process an outbound IP packet (from TUN to overlay).
    ///
    /// Flow: extract dst_ip → route lookup → send via tunnel
    pub async fn process_outbound(&self, packet: &[u8]) -> Result<(), OverlayError> {
        let dst_ip = extract_dst_ip(packet)
            .ok_or(OverlayError::InvalidPacket("Not a valid IPv4 packet".into()))?;

        // Route lookup
        let route = self.route_table.lookup(dst_ip).await
            .ok_or(OverlayError::NoRoute(dst_ip))?;

        let peer_id = &route.peer_id;

        // Send via tunnel
        let tunnels = self.tunnel_manager.lock().await;
        tunnels.send_to(peer_id, packet).await
            .map_err(|e| OverlayError::TunnelError(e))?;

        Ok(())
    }

    /// Process an inbound packet (from tunnel to TUN).
    ///
    /// The packet is injected into the OS network stack via the TUN interface.
    /// The OS then delivers it to the appropriate application.
    pub async fn process_inbound(&self, packet: &[u8]) -> Result<(), OverlayError> {
        self.tun.write_packet(packet).await
            .map_err(|e| OverlayError::TunError(e))?;
        Ok(())
    }

    /// Start the main overlay packet processing loop.
    ///
    /// This runs two concurrent tasks:
    /// 1. Read from TUN → route → send to peer (outbound)
    /// 2. Read from tunnel → decrypt → inject into TUN (inbound)
    pub fn start_processing(&mut self) {
        let tun_out = self.tun.clone();
        let tun_in = self.tun.clone();
        let route_table = self.route_table.clone();
        let tunnel_manager_out = self.tunnel_manager.clone();
        let tunnel_manager_in = self.tunnel_manager.clone();

        // Outbound task: TUN → route table → tunnel
        let out_handle = tokio::spawn(async move {
            loop {
                match tun_out.read_packet().await {
                    Ok(packet) => {
                        if let Some(dst_ip) = extract_dst_ip(&packet) {
                            match route_table.lookup(dst_ip).await {
                                Some(route) => {
                                    let tunnels = tunnel_manager_out.lock().await;
                                    let _ = tunnels.send_to(&route.peer_id, &packet).await;
                                    drop(tunnels);
                                }
                                None => {
                                    log::trace!("No route for destination IP {}", dst_ip);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Inbound task: tunnel → decrypt → TUN
        tokio::spawn(async move {
            loop {
                let (peer_id, packet) = {
                    let tunnels = tunnel_manager_in.lock().await;
                    match tunnels.recv_from().await {
                        Some(result) => result,
                        None => {
                            drop(tunnels);
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            continue;
                        }
                    }
                };
                log::trace!("Received inbound packet from {}", peer_id);
                if let Err(e) = tun_in.write_packet(&packet).await {
                    log::error!("TUN write error (inbound from {}): {}", peer_id, e);
                }
            }
        });

        self.process_handle = Some(out_handle);
    }

    /// Get our virtual IP on the overlay.
    pub fn our_ip(&self) -> Ipv4Addr {
        self.our_virtual_ip
    }

    /// Add subnet routes for a peer.
    pub async fn add_peer_routes(&self, peer_id: &str, subnets: &[Ipv4Net]) {
        for subnet in subnets {
            let route = Route {
                cidr: *subnet,
                peer_id: peer_id.to_string(),
                metric: 10,
                admin_distance: 2,
                route_type: RouteType::Mesh,
                active: true,
                added_at: std::time::Instant::now(),
                last_used: None,
            };
            self.route_table.add_route(route).await;
        }
    }
}

/// Overlay network errors.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("No route to {0}")]
    NoRoute(Ipv4Addr),

    #[error("Tunnel error: {0}")]
    TunnelError(String),

    #[error("TUN error: {0}")]
    TunError(std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dst_ip_valid() {
        // Build a minimal IPv4 packet
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // version=4, IHL=5
        packet[16] = 100;
        packet[17] = 64;
        packet[18] = 0;
        packet[19] = 42;

        let dst = extract_dst_ip(&packet);
        assert_eq!(dst, Some(Ipv4Addr::new(100, 64, 0, 42)));
    }

    #[test]
    fn test_extract_dst_ip_too_short() {
        let packet = vec![0u8; 10];
        assert_eq!(extract_dst_ip(&packet), None);
    }

    #[test]
    fn test_extract_dst_ip_not_ipv4() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x60; // version=6
        assert_eq!(extract_dst_ip(&packet), None);
    }
}
