//! Relay node module - high-performance packet forwarding for the mesh network.
//!
//! When direct P2P is not possible (e.g., symmetric NAT on both ends),
//! the relay node acts as a transparent forwarder. It does NOT decrypt
//! traffic — packets are forwarded end-to-end encrypted (zero-trust).
//!
//! Security:
//! - Packets include an HMAC-SHA256 tag to authenticate the source device ID
//! - The relay verifies the HMAC before forwarding (prevents device ID spoofing)
//! - Routes must be pre-established (no auto-registration of unknown devices)
//! - Per-device rate limiting prevents traffic amplification attacks

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use sha2::Sha256;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use zeroize::Zeroize;

/// Packet format (wire protocol):
/// ┌─────────────────┬──────────────────┬───────────────────────┬──────────┐
/// │ src_device (16B) │ dst_device (16B) │ hmac_tag (32B)       │ payload  │
/// └─────────────────┴──────────────────┴───────────────────────┴──────────┘
///   0                 16                 32                     64
///
/// The HMAC-SHA256 covers bytes 0-31 (src + dst device IDs) and is keyed
/// with a shared relay secret. The relay verifies this before forwarding.
const HEADER_SIZE: usize = 64; // 16 + 16 + 32 = 64 bytes

/// The relay's forwarding table.
pub struct ForwardingTable {
    /// (src_device, dst_device) -> dst_addr
    routes: RwLock<HashMap<(String, String), SocketAddr>>,
    /// device_id -> current SocketAddr
    device_addrs: RwLock<HashMap<String, SocketAddr>>,
    /// device_id -> (bytes_forwarded, packets_forwarded)
    stats: RwLock<HashMap<String, (u64, u64)>>,
    /// device_id -> packets in current second (rate limiting)
    rate_limits: RwLock<HashMap<String, (u64, u64)>>, // (window_start, count)
    /// IP address -> packets in current second (secondary rate limiting)
    /// Prevents a single IP from rotating through many device IDs.
    ip_rate_limits: RwLock<HashMap<String, (u64, u64)>>, // (window_start, count)
    /// Shared HMAC key for source authentication
    hmac_key: Vec<u8>,
}

impl ForwardingTable {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            device_addrs: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
            rate_limits: RwLock::new(HashMap::new()),
            ip_rate_limits: RwLock::new(HashMap::new()),
            hmac_key: {
                let key = std::env::var("RELAY_HMAC_KEY").unwrap_or_default();
                if key.is_empty() {
                    log::warn!(
                        "RELAY_HMAC_KEY not set — HMAC verification will reject all packets"
                    );
                }
                key.into_bytes()
            },
        }
    }

    /// Set the HMAC key for source authentication.
    pub fn set_hmac_key(&mut self, key: Vec<u8>) {
        self.hmac_key = key;
    }

    /// Verify an HMAC tag over the device ID header.
    /// Returns false if the HMAC key is empty (not configured).
    fn verify_hmac(&self, src_id: &[u8], dst_id: &[u8], tag: &[u8]) -> bool {
        if self.hmac_key.is_empty() {
            return false;
        }
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = match HmacSha256::new_from_slice(&self.hmac_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(src_id);
        mac.update(dst_id);
        mac.verify_slice(tag).is_ok()
    }

    /// Compute an HMAC tag for a given src+dst pair (used by clients).
    pub fn compute_hmac(&self, src_id: &str, dst_id: &str) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC key should be valid");
        mac.update(src_id.as_bytes());
        mac.update(dst_id.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Register a device's current address (only after HMAC verification).
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

    /// Per-device rate limiting — max `limit` packets per second.
    async fn check_rate_limit(&self, device_id: &str, limit: u64) -> bool {
        let mut rates = self.rate_limits.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = rates.entry(device_id.to_string()).or_insert((now, 0));

        if entry.0 != now {
            // New second — reset counter
            entry.0 = now;
            entry.1 = 0;
        }

        entry.1 += 1;
        if entry.1 > limit {
            return false; // rate limit exceeded
        }
        true
    }

    /// Secondary IP-based rate limiting — max `limit` packets per second per IP.
    /// Prevents spoofing attacks where a single IP rotates through many device IDs.
    pub async fn check_ip_rate_limit(&self, ip: std::net::IpAddr, limit: u64) -> bool {
        let mut rates = self.ip_rate_limits.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ip_str = ip.to_string();
        let entry = rates.entry(ip_str).or_insert((now, 0));

        if entry.0 != now {
            entry.0 = now;
            entry.1 = 0;
        }

        entry.1 += 1;
        if entry.1 > limit {
            return false;
        }
        true
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

/// Zeroize the HMAC key on drop to prevent lingering secrets in memory.
impl Drop for ForwardingTable {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

/// Run the relay forwarding loop.
///
/// Continuously receives packets and forwards them to the destination
/// based on the routing table. Verifies HMAC on each packet to prevent
/// device ID spoofing.
pub async fn relay_loop(
    socket: Arc<UdpSocket>,
    forwarding_table: Arc<ForwardingTable>,
) {
    let mut buf = vec![0u8; 65536]; // Max UDP packet size
    const MAX_PACKETS_PER_SEC: u64 = 100; // Per-device rate limit
    const MAX_IP_PACKETS_PER_SEC: u64 = 500; // Per-IP secondary rate limit

    log::info!("Relay forwarding loop started (HMAC verification enabled)");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                let data = &buf[..n];

                // Packets must be at least HEADER_SIZE (64 bytes) to include the HMAC tag
                if data.len() < HEADER_SIZE {
                    log::warn!(
                        "Short relay packet from {}: {} bytes (need >= {})",
                        src_addr, n, HEADER_SIZE
                    );
                    continue;
                }

                let src_id_bytes = &data[..16];
                let dst_id_bytes = &data[16..32];
                let hmac_tag = &data[32..64];
                let payload = &data[HEADER_SIZE..];

                let src_id = String::from_utf8_lossy(src_id_bytes)
                    .trim_end_matches('\0')
                    .to_string();
                let dst_id = String::from_utf8_lossy(dst_id_bytes)
                    .trim_end_matches('\0')
                    .to_string();

                // Verify HMAC to authenticate the source device ID
                if !forwarding_table.verify_hmac(src_id_bytes, dst_id_bytes, hmac_tag) {
                    log::warn!(
                        "HMAC verification failed for src={} dst={} from {}",
                        src_id, dst_id, src_addr
                    );
                    continue; // Drop spoofed packet
                }

                // Rate limit per source device
                if !forwarding_table.check_rate_limit(&src_id, MAX_PACKETS_PER_SEC).await {
                    log::warn!("Rate limit exceeded for device {}", src_id);
                    continue;
                }

                // Secondary IP-based rate limit — prevents spoofing attacks
                // where a single IP rotates through many device IDs
                if !forwarding_table.check_ip_rate_limit(src_addr.ip(), MAX_IP_PACKETS_PER_SEC).await {
                    log::warn!("IP rate limit exceeded for {}", src_addr.ip());
                    continue;
                }

                // Update device address (only after HMAC passes)
                forwarding_table.register_device(&src_id, src_addr).await;

                // Look up the destination route
                if let Some(dst_addr) = forwarding_table.lookup(&src_id, &dst_id).await {
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
                    // No pre-established route — do NOT auto-create one.
                    // Routes are established by the control plane's signaling.
                    log::debug!(
                        "No established route for {} -> {} (packet from {})",
                        src_id, dst_id, src_addr
                    );
                }
            }
            Err(e) => {
                log::error!("Receive error in relay loop: {}", e);
                break;
            }
        }
    }
}
