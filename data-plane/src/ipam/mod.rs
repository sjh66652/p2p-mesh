//! IP Address Management (IPAM) module.
//!
//! Automatically assigns virtual IP addresses from the 100.64.0.0/10
//! (Carrier-Grade NAT reserved space, per RFC 6598) to mesh nodes.
//!
//! Design:
//! - Control plane owns the canonical IP assignment table (PostgreSQL)
//! - Data plane caches assignments locally and requests IPs via API
//! - IPv4-only for now; IPv6 support planned
//!
//! Address allocation strategy:
//! - First-come-first-served within the 100.64.0.0/10 space
//! - Each device gets a /32 (single IPv4 address)
//! - Reclamation of stale IPs after device deregistration

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// The overlay network prefix (RFC 6598 CGNAT space, borrowed with modifications).
/// We use 100.64.0.0/10 similar to Tailscale and ZeroTier for overlay addressing.
pub const OVERLAY_PREFIX: &str = "100.64.0.0";
pub const OVERLAY_PREFIX_LEN: u8 = 10;

/// IP address pool state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpamState {
    /// Our assigned virtual IP (None if not yet assigned)
    pub our_ip: Option<Ipv4Addr>,
    /// peer_id -> virtual_ip mapping (local cache)
    pub peer_ips: std::collections::HashMap<String, Ipv4Addr>,
    /// virtual_ip -> peer_id reverse mapping
    pub ip_to_peer: std::collections::HashMap<Ipv4Addr, String>,
    /// IPs we've requested but not yet confirmed
    pub pending_ips: std::collections::HashSet<Ipv4Addr>,
}

/// IPAM manager.
pub struct IpamManager {
    /// IPAM state
    state: RwLock<IpamState>,
    /// Control plane API endpoint
    api_base_url: String,
    /// Auth token for API calls
    auth_token: String,
    /// HTTP client
    http_client: reqwest::Client,
}

impl IpamManager {
    /// Create a new IPAM manager.
    pub fn new(api_base_url: String, auth_token: String) -> Self {
        Self {
            state: RwLock::new(IpamState {
                our_ip: None,
                peer_ips: std::collections::HashMap::new(),
                ip_to_peer: std::collections::HashMap::new(),
                pending_ips: std::collections::HashSet::new(),
            }),
            api_base_url,
            auth_token,
            http_client: reqwest::Client::new(),
        }
    }

    /// Request a virtual IP from the control plane.
    ///
    /// POST /api/v1/network/ipam/allocate
    /// Body: { "device_id": "..." }
    /// Response: { "virtual_ip": "100.64.0.1" }
    pub async fn request_ip(&self, device_id: &str) -> Result<Ipv4Addr, IpamError> {
        let url = format!("{}/api/v1/network/ipam/allocate", self.api_base_url);

        let request_body = serde_json::json!({
            "device_id": device_id,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| IpamError::ApiError(format!("HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(IpamError::ApiError(format!("IP allocation failed ({}): {}", status, body)));
        }

        let json: serde_json::Value = resp.json().await
            .map_err(|e| IpamError::ApiError(format!("JSON parse failed: {}", e)))?;

        let ip_str = json["virtual_ip"].as_str()
            .ok_or(IpamError::ApiError("No virtual_ip in response".into()))?;

        let ip: Ipv4Addr = ip_str.parse()
            .map_err(|e| IpamError::ApiError(format!("Invalid IP in response: {}", e)))?;

        // Cache the assignment
        let mut state = self.state.write().await;
        state.our_ip = Some(ip);
        state.pending_ips.remove(&ip);

        log::info!("Allocated overlay IP: {}", ip);
        Ok(ip)
    }

    /// Release our virtual IP (on shutdown).
    pub async fn release_ip(&self, device_id: &str) -> Result<(), IpamError> {
        let url = format!("{}/api/v1/network/ipam/release", self.api_base_url);

        let resp = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .json(&serde_json::json!({ "device_id": device_id }))
            .send()
            .await
            .map_err(|e| IpamError::ApiError(format!("Release failed: {}", e)))?;

        if resp.status().is_success() {
            let mut state = self.state.write().await;
            state.our_ip = None;
            log::info!("Released overlay IP for device {}", device_id);
        }

        Ok(())
    }

    /// Resolve a peer ID to its virtual IP from cache.
    pub async fn resolve_peer_ip(&self, peer_id: &str) -> Option<Ipv4Addr> {
        let state = self.state.read().await;
        state.peer_ips.get(peer_id).copied()
    }

    /// Cache a peer ID → virtual IP mapping.
    pub async fn set_peer_ip(&self, peer_id: &str, ip: Ipv4Addr) {
        let mut state = self.state.write().await;
        state.peer_ips.insert(peer_id.to_string(), ip);
        state.ip_to_peer.insert(ip, peer_id.to_string());
    }

    /// Get our currently assigned virtual IP.
    pub async fn our_ip(&self) -> Option<Ipv4Addr> {
        let state = self.state.read().await;
        state.our_ip
    }

    /// Check if an IP is within the overlay prefix.
    pub fn is_overlay_ip(ip: Ipv4Addr) -> bool {
        let prefix: Ipv4Net = OVERLAY_PREFIX.parse().unwrap();
        prefix.contains(&ip)
    }

    /// Suggest an available IP (client-side heuristic before API call).
    /// Uses a simple hash-based approach to minimize collisions.
    pub fn suggest_ip(device_id: &str) -> Ipv4Addr {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        device_id.hash(&mut hasher);
        let hash = hasher.finish();

        // Use hash to select an IP in 100.64.0.0/10
        // Network: 100.64.0.0, Range: 100.64.0.1 - 100.127.255.254
        let offset = (hash % ((1u64 << 22) - 2)) + 1; // ~4M addresses
        let ip_u32: u32 = ((100u32 * 256 + 64) * 65536) + offset as u32;
        Ipv4Addr::from(ip_u32.to_be_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    #[error("API error: {0}")]
    ApiError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_ip_check() {
        assert!(IpamManager::is_overlay_ip(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(IpamManager::is_overlay_ip(Ipv4Addr::new(100, 100, 0, 1)));
        assert!(IpamManager::is_overlay_ip(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!IpamManager::is_overlay_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!IpamManager::is_overlay_ip(Ipv4Addr::new(100, 63, 255, 255)));
    }

    #[test]
    fn test_suggest_ip_deterministic() {
        let ip1 = IpamManager::suggest_ip("device-abc");
        let ip2 = IpamManager::suggest_ip("device-abc");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_suggest_ip_different_devices() {
        let ip1 = IpamManager::suggest_ip("device-abc");
        let ip2 = IpamManager::suggest_ip("device-xyz");
        assert_ne!(ip1, ip2);
    }
}
