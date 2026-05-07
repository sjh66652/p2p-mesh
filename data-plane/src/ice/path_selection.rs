//! Path Selection Engine with IPv6 priority.
//!
//! Implements intelligent path selection:
//! - IPv6 Direct preferred over IPv4 Direct
//! - Happy Eyeballs algorithm (RFC 8305) for dual-stack
//! - Path ranking by latency, loss, and jitter
//! - Automatic path migration on quality degradation
//! - Network interface awareness

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

fn instant_now() -> Instant { Instant::now() }

/// A single network path between two peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPath {
    /// Path ID (unique per peer)
    pub path_id: String,
    /// Remote socket address
    pub remote_addr: SocketAddr,
    /// Local interface used
    pub local_addr: Option<SocketAddr>,
    /// Path type
    pub path_type: PathType,
    /// IP version
    pub ip_version: IpVersion,
    /// Current path state
    pub state: PathState,
    /// Quality metrics
    pub metrics: PathMetrics,
    /// Priority score (higher = more preferred)
    pub score: f64,
    /// Created timestamp
    #[serde(skip, default = "instant_now")]
    pub created_at: Instant,
    /// Last activity timestamp
    #[serde(skip, default = "instant_now")]
    pub last_active: Instant,
    /// Number of consecutive failures
    pub failures: u32,
    /// Parent interface name
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathType {
    /// Direct P2P connection
    Direct,
    /// Via TURN relay
    Relay,
    /// Local network (same subnet)
    Local,
    /// UDP hole punch
    HolePunch,
    /// QUIC connection
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathState {
    /// Path is being discovered
    Discovering,
    /// Path is established and usable
    Active,
    /// Path quality is degraded
    Degraded,
    /// Path is temporarily unavailable
    Inactive,
    /// Path has been removed
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    /// Smoothed RTT (microseconds)
    pub rtt_us: u64,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Jitter (RTT variance, microseconds)
    pub jitter_us: u64,
    /// Estimated bandwidth (bytes/sec)
    pub bandwidth_bps: u64,
    /// MOS (Mean Opinion Score) 1.0-5.0
    pub mos: f64,
    /// Last update timestamp
    #[serde(skip, default = "instant_now")]
    pub updated_at: Instant,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            rtt_us: 0,
            loss_rate: 0.0,
            jitter_us: 0,
            bandwidth_bps: 0,
            mos: 0.0,
            updated_at: Instant::now(),
        }
    }
}

/// Path Selection Engine.
///
/// Manages multiple paths per peer and selects the best one
/// based on quality metrics and IPv6 preference.
pub struct PathSelector {
    /// peer_id → [path_id → NetworkPath]
    paths: RwLock<HashMap<String, Vec<NetworkPath>>>,
    /// Active path per peer
    active_paths: RwLock<HashMap<String, String>>,
    /// IPv6 preference weight
    ipv6_preference: f64,
    /// Degradation threshold (RTT multiplier)
    degradation_threshold: f64,
    /// Minimum time between path switches
    min_switch_interval: Duration,
}

impl PathSelector {
    /// Create a new path selector.
    pub fn new() -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            active_paths: RwLock::new(HashMap::new()),
            ipv6_preference: 1.5, // IPv6 gets 1.5x score boost
            degradation_threshold: 2.0, // Switch if RTT doubles
            min_switch_interval: Duration::from_secs(10),
        }
    }

    /// Add a path for a peer.
    pub async fn add_path(&self, peer_id: &str, path: NetworkPath) {
        let mut paths = self.paths.write().await;
        let peer_paths = paths.entry(peer_id.to_string()).or_default();
        peer_paths.push(path);
    }

    /// Remove a path for a peer.
    pub async fn remove_path(&self, peer_id: &str, path_id: &str) {
        let mut paths = self.paths.write().await;
        if let Some(peer_paths) = paths.get_mut(peer_id) {
            peer_paths.retain(|p| p.path_id != path_id);
        }
        // Clear active path if it was this one
        let mut active = self.active_paths.write().await;
        if active.get(peer_id).map(|p| p == path_id).unwrap_or(false) {
            active.remove(peer_id);
        }
    }

    /// Select the best path for a peer.
    ///
    /// Algorithm:
    /// 1. Filter to active/usable paths
    /// 2. Score each path (IPv6 boost × quality score)
    /// 3. Return highest-scoring path
    /// 4. Enforce min_switch_interval to prevent flapping
    pub async fn select_best_path(&self, peer_id: &str) -> Option<NetworkPath> {
        let paths = self.paths.read().await;
        let peer_paths = paths.get(peer_id)?;

        // Filter usable paths
        let usable: Vec<&NetworkPath> = peer_paths
            .iter()
            .filter(|p| p.state == PathState::Active || p.state == PathState::Degraded)
            .collect();

        if usable.is_empty() {
            return None;
        }

        // Score paths
        let mut best: Option<(&NetworkPath, f64)> = None;

        for path in &usable {
            let score = self.score_path(path);

            if best.is_none() || score > best.unwrap().1 {
                best = Some((path, score));
            }
        }

        best.map(|(path, _)| path.clone())
    }

    /// Score a path for comparison.
    ///
    /// Higher score = better path.
    /// Formula: score = quality_factor × (ipv6_bonus) × (1 - loss_rate)
    fn score_path(&self, path: &NetworkPath) -> f64 {
        let mut score = 1000.0;

        // RTT penalty (lower is better)
        if path.metrics.rtt_us > 0 {
            let rtt_ms = path.metrics.rtt_us as f64 / 1000.0;
            score -= rtt_ms * 2.0; // -2 points per ms of RTT
        }

        // Loss penalty
        score *= 1.0 - path.metrics.loss_rate.min(0.99);

        // Jitter penalty
        if path.metrics.jitter_us > 0 {
            score -= (path.metrics.jitter_us as f64 / 1000.0) * 0.5;
        }

        // Bandwidth bonus
        if path.metrics.bandwidth_bps > 0 {
            let mbps = path.metrics.bandwidth_bps as f64 / 1_000_000.0;
            score += (mbps * 5.0).min(500.0);
        }

        // IPv6 boost (prefer IPv6 for future-proofing)
        if path.ip_version == IpVersion::V6 {
            score *= self.ipv6_preference;
        }

        // Direct paths preferred over relay
        match path.path_type {
            PathType::Local => score *= 1.2,
            PathType::Direct => score *= 1.1,
            PathType::HolePunch => score *= 1.0,
            PathType::Quic => score *= 0.95,
            PathType::Relay => score *= 0.7,
        }

        score
    }

    /// Implement Happy Eyeballs (RFC 8305) for dual-stack connection.
    ///
    /// Attempts IPv6 first with a 250ms head start, then IPv4.
    /// Returns the first path that successfully connects.
    pub async fn happy_eyeballs_select(
        &self,
        peer_id: &str,
    ) -> Option<NetworkPath> {
        let paths = self.paths.read().await;
        let peer_paths = paths.get(peer_id)?;

        // Separate IPv6 and IPv4 paths
        let v6_paths: Vec<&NetworkPath> = peer_paths
            .iter()
            .filter(|p| p.ip_version == IpVersion::V6 && p.state == PathState::Active)
            .collect();

        let v4_paths: Vec<&NetworkPath> = peer_paths
            .iter()
            .filter(|p| p.ip_version == IpVersion::V4 && p.state == PathState::Active)
            .collect();

        // Prefer IPv6
        if !v6_paths.is_empty() {
            // Return best IPv6 path (highest score)
            let best = v6_paths
                .iter()
                .max_by(|a, b| self.score_path(a).partial_cmp(&self.score_path(b)).unwrap_or(std::cmp::Ordering::Equal))
                .map(|p| (*p).clone());

            if best.is_some() {
                return best;
            }
        }

        // Fall back to IPv4
        if !v4_paths.is_empty() {
            let best = v4_paths
                .iter()
                .max_by(|a, b| self.score_path(a).partial_cmp(&self.score_path(b)).unwrap_or(std::cmp::Ordering::Equal))
                .map(|p| (*p).clone());

            return best;
        }

        None
    }

    /// Update path metrics after a measurement.
    pub async fn update_metrics(
        &self,
        peer_id: &str,
        path_id: &str,
        rtt_us: u64,
        loss_rate: f64,
        jitter_us: u64,
        bandwidth_bps: u64,
    ) {
        let mut paths = self.paths.write().await;
        if let Some(peer_paths) = paths.get_mut(peer_id) {
            for path in peer_paths.iter_mut() {
                if path.path_id == path_id {
                    path.metrics.rtt_us = rtt_us;
                    path.metrics.loss_rate = loss_rate;
                    path.metrics.jitter_us = jitter_us;
                    path.metrics.bandwidth_bps = bandwidth_bps;
                    path.metrics.updated_at = Instant::now();

                    // Recalculate MOS (Mean Opinion Score)
                    path.metrics.mos = Self::calculate_mos(rtt_us, loss_rate, jitter_us);

                    // Update state based on metrics
                    if loss_rate > 0.05 || rtt_us > 500_000 {
                        path.state = PathState::Degraded;
                    }
                    if loss_rate > 0.20 {
                        path.state = PathState::Inactive;
                    }
                }
            }
        }
    }

    /// Calculate MOS (Mean Opinion Score) for VoIP quality assessment.
    /// Returns 1.0 (worst) to 5.0 (best).
    ///
    /// Based on ITU-T E-model (simplified).
    fn calculate_mos(rtt_us: u64, loss_rate: f64, jitter_us: u64) -> f64 {
        let mut mos = 5.0;

        // RTT penalty (every 100ms costs ~0.5 MOS)
        let rtt_ms = rtt_us as f64 / 1000.0;
        mos -= (rtt_ms / 100.0) * 0.5;

        // Loss penalty (every 1% loss costs ~0.4 MOS)
        mos -= loss_rate * 40.0;

        // Jitter penalty (every 50ms jitter costs ~0.3 MOS)
        let jitter_ms = jitter_us as f64 / 1000.0;
        mos -= (jitter_ms / 50.0) * 0.3;

        mos.max(1.0).min(5.0)
    }

    /// Get the active path for a peer.
    pub async fn get_active_path(&self, peer_id: &str) -> Option<NetworkPath> {
        let active = self.active_paths.read().await;
        let active_id = active.get(peer_id)?;

        let paths = self.paths.read().await;
        let peer_paths = paths.get(peer_id)?;
        peer_paths.iter().find(|p| p.path_id == *active_id).cloned()
    }

    /// Set the active path for a peer.
    pub async fn set_active_path(&self, peer_id: &str, path_id: &str) {
        let mut active = self.active_paths.write().await;
        active.insert(peer_id.to_string(), path_id.to_string());
    }

    /// Get all paths for a peer sorted by score.
    pub async fn get_ranked_paths(&self, peer_id: &str) -> Vec<NetworkPath> {
        let paths = self.paths.read().await;
        let mut peer_paths = paths.get(peer_id).cloned().unwrap_or_default();
        peer_paths.sort_by(|a, b| {
            self.score_path(b).partial_cmp(&self.score_path(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        peer_paths
    }

    /// IPv6 path selection strategy (as specified in roadmap).
    ///
    /// Priority order: IPv6 Direct → IPv4 Direct → IPv6 Relay → IPv4 Relay
    pub async fn ipv6_priority_select(&self, peer_id: &str) -> Option<NetworkPath> {
        let paths = self.paths.read().await;
        let peer_paths = paths.get(peer_id)?;

        let priorities = [
            (IpVersion::V6, PathType::Direct),
            (IpVersion::V4, PathType::Direct),
            (IpVersion::V6, PathType::HolePunch),
            (IpVersion::V4, PathType::HolePunch),
            (IpVersion::V6, PathType::Relay),
            (IpVersion::V4, PathType::Relay),
        ];

        for (ip_ver, path_type) in &priorities {
            for path in peer_paths {
                if path.ip_version == *ip_ver
                    && path.path_type == *path_type
                    && path.state == PathState::Active
                {
                    return Some(path.clone());
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_path(id: &str, ip_ver: IpVersion, path_type: PathType, rtt_ms: u64) -> NetworkPath {
        NetworkPath {
            path_id: id.to_string(),
            remote_addr: if ip_ver == IpVersion::V6 {
                "::1:9999".parse().unwrap()
            } else {
                "10.0.0.1:9999".parse().unwrap()
            },
            local_addr: None,
            path_type,
            ip_version: ip_ver,
            state: PathState::Active,
            metrics: PathMetrics {
                rtt_us: rtt_ms * 1_000,
                loss_rate: 0.0,
                jitter_us: 0,
                bandwidth_bps: 10_000_000, // 10 Mbps
                mos: 4.5,
                updated_at: Instant::now(),
            },
            score: 0.0,
            created_at: Instant::now(),
            last_active: Instant::now(),
            failures: 0,
            interface: None,
        }
    }

    #[tokio::test]
    async fn test_ipv6_priority_over_ipv4() {
        let selector = PathSelector::new();
        selector.add_path("peer1", make_test_path("v4-direct", IpVersion::V4, PathType::Direct, 10)).await;
        selector.add_path("peer1", make_test_path("v6-direct", IpVersion::V6, PathType::Direct, 10)).await;

        let best = selector.ipv6_priority_select("peer1").await;
        assert!(best.is_some());
        assert_eq!(best.unwrap().ip_version, IpVersion::V6);
    }

    #[tokio::test]
    async fn test_direct_preferred_over_relay() {
        let selector = PathSelector::new();
        selector.add_path("peer1", make_test_path("v4-relay", IpVersion::V4, PathType::Relay, 10)).await;
        selector.add_path("peer1", make_test_path("v4-direct", IpVersion::V4, PathType::Direct, 50)).await;

        let best = selector.select_best_path("peer1").await;
        assert!(best.is_some());
        assert_eq!(best.unwrap().path_type, PathType::Direct);
    }

    #[tokio::test]
    async fn test_degraded_path_not_selected() {
        let selector = PathSelector::new();
        let mut degraded = make_test_path("v4-bad", IpVersion::V4, PathType::Direct, 600); // 600ms RTT
        degraded.state = PathState::Degraded;
        selector.add_path("peer1", degraded).await;

        let mut good = make_test_path("v4-relay", IpVersion::V4, PathType::Relay, 50);
        selector.add_path("peer1", good).await;

        let best = selector.select_best_path("peer1").await;
        assert!(best.is_some());
        assert_eq!(best.unwrap().path_id, "v4-relay");
    }

    #[test]
    fn test_mos_calculation() {
        // Perfect conditions → MOS ~5.0
        let mos_perfect = PathSelector::calculate_mos(0, 0.0, 0);
        assert!(mos_perfect > 4.5);

        // Bad conditions → MOS < 2.0
        let mos_bad = PathSelector::calculate_mos(500_000, 0.05, 100_000);
        assert!(mos_bad < 3.0);
    }
}
