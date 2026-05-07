//! QUIC Multipath Transport — Phase 10.3.
//!
//! Multipath QUIC (MP-QUIC) implementation extending QUIC transport
//! with multiple concurrent network paths for bandwidth aggregation,
//! seamless failover, and connection migration.
//!
//! Based on IETF draft-ietf-quic-multipath (latest).
//!
//! Key features:
//! - Multiple path establishment per connection (path_id 0 = initial path)
//! - Path validation (PATH_CHALLENGE / PATH_RESPONSE frames)
//! - Per-path congestion control (independent CWND per path)
//! - Packet scheduling across paths (Lowest-RTT-First, Round-Robin, Weighted)
//! - Connection migration with path failover
//! - Path quality monitoring and dynamic path addition/removal
//! - Multipath-aware flow control (shared per-connection limits)
//!
//! Frame types (per draft-ietf-quic-multipath):
//! - PATH_CHALLENGE (0x1a): Challenge specific path
//! - PATH_RESPONSE (0x1b): Respond to path challenge
//! - PATH_ABANDON (0x1c): Abandon a path
//! - PATH_STANDBY (0x1d): Mark path as standby
//! - PATH_AVAILABLE (0x1e): Mark path as available
//!
//! Production dependency: quinn with multipath feature

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// =====================================================================
// Path identifier and state
// =====================================================================

/// QUIC path identifier (0 = initial path, 1-255 = additional paths).
pub type PathId = u8;

/// Maximum number of concurrent paths per connection.
pub const MAX_PATHS: usize = 8;

/// Path state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathState {
    /// Path is being validated (PATH_CHALLENGE sent)
    Validating,
    /// Path is active (can send/receive data)
    Active,
    /// Path is on standby (validated but not sending data)
    Standby,
    /// Path is being abandoned
    Abandoning,
    /// Path has been closed
    Closed,
}

/// A single QUIC multipath path.
#[derive(Debug, Clone)]
pub struct MultipathEntry {
    /// Path identifier
    pub path_id: PathId,
    /// Local address for this path
    pub local_addr: SocketAddr,
    /// Remote address for this path
    pub remote_addr: SocketAddr,
    /// Current path state
    pub state: PathState,
    /// When the path was established
    pub established_at: Instant,
    /// Path quality metrics
    pub quality: PathQuality,
    /// Congestion control state per-path
    pub congestion: PathCongestion,
    /// Path priority (higher = preferred)
    pub priority: u8,
    /// Whether this path is used for data transmission
    pub active: bool,
}

/// Per-path quality metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathQuality {
    /// Smoothed RTT in microseconds
    pub srtt_us: u64,
    /// RTT variance
    pub rttvar_us: u64,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Estimated bandwidth (bps)
    pub bandwidth_bps: u64,
    /// Path latency tier
    pub latency_tier: LatencyTier,
    /// Number of consecutive probing timeouts
    pub probing_timeouts: u32,
}

/// Latency classification tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LatencyTier {
    #[default]
    Unknown,
    /// < 10ms
    UltraLow,
    /// 10-50ms
    Low,
    /// 50-150ms
    Medium,
    /// 150-300ms
    High,
    /// > 300ms
    Satellite,
}

impl From<u64> for LatencyTier {
    fn from(rtt_us: u64) -> Self {
        match rtt_us {
            0..=10_000 => LatencyTier::UltraLow,
            10_001..=50_000 => LatencyTier::Low,
            50_001..=150_000 => LatencyTier::Medium,
            150_001..=300_000 => LatencyTier::High,
            _ => LatencyTier::Satellite,
        }
    }
}

/// Per-path congestion control state (NewReno-like).
#[derive(Debug, Clone)]
pub struct PathCongestion {
    /// Congestion window (bytes)
    pub cwnd: u64,
    /// Slow start threshold
    pub ssthresh: u64,
    /// Bytes in flight
    pub bytes_in_flight: u64,
    /// Congestion state
    pub state: CongestionState,
    /// Consecutive congestion events
    pub congestion_events: u32,
    /// Last congestion event
    pub last_congestion: Option<Instant>,
}

impl Default for PathCongestion {
    fn default() -> Self {
        Self {
            cwnd: 14720,     // 10 x MSS (1460)
            ssthresh: u64::MAX, // Start in slow start
            bytes_in_flight: 0,
            state: CongestionState::SlowStart,
            congestion_events: 0,
            last_congestion: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    Recovery,
}

// =====================================================================
// Packet Scheduler — Distributes packets across available paths
// =====================================================================

/// Packet scheduling strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerStrategy {
    /// Send on the path with lowest RTT first
    LowestRttFirst,
    /// Round-robin across available paths
    RoundRobin,
    /// Weighted by bandwidth (higher bandwidth = more packets)
    BandwidthWeighted,
    /// Redundant: send same data on multiple paths (most reliable)
    Redundant,
    /// Adaptive: switch strategy based on network conditions
    Adaptive,
}

/// Multipath packet scheduler.
pub struct MultipathScheduler {
    /// Scheduling strategy
    strategy: SchedulerStrategy,
    /// Round-robin cursor
    rr_cursor: usize,
    /// Path weights for weighted scheduling
    path_weights: HashMap<PathId, f64>,
    /// Redundancy factor for redundant scheduling
    redundancy_factor: u8,
    /// Packets scheduled per path
    path_packets: HashMap<PathId, AtomicU64>,
    /// Total packets scheduled
    total_packets: AtomicU64,
}

impl MultipathScheduler {
    /// Create a new scheduler with the given strategy.
    pub fn new(strategy: SchedulerStrategy) -> Self {
        Self {
            strategy,
            rr_cursor: 0,
            path_weights: HashMap::new(),
            redundancy_factor: 2,
            path_packets: HashMap::new(),
            total_packets: AtomicU64::new(0),
        }
    }

    /// Choose the next path for transmitting a packet.
    pub fn schedule_packet(&mut self, paths: &[&MultipathEntry]) -> Option<PathId> {
        let active: Vec<&MultipathEntry> = paths
            .iter()
            .filter(|p| p.state == PathState::Active && p.active)
            .copied()
            .collect();

        if active.is_empty() {
            return None;
        }

        let path_id = match self.strategy {
            SchedulerStrategy::LowestRttFirst => {
                // Pick path with lowest RTT
                active
                    .iter()
                    .min_by_key(|p| p.quality.srtt_us)
                    .map(|p| p.path_id)
            }
            SchedulerStrategy::RoundRobin => {
                let idx = self.rr_cursor % active.len();
                self.rr_cursor += 1;
                Some(active[idx].path_id)
            }
            SchedulerStrategy::BandwidthWeighted => {
                // Weighted random selection by bandwidth
                let total_weight: f64 = active
                    .iter()
                    .map(|p| self.path_weights.get(&p.path_id).copied().unwrap_or(1.0))
                    .sum();

                if total_weight <= 0.0 {
                    Some(active[0].path_id)
                } else {
                    let mut cumulative = 0.0;
                    let target = rand::random::<f64>() * total_weight;
                    for path in &active {
                        let w = self.path_weights.get(&path.path_id).copied().unwrap_or(1.0);
                        cumulative += w;
                        if cumulative >= target {
                            return Some(path.path_id);
                        }
                    }
                    Some(active.last().unwrap().path_id)
                }
            }
            SchedulerStrategy::Redundant => {
                // Return the primary path; redundancy managed at a higher level
                active.first().map(|p| p.path_id)
            }
            SchedulerStrategy::Adaptive => {
                // Adaptive: if any path has very low RTT, use it;
                // otherwise round-robin
                let min_rtt = active.iter().map(|p| p.quality.srtt_us).min().unwrap_or(u64::MAX);
                let max_rtt = active.iter().map(|p| p.quality.srtt_us).max().unwrap_or(0);

                if max_rtt > min_rtt * 3 {
                    // High variance — prefer lowest RTT
                    active.iter().min_by_key(|p| p.quality.srtt_us).map(|p| p.path_id)
                } else {
                    let idx = self.rr_cursor % active.len();
                    self.rr_cursor += 1;
                    Some(active[idx].path_id)
                }
            }
        };

        if let Some(pid) = path_id {
            self.path_packets
                .entry(pid)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
            self.total_packets.fetch_add(1, Ordering::Relaxed);
        }

        path_id
    }

    /// Update path weights based on quality metrics.
    pub fn update_weights(&mut self, paths: &[&MultipathEntry]) {
        let total_bw: f64 = paths.iter().map(|p| p.quality.bandwidth_bps as f64).sum();
        if total_bw > 0.0 {
            for path in paths {
                let weight = path.quality.bandwidth_bps as f64 / total_bw;
                self.path_weights.insert(path.path_id, weight);
            }
        }
    }

    /// Set the scheduling strategy.
    pub fn set_strategy(&mut self, strategy: SchedulerStrategy) {
        log::info!("Multipath scheduler: strategy changed to {:?}", strategy);
        self.strategy = strategy;
    }

    /// Get scheduler statistics.
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            strategy: self.strategy,
            total_packets: self.total_packets.load(Ordering::Relaxed),
            active_paths: self.path_packets.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub strategy: SchedulerStrategy,
    pub total_packets: u64,
    pub active_paths: usize,
}

// =====================================================================
// Multipath Connection Manager
// =====================================================================

/// Multipath QUIC connection manager.
pub struct MultipathQuicConnection {
    /// Connection ID
    connection_id: Vec<u8>,
    /// Active paths
    paths: RwLock<HashMap<PathId, MultipathEntry>>,
    /// Next available path ID
    next_path_id: AtomicU64,
    /// Packet scheduler
    scheduler: RwLock<MultipathScheduler>,
    /// Multipath configuration
    config: MultipathConfig,
    /// Connection-level flow control
    flow_control: RwLock<FlowControl>,
}

/// Multipath configuration.
#[derive(Debug, Clone)]
pub struct MultipathConfig {
    /// Maximum number of paths
    pub max_paths: u8,
    /// Minimum RTT difference to consider adding a new path
    pub min_rtt_diff_us: u64,
    /// Path validation timeout
    pub validation_timeout: Duration,
    /// Idle path timeout (abandon if no data for this long)
    pub idle_path_timeout: Duration,
    /// Enable active probing for path quality
    pub enable_probing: bool,
    /// Probing interval
    pub probe_interval: Duration,
    /// Default scheduling strategy
    pub scheduler_strategy: SchedulerStrategy,
    /// Enable seamless failover
    pub seamless_failover: bool,
    /// Max reordering delay for multipath (ms)
    pub max_reordering_delay_ms: u64,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            max_paths: 4,
            min_rtt_diff_us: 5_000, // 5ms
            validation_timeout: Duration::from_secs(3),
            idle_path_timeout: Duration::from_secs(30),
            enable_probing: true,
            probe_interval: Duration::from_secs(1),
            scheduler_strategy: SchedulerStrategy::LowestRttFirst,
            seamless_failover: true,
            max_reordering_delay_ms: 50,
        }
    }
}

/// Connection-level flow control for multipath.
#[derive(Debug, Clone)]
pub struct FlowControl {
    /// Maximum data the peer can send (shared across all paths)
    pub max_data: u64,
    /// Data received (shared across all paths)
    pub data_received: u64,
    /// Window size
    pub window: u64,
    /// Last window update sent
    pub last_window_update: Instant,
}

impl Default for FlowControl {
    fn default() -> Self {
        Self {
            max_data: 1_048_576, // 1MB initial
            data_received: 0,
            window: 65_536,       // 64KB
            last_window_update: Instant::now(),
        }
    }
}

impl MultipathQuicConnection {
    /// Create a new multipath QUIC connection.
    pub fn new(connection_id: Vec<u8>, config: MultipathConfig) -> Self {
        log::info!("Multipath QUIC connection established: {} paths max", config.max_paths);

        Self {
            paths: RwLock::new(HashMap::new()),
            next_path_id: AtomicU64::new(1), // 0 reserved for initial path
            scheduler: RwLock::new(MultipathScheduler::new(config.scheduler_strategy)),
            flow_control: RwLock::new(FlowControl::default()),
            connection_id,
            config,
        }
    }

    /// Add a new path to the connection.
    pub async fn add_path(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<PathId, MultipathError> {
        let paths = self.paths.read().await;
        if paths.len() >= self.config.max_paths as usize {
            return Err(MultipathError::TooManyPaths);
        }
        drop(paths);

        let path_id = self.next_path_id.fetch_add(1, Ordering::Relaxed) as PathId;

        let entry = MultipathEntry {
            path_id,
            local_addr,
            remote_addr,
            state: PathState::Validating,
            established_at: Instant::now(),
            quality: PathQuality::default(),
            congestion: PathCongestion::default(),
            priority: 0,
            active: false,
        };

        self.paths.write().await.insert(path_id, entry);
        log::info!(
            "Multipath: path {} added ({} → {})",
            path_id, local_addr, remote_addr
        );

        Ok(path_id)
    }

    /// Activate a path (mark as available for data transmission).
    pub async fn activate_path(&self, path_id: PathId) -> Result<(), MultipathError> {
        let mut paths = self.paths.write().await;
        let path = paths.get_mut(&path_id).ok_or(MultipathError::PathNotFound)?;

        if path.state == PathState::Closed {
            return Err(MultipathError::PathClosed);
        }

        path.state = PathState::Active;
        path.active = true;
        log::info!("Multipath: path {} activated", path_id);
        Ok(())
    }

    /// Set a path to standby (keep alive but don't send data).
    pub async fn standby_path(&self, path_id: PathId) -> Result<(), MultipathError> {
        let mut paths = self.paths.write().await;
        let path = paths.get_mut(&path_id).ok_or(MultipathError::PathNotFound)?;

        path.state = PathState::Standby;
        path.active = false;
        log::info!("Multipath: path {} set to standby", path_id);
        Ok(())
    }

    /// Abandon a path (graceful removal).
    pub async fn abandon_path(&self, path_id: PathId) -> Result<(), MultipathError> {
        let mut paths = self.paths.write().await;
        let path = paths.get_mut(&path_id).ok_or(MultipathError::PathNotFound)?;

        if path_id == 0 {
            return Err(MultipathError::CannotAbandonPrimary);
        }

        path.state = PathState::Abandoning;
        path.active = false;
        log::info!("Multipath: path {} abandoned", path_id);
        Ok(())
    }

    /// Update path quality metrics.
    pub async fn update_path_quality(
        &self,
        path_id: PathId,
        srtt_us: u64,
        loss_rate: f64,
        bandwidth_bps: u64,
    ) -> Result<(), MultipathError> {
        let mut paths = self.paths.write().await;
        let path = paths.get_mut(&path_id).ok_or(MultipathError::PathNotFound)?;

        path.quality.srtt_us = srtt_us;
        path.quality.loss_rate = loss_rate;
        path.quality.bandwidth_bps = bandwidth_bps;
        path.quality.latency_tier = LatencyTier::from(srtt_us);

        // Update scheduler weights
        let all_paths: Vec<&MultipathEntry> = paths.values().collect();
        self.scheduler.write().await.update_weights(&all_paths);

        Ok(())
    }

    /// Handle congestion event on a path.
    pub async fn on_congestion(&self, path_id: PathId) -> Result<(), MultipathError> {
        let mut paths = self.paths.write().await;
        let path = paths.get_mut(&path_id).ok_or(MultipathError::PathNotFound)?;

        let c = &mut path.congestion;
        c.congestion_events += 1;
        c.last_congestion = Some(Instant::now());

        // NewReno congestion response
        match c.state {
            CongestionState::SlowStart => {
                c.ssthresh = (c.cwnd / 2).max(2940); // Min 2x MSS
                c.cwnd = c.ssthresh + 3 * 1460;
                c.state = CongestionState::Recovery;
            }
            CongestionState::CongestionAvoidance => {
                c.ssthresh = (c.cwnd / 2).max(2940);
                c.cwnd = c.ssthresh;
                c.state = CongestionState::Recovery;
            }
            CongestionState::Recovery => {
                c.cwnd = (c.cwnd / 2).max(2940);
                c.ssthresh = c.cwnd;
            }
        }

        log::debug!(
            "Multipath: Path {} congestion event #{}, cwnd={}B, ssthresh={}B",
            path_id, c.congestion_events, c.cwnd, c.ssthresh
        );
        Ok(())
    }

    /// Schedule the next packet for transmission.
    pub async fn schedule_next(&self) -> Option<PathId> {
        let paths = self.paths.read().await;
        let active_paths: Vec<&MultipathEntry> = paths
            .values()
            .filter(|p| p.active && p.state == PathState::Active)
            .collect();

        self.scheduler.write().await.schedule_packet(&active_paths)
    }

    /// Perform seamless failover: switch all traffic to best available path.
    pub async fn seamless_failover(&self, failed_path: PathId) -> Result<PathId, MultipathError> {
        if !self.config.seamless_failover {
            return Err(MultipathError::FailoverDisabled);
        }

        let mut paths = self.paths.write().await;

        // Mark failed path as closed
        if let Some(path) = paths.get_mut(&failed_path) {
            path.state = PathState::Closed;
            path.active = false;
        }

        // Find best alternative (lowest RTT, active)
        let best = paths
            .values()
            .filter(|p| p.path_id != failed_path && p.state == PathState::Active)
            .min_by_key(|p| p.quality.srtt_us)
            .map(|p| p.path_id);

        if let Some(pid) = best {
            log::warn!(
                "Multipath failover: Path {} failed, switching to path {}",
                failed_path, pid
            );
            Ok(pid)
        } else {
            Err(MultipathError::NoAlternativePath)
        }
    }

    /// Get multipath connection statistics.
    pub async fn stats(&self) -> ConnectionStats {
        let paths = self.paths.read().await;
        let active = paths.values().filter(|p| p.active).count();
        let total_paths = paths.len();

        let total_bw: u64 = paths.values().map(|p| p.quality.bandwidth_bps).sum();
        let min_rtt: u64 = paths
            .values()
            .filter(|p| p.active)
            .map(|p| p.quality.srtt_us)
            .min()
            .unwrap_or(0);
        let max_rtt: u64 = paths
            .values()
            .filter(|p| p.active)
            .map(|p| p.quality.srtt_us)
            .max()
            .unwrap_or(0);

        ConnectionStats {
            total_paths,
            active_paths: active,
            aggregate_bandwidth_bps: total_bw,
            min_rtt_us: min_rtt,
            max_rtt_us: max_rtt,
            scheduler: self.scheduler.read().await.stats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total_paths: usize,
    pub active_paths: usize,
    pub aggregate_bandwidth_bps: u64,
    pub min_rtt_us: u64,
    pub max_rtt_us: u64,
    pub scheduler: SchedulerStats,
}

// =====================================================================
// Path Validator — PATH_CHALLENGE / PATH_RESPONSE
// =====================================================================

/// PATH_CHALLENGE frame (8 bytes of random data).
#[derive(Debug, Clone)]
pub struct PathChallenge {
    pub data: [u8; 8],
}

/// PATH_RESPONSE frame (echoes the challenge data).
#[derive(Debug, Clone)]
pub struct PathResponse {
    pub data: [u8; 8],
}

/// Path validation state tracker.
pub struct PathValidator {
    /// Pending challenges: path_id → (challenge_data, sent_at)
    pending: RwLock<HashMap<PathId, ([u8; 8], Instant)>>,
    /// Validation timeout
    timeout: Duration,
}

impl PathValidator {
    /// Create a new path validator.
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            timeout,
        }
    }

    /// Send a PATH_CHALLENGE for a path.
    pub async fn challenge(&self, path_id: PathId) -> PathChallenge {
        let mut data = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
        self.pending.write().await.insert(path_id, (data, Instant::now()));
        PathChallenge { data }
    }

    /// Receive a PATH_RESPONSE and validate.
    pub async fn validate_response(&self, path_id: PathId, response: PathResponse) -> bool {
        let pending = self.pending.read().await;
        if let Some((expected, sent_at)) = pending.get(&path_id) {
            if *expected == response.data && sent_at.elapsed() < self.timeout {
                return true;
            }
        }
        false
    }

    /// Clean up expired pending challenges.
    pub async fn cleanup_expired(&self) -> usize {
        let mut pending = self.pending.write().await;
        let before = pending.len();
        pending.retain(|_, (_, sent_at)| sent_at.elapsed() < self.timeout);
        before - pending.len()
    }
}

// =====================================================================
// Errors
// =====================================================================

#[derive(Debug, thiserror::Error)]
pub enum MultipathError {
    #[error("Maximum number of paths ({MAX_PATHS}) reached")]
    TooManyPaths,

    #[error("Path not found")]
    PathNotFound,

    #[error("Cannot abandon primary path (path_id=0)")]
    CannotAbandonPrimary,

    #[error("Path is closed")]
    PathClosed,

    #[error("Seamless failover is disabled")]
    FailoverDisabled,

    #[error("No alternative path available for failover")]
    NoAlternativePath,

    #[error("Path validation timed out")]
    ValidationTimeout,

    #[error("Multipath not negotiated")]
    NotNegotiated,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_path(id: PathId, rtt_us: u64, bw_bps: u64) -> MultipathEntry {
        MultipathEntry {
            path_id: id,
            local_addr: "127.0.0.1:9000".parse().unwrap(),
            remote_addr: "127.0.0.1:9001".parse().unwrap(),
            state: PathState::Active,
            established_at: Instant::now(),
            quality: PathQuality {
                srtt_us: rtt_us,
                bandwidth_bps: bw_bps,
                ..Default::default()
            },
            congestion: PathCongestion::default(),
            priority: 0,
            active: true,
        }
    }

    #[test]
    fn test_scheduler_lowest_rtt() {
        let paths = vec![
            make_test_path(1, 50_000, 100_000_000),
            make_test_path(2, 10_000, 50_000_000),
            make_test_path(3, 100_000, 200_000_000),
        ];
        let refs: Vec<&MultipathEntry> = paths.iter().collect();

        let mut scheduler = MultipathScheduler::new(SchedulerStrategy::LowestRttFirst);
        let chosen = scheduler.schedule_packet(&refs);
        assert_eq!(chosen, Some(2)); // Path 2 has lowest RTT
    }

    #[test]
    fn test_scheduler_round_robin() {
        let paths = vec![
            make_test_path(1, 50_000, 100_000_000),
            make_test_path(2, 10_000, 50_000_000),
        ];
        let refs: Vec<&MultipathEntry> = paths.iter().collect();

        let mut scheduler = MultipathScheduler::new(SchedulerStrategy::RoundRobin);
        assert_eq!(scheduler.schedule_packet(&refs), Some(1));
        assert_eq!(scheduler.schedule_packet(&refs), Some(2));
        assert_eq!(scheduler.schedule_packet(&refs), Some(1));
    }

    #[test]
    fn test_latency_tier() {
        assert_eq!(LatencyTier::from(5_000), LatencyTier::UltraLow);
        assert_eq!(LatencyTier::from(30_000), LatencyTier::Low);
        assert_eq!(LatencyTier::from(100_000), LatencyTier::Medium);
        assert_eq!(LatencyTier::from(200_000), LatencyTier::High);
        assert_eq!(LatencyTier::from(500_000), LatencyTier::Satellite);
    }

    #[tokio::test]
    async fn test_multipath_connection_lifecycle() {
        let conn = MultipathQuicConnection::new(
            b"test-conn-001".to_vec(),
            MultipathConfig::default(),
        );

        // Add paths
        let p1 = conn.add_path(
            "10.0.0.1:9000".parse().unwrap(),
            "10.0.0.2:9000".parse().unwrap(),
        ).await.unwrap();

        let p2 = conn.add_path(
            "192.168.1.1:9000".parse().unwrap(),
            "192.168.1.2:9000".parse().unwrap(),
        ).await.unwrap();

        // Activate paths
        conn.activate_path(p1).await.unwrap();
        conn.activate_path(p2).await.unwrap();

        // Update quality
        conn.update_path_quality(p1, 15_000, 0.001, 100_000_000).await.unwrap();
        conn.update_path_quality(p2, 45_000, 0.002, 50_000_000).await.unwrap();

        let stats = conn.stats().await;
        assert_eq!(stats.total_paths, 2);
        assert_eq!(stats.active_paths, 2);

        // Test failover
        let _ = conn.abandon_path(p2).await;
        let result = conn.seamless_failover(p2).await;
        assert!(result.is_ok());
    }
}
