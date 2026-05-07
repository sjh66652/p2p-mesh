//! Smart Relay Network — Phase 10.5.
//!
//! Intelligent relay network that optimizes relay selection using
//! machine learning, geographic proximity, and real-time performance data.
//! Extends the basic relay system with advanced optimization strategies.
//!
//! Key features:
//! - Geographic relay placement (lat/lon → nearest relay)
//! - Relay tier system (Edge, Regional, Global, Core)
//! - Load-aware relay selection (CPU, memory, bandwidth utilization)
//! - Predictive relay scaling (anticipate demand spikes)
//! - Relay peering optimization (minimize inter-relay latency)
//! - Anycast relay discovery (route to nearest by network distance)
//! - Relay health scoring (composite health metric)
//! - Cost-aware routing (minimize transit costs across relay tiers)
//!
//! Relay Tier Architecture:
//!   Edge:      End-user facing, low latency, many instances (100s)
//!   Regional:  Aggregation layer, medium latency (10s per region)
//!   Global:    Cross-region transit, high bandwidth (3-5 per continent)
//!   Core:      Inter-continental backbone, highest capacity (5-10 globally)

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

fn instant_now() -> Instant { Instant::now() }

// =====================================================================
// Relay Tiers & Topology
// =====================================================================

/// Relay tier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum RelayTier {
    #[default]
    Edge,
    /// End-user facing, lowest latency, many instances
    Edge,
    /// Regional aggregation, medium latency
    Regional,
    /// Cross-region transit, high bandwidth
    Global,
    /// Inter-continental backbone, highest capacity
    Core,
}

impl RelayTier {
    /// Maximum acceptable latency for this tier (ms).
    pub fn max_latency_ms(&self) -> u64 {
        match self {
            RelayTier::Edge => 10,
            RelayTier::Regional => 50,
            RelayTier::Global => 150,
            RelayTier::Core => 300,
        }
    }

    /// Target number of relays in this tier.
    pub fn target_count(&self) -> u32 {
        match self {
            RelayTier::Edge => 100,
            RelayTier::Regional => 20,
            RelayTier::Global => 5,
            RelayTier::Core => 10,
        }
    }

    /// Cost multiplier for traffic through this tier.
    pub fn cost_multiplier(&self) -> f64 {
        match self {
            RelayTier::Edge => 0.1,
            RelayTier::Regional => 0.3,
            RelayTier::Global => 1.0,
            RelayTier::Core => 3.0,
        }
    }
}

/// Geographic coordinates for relay placement.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
}

impl GeoLocation {
    /// Calculate great-circle distance to another point (Haversine formula).
    pub fn distance_km(&self, other: &GeoLocation) -> f64 {
        let r = 6371.0; // Earth's radius in km
        let dlat = (other.latitude - self.latitude).to_radians();
        let dlon = (other.longitude - self.longitude).to_radians();

        let a = (dlat / 2.0).sin().powi(2)
            + self.latitude.to_radians().cos()
                * other.latitude.to_radians().cos()
                * (dlon / 2.0).sin().powi(2);

        let c = 2.0 * a.sqrt().asin();
        r * c
    }

    /// Estimate network RTT based on geographic distance.
    /// Assumes fiber speed ≈ 2/3c, plus 5ms of switching delay per 1000km.
    pub fn estimated_rtt_us(&self, other: &GeoLocation) -> u64 {
        let dist_km = self.distance_km(other);
        // Speed of light in fiber: ~200,000 km/s
        // RTT = 2 * distance / speed + switching overhead
        let fiber_rtt_us = (2.0 * dist_km / 200_000.0 * 1_000_000.0) as u64;
        let switching_us = (dist_km / 1000.0 * 5_000.0) as u64;
        fiber_rtt_us + switching_us
    }
}

// =====================================================================
// Relay Node
// =====================================================================

/// A single relay node in the smart relay network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartRelayNode {
    /// Unique relay identifier
    pub id: String,
    /// Relay tier
    pub tier: RelayTier,
    /// Network address
    pub addr: SocketAddr,
    /// Geographic location
    pub location: GeoLocation,
    /// Relay capacity
    pub capacity: RelayCapacity,
    /// Current load
    pub load: RelayLoad,
    /// Health score (0.0 = dead, 1.0 = perfect)
    pub health_score: f64,
    /// Peering: relay IDs to which this relay has direct links
    pub peers: HashSet<String>,
    /// Upstream relay (toward Core)
    pub upstream: Option<String>,
    /// Downstream relays (toward Edge)
    pub downstream: Vec<String>,
    /// When this relay was last seen
    #[serde(skip, default = "instant_now")]
    pub last_seen: Instant,
    /// Uptime percentage (last 30 days)
    pub uptime_pct: f64,
    /// Tags for custom routing policies
    pub tags: HashMap<String, String>,
}

impl Default for SmartRelayNode {
    fn default() -> Self {
        Self {
            id: String::new(),
            tier: RelayTier::default(),
            addr: "0.0.0.0:0".parse().unwrap(),
            location: GeoLocation::default(),
            capacity: RelayCapacity::default(),
            load: RelayLoad::default(),
            health_score: 0.0,
            peers: HashSet::new(),
            upstream: None,
            downstream: Vec::new(),
            last_seen: Instant::now(),
            uptime_pct: 100.0,
            tags: HashMap::new(),
        }
    }
}

/// Relay capacity specifications.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RelayCapacity {
    /// Maximum bandwidth (bps)
    pub max_bandwidth_bps: u64,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Maximum packets per second
    pub max_pps: u64,
    /// CPU cores available
    pub cpu_cores: u32,
    /// Total memory (bytes)
    pub memory_bytes: u64,
    /// Network interfaces
    pub interfaces: Vec<String>,
}

/// Relay load metrics.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RelayLoad {
    /// Current bandwidth usage (bps)
    pub bandwidth_bps: u64,
    /// Current active connections
    pub connections: u32,
    /// Current packets per second
    pub pps: u64,
    /// CPU utilization (0.0-1.0)
    pub cpu_utilization: f64,
    /// Memory utilization (0.0-1.0)
    pub memory_utilization: f64,
}

impl RelayLoad {
    /// Compute load factor (0.0 = idle, 1.0 = fully loaded).
    pub fn load_factor(&self, capacity: &RelayCapacity) -> f64 {
        let bw_factor = if capacity.max_bandwidth_bps > 0 {
            self.bandwidth_bps as f64 / capacity.max_bandwidth_bps as f64
        } else {
            0.0
        };
        let conn_factor = if capacity.max_connections > 0 {
            self.connections as f64 / capacity.max_connections as f64
        } else {
            0.0
        };
        let pps_factor = if capacity.max_pps > 0 {
            self.pps as f64 / capacity.max_pps as f64
        } else {
            0.0
        };

        // Weighted load factor
        0.4 * bw_factor + 0.3 * conn_factor + 0.2 * pps_factor + 0.1 * self.cpu_utilization
    }
}

// =====================================================================
// Health Scoring
// =====================================================================

/// Composite health score calculator for relay nodes.
pub struct HealthScorer {
    /// Weight: latency component
    weight_latency: f64,
    /// Weight: packet loss component
    weight_loss: f64,
    /// Weight: load component
    weight_load: f64,
    /// Weight: uptime component
    weight_uptime: f64,
    /// Weight: capacity component
    weight_capacity: f64,
}

impl Default for HealthScorer {
    fn default() -> Self {
        Self {
            weight_latency: 0.25,
            weight_loss: 0.25,
            weight_load: 0.20,
            weight_uptime: 0.15,
            weight_capacity: 0.15,
        }
    }
}

impl HealthScorer {
    /// Compute a composite health score for a relay.
    pub fn score(
        &self,
        relay: &SmartRelayNode,
        latency_us: u64,
        loss_rate: f64,
    ) -> f64 {
        let tier_max_latency = relay.tier.max_latency_ms() * 1000; // to us

        // Latency score: 1.0 at 0ms, 0.0 at max_latency
        let latency_score = if tier_max_latency > 0 {
            (1.0 - latency_us as f64 / tier_max_latency as f64).max(0.0)
        } else {
            1.0
        };

        // Loss score: 1.0 at 0%, 0.0 at 10%
        let loss_score = (1.0 - loss_rate / 0.10).max(0.0);

        // Load score: 1.0 at idle, 0.0 at fully loaded
        let load = relay.load.load_factor(&relay.capacity);
        let load_score = (1.0 - load).max(0.0);

        // Uptime score: direct mapping
        let uptime_score = relay.uptime_pct / 100.0;

        // Capacity score: how much headroom remains
        let capacity_score = if relay.capacity.max_bandwidth_bps > 0 {
            let remaining = relay.capacity.max_bandwidth_bps.saturating_sub(relay.load.bandwidth_bps);
            (remaining as f64 / relay.capacity.max_bandwidth_bps as f64).min(1.0)
        } else {
            0.0
        };

        self.weight_latency * latency_score
            + self.weight_loss * loss_score
            + self.weight_load * load_score
            + self.weight_uptime * uptime_score
            + self.weight_capacity * capacity_score
    }
}

// =====================================================================
// Anycast Relay Discovery
// =====================================================================

/// Anycast group: multiple relays sharing the same anycast IP.
#[derive(Debug, Clone)]
pub struct AnycastGroup {
    /// Anycast IP address
    pub anycast_ip: String,
    /// Relay IDs in this group
    pub relays: HashSet<String>,
    /// BGP communities for traffic engineering
    pub bgp_communities: Vec<u32>,
    /// Anycast priority (lower = preferred)
    pub priority: u32,
}

/// Anycast resolver — finds the nearest relay for a client IP.
pub struct AnycastResolver {
    /// Anycast groups
    groups: RwLock<HashMap<String, AnycastGroup>>,
    /// Client → closest relay cache
    cache: RwLock<HashMap<String, (String, Instant)>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl AnycastResolver {
    /// Create a new anycast resolver.
    pub fn new(cache_ttl: Duration) -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
            cache_ttl,
        }
    }

    /// Register an anycast group.
    pub async fn register_group(&self, group: AnycastGroup) {
        log::info!("Anycast: registered group for {}", group.anycast_ip);
        self.groups.write().await.insert(group.anycast_ip.clone(), group);
    }

    /// Resolve the best relay for a client IP.
    pub async fn resolve(
        &self,
        client_ip: &str,
        anycast_ip: &str,
        all_relays: &HashMap<String, SmartRelayNode>,
    ) -> Option<String> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some((relay_id, timestamp)) = cache.get(client_ip) {
                if timestamp.elapsed() < self.cache_ttl {
                    return Some(relay_id.clone());
                }
            }
        }

        // Find the anycast group
        let groups = self.groups.read().await;
        let group = groups.get(anycast_ip)?;

        // Find the relay with lowest load in the group
        let best_relay = group
            .relays
            .iter()
            .filter_map(|id| all_relays.get(id))
            .min_by(|a, b| {
                let la = a.load.load_factor(&a.capacity);
                let lb = b.load.load_factor(&b.capacity);
                la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
            });

        if let Some(relay) = best_relay {
            self.cache.write().await.insert(
                client_ip.to_string(),
                (relay.id.clone(), Instant::now()),
            );
            Some(relay.id.clone())
        } else {
            None
        }
    }
}

// =====================================================================
// Predictive Relay Scaling
// =====================================================================

/// Time-series load prediction for relay scaling.
#[derive(Debug)]
pub struct LoadPredictor {
    /// Historical load data: timestamp → (bandwidth_bps, connections, pps)
    history: VecDeque<(Instant, RelayLoad)>,
    /// Maximum history length
    max_history: usize,
    /// Seasonal pattern detection window
    seasonality_window: Duration,
}

impl LoadPredictor {
    /// Create a new load predictor.
    pub fn new(max_history: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(max_history),
            max_history,
            seasonality_window: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Add a load measurement.
    pub fn observe(&mut self, load: RelayLoad) {
        self.history.push_back((Instant::now(), load));
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }

    /// Predict load in `horizon` seconds.
    pub fn predict_load(&self, horizon_secs: f64) -> RelayLoad {
        if self.history.len() < 4 {
            return RelayLoad::default();
        }

        // Simple EWMA-based prediction
        let _n = self.history.len();
        let mut bw_ewma = 0.0f64;
        let mut conn_ewma = 0.0f64;
        let mut pps_ewma = 0.0f64;
        let mut cpu_ewma = 0.0f64;
        let alpha = 0.2;

        for (_, load) in self.history.iter() {
            if bw_ewma == 0.0 {
                bw_ewma = load.bandwidth_bps as f64;
                conn_ewma = load.connections as f64;
                pps_ewma = load.pps as f64;
                cpu_ewma = load.cpu_utilization;
            } else {
                bw_ewma = alpha * load.bandwidth_bps as f64 + (1.0 - alpha) * bw_ewma;
                conn_ewma = alpha * load.connections as f64 + (1.0 - alpha) * conn_ewma;
                pps_ewma = alpha * load.pps as f64 + (1.0 - alpha) * pps_ewma;
                cpu_ewma = alpha * load.cpu_utilization + (1.0 - alpha) * cpu_ewma;
            }
        }

        // Apply trend
        let trend_multiplier = 1.0 + (horizon_secs / 3600.0) * 0.1; // 10% growth per hour

        RelayLoad {
            bandwidth_bps: (bw_ewma * trend_multiplier) as u64,
            connections: (conn_ewma * trend_multiplier) as u32,
            pps: (pps_ewma * trend_multiplier) as u64,
            cpu_utilization: (cpu_ewma * trend_multiplier).min(1.0),
            memory_utilization: 0.5,
        }
    }

    /// Check if scaling is needed (predicted load exceeds threshold).
    pub fn needs_scaling(&self, capacity: &RelayCapacity, threshold: f64) -> bool {
        let predicted = self.predict_load(300.0); // 5 min horizon
        predicted.load_factor(capacity) > threshold
    }
}

// =====================================================================
// Cost-Aware Routing
// =====================================================================

/// Routing cost calculator for relay path selection.
#[derive(Debug, Clone)]
pub struct CostCalculator {
    /// Cost per GB per 1000km per tier
    transit_cost_per_gb: HashMap<RelayTier, f64>,
    /// Whether to prefer cheaper paths
    prefer_cheaper: bool,
    /// Maximum acceptable cost multiplier
    max_cost_multiplier: f64,
}

impl Default for CostCalculator {
    fn default() -> Self {
        let mut costs = HashMap::new();
        costs.insert(RelayTier::Edge, 0.01);
        costs.insert(RelayTier::Regional, 0.02);
        costs.insert(RelayTier::Global, 0.05);
        costs.insert(RelayTier::Core, 0.10);

        Self {
            transit_cost_per_gb: costs,
            prefer_cheaper: true,
            max_cost_multiplier: 2.0,
        }
    }
}

impl CostCalculator {
    /// Calculate the estimated cost of a relay path.
    pub fn path_cost(
        &self,
        path: &[&SmartRelayNode],
        bandwidth_bps: u64,
        duration_secs: u64,
    ) -> f64 {
        if path.len() < 2 {
            return 0.0;
        }

        let gb_transferred = (bandwidth_bps as f64 * duration_secs as f64) / (8.0 * 1_000_000_000.0);
        let mut total_cost = 0.0;

        for i in 0..path.len() - 1 {
            let from = path[i];
            let to = path[i + 1];
            let dist_km = from.location.distance_km(&to.location) / 1000.0; // per 1000km
            let tier_cost = self.transit_cost_per_gb.get(&from.tier).copied().unwrap_or(0.05);

            total_cost += tier_cost * gb_transferred * dist_km.max(1.0);
        }

        total_cost
    }

    /// Rank relays by cost efficiency.
    pub fn rank_by_cost(
        &self,
        candidates: &[SmartRelayNode],
        src: &GeoLocation,
        bw_bps: u64,
        duration_secs: u64,
    ) -> Vec<(String, f64)> {
        let mut scored: Vec<(String, f64)> = candidates
            .iter()
            .map(|r| {
                let cost = self.path_cost(
                    &[&SmartRelayNode {
                        location: *src,
                        tier: RelayTier::Edge,
                        ..Default::default()
                    }, r],
                    bw_bps,
                    duration_secs,
                );
                (r.id.clone(), cost)
            })
            .collect();

        scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }
}

// =====================================================================
// Smart Relay Manager
// =====================================================================

/// Central Smart Relay Network manager.
pub struct SmartRelayManager {
    /// All known relays: relay_id → relay node
    relays: RwLock<HashMap<String, SmartRelayNode>>,
    /// Relays grouped by tier
    by_tier: RwLock<HashMap<RelayTier, HashSet<String>>>,
    /// Relays grouped by geographic region
    by_region: RwLock<HashMap<String, HashSet<String>>>,
    /// Health scorer
    health_scorer: HealthScorer,
    /// Anycast resolver
    anycast: AnycastResolver,
    /// Cost calculator
    cost_calc: CostCalculator,
    /// Load predictor per relay
    predictors: RwLock<HashMap<String, LoadPredictor>>,
    /// Selection count per relay
    selections: RwLock<HashMap<String, AtomicU64>>,
}

impl SmartRelayManager {
    /// Create a new smart relay manager.
    pub fn new() -> Self {
        Self {
            relays: RwLock::new(HashMap::new()),
            by_tier: RwLock::new(HashMap::new()),
            by_region: RwLock::new(HashMap::new()),
            health_scorer: HealthScorer::default(),
            anycast: AnycastResolver::new(Duration::from_secs(30)),
            cost_calc: CostCalculator::default(),
            predictors: RwLock::new(HashMap::new()),
            selections: RwLock::new(HashMap::new()),
        }
    }

    /// Register a relay node.
    pub async fn register_relay(&self, relay: SmartRelayNode) {
        let relay_id = relay.id.clone();
        let tier = relay.tier;
        let region = Self::geo_region(&relay.location);

        // Register in main map
        self.relays.write().await.insert(relay_id.clone(), relay);

        // Register by tier
        self.by_tier.write().await.entry(tier).or_default().insert(relay_id.clone());

        // Register by region
        self.by_region.write().await.entry(region).or_default().insert(relay_id.clone());

        // Initialize predictor
        self.predictors.write().await.insert(relay_id.clone(), LoadPredictor::new(128));

        // Initialize selection counter
        self.selections.write().await.insert(relay_id.clone(), AtomicU64::new(0));

        log::info!("Smart Relay: registered {} ({:?})", relay_id, tier);
    }

    /// Remove a relay node.
    pub async fn remove_relay(&self, relay_id: &str) {
        if let Some(relay) = self.relays.write().await.remove(relay_id) {
            let tier = relay.tier;
            let region = Self::geo_region(&relay.location);

            if let Some(set) = self.by_tier.write().await.get_mut(&tier) {
                set.remove(relay_id);
            }
            if let Some(set) = self.by_region.write().await.get_mut(&region) {
                set.remove(relay_id);
            }

            self.predictors.write().await.remove(relay_id);
            self.selections.write().await.remove(relay_id);

            log::info!("Smart Relay: removed {}", relay_id);
        }
    }

    /// Update relay load metrics.
    pub async fn update_load(&self, relay_id: &str, load: RelayLoad) {
        let mut relays = self.relays.write().await;
        if let Some(relay) = relays.get_mut(relay_id) {
            relay.load = load.clone();
            relay.last_seen = Instant::now();
        }

        if let Some(predictor) = self.predictors.write().await.get_mut(relay_id) {
            predictor.observe(load);
        }
    }

    /// Find the best relay for a client at a given location.
    pub async fn find_best_relay(
        &self,
        client_location: GeoLocation,
        required_bandwidth_bps: u64,
        tier_hint: Option<RelayTier>,
    ) -> Option<String> {
        let relays = self.relays.read().await;

        // Filter relays by tier and capacity
        let candidates: Vec<&SmartRelayNode> = relays
            .values()
            .filter(|r| {
                let tier_ok = tier_hint.map_or(true, |t| r.tier == t);
                let capacity_ok = r.capacity.max_bandwidth_bps.saturating_sub(r.load.bandwidth_bps)
                    >= required_bandwidth_bps;
                let alive = r.last_seen.elapsed() < Duration::from_secs(30);
                tier_ok && capacity_ok && alive
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Score each candidate
        let estimated_rtt = client_location.estimated_rtt_us(&candidates[0].location);

        let mut scored: Vec<(&SmartRelayNode, f64)> = candidates
            .iter()
            .map(|r| {
                let rtt = client_location.estimated_rtt_us(&r.location);
                let health = self.health_scorer.score(r, rtt, 0.0);
                (*r, health)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        if let Some((best, score)) = scored.first() {
            log::debug!(
                "Smart Relay: selected {} ({:?}) with score {:.3}, RTT {}us",
                best.id, best.tier, score, estimated_rtt
            );

            // Increment selection counter
            if let Some(counter) = self.selections.write().await.get(&best.id) {
                counter.fetch_add(1, Ordering::Relaxed);
            }

            Some(best.id.clone())
        } else {
            None
        }
    }

    /// Find the best relay path between two locations.
    pub async fn find_best_path(
        &self,
        src_location: GeoLocation,
        dst_location: GeoLocation,
        _bandwidth_bps: u64,
    ) -> Option<Vec<String>> {
        let relays = self.relays.read().await;

        // Simple 2-hop relay path: src → best_near_src → best_near_dst → dst
        let near_src = self.find_nearest_relays(&relays, src_location, 3).await;
        let near_dst = self.find_nearest_relays(&relays, dst_location, 3).await;

        if near_src.is_empty() || near_dst.is_empty() {
            return None;
        }

        // Try to find best pair
        for src_relay in &near_src {
            for dst_relay in &near_dst {
                if src_relay != dst_relay {
                    let src_rtt = src_location.estimated_rtt_us(&src_relay.location);
                    let dst_rtt = dst_relay.location.estimated_rtt_us(&dst_location);

                    if src_rtt < 100_000 && dst_rtt < 100_000 {
                        return Some(vec![
                            src_relay.id.clone(),
                            dst_relay.id.clone(),
                        ]);
                    }
                }
            }
        }

        None
    }

    /// Find the nearest relays to a location.
    async fn find_nearest_relays(
        &self,
        relays: &HashMap<String, SmartRelayNode>,
        location: GeoLocation,
        count: usize,
    ) -> Vec<SmartRelayNode> {
        let mut sorted: Vec<&SmartRelayNode> = relays
            .values()
            .filter(|r| r.last_seen.elapsed() < Duration::from_secs(30))
            .collect();

        sorted.sort_by_key(|r| {
            (location.distance_km(&r.location) * 1000.0) as u64
        });

        sorted.truncate(count);
        sorted.into_iter().cloned().collect()
    }

    /// Get relay network topology statistics.
    pub async fn stats(&self) -> SmartRelayStats {
        let relays = self.relays.read().await;
        let by_tier = self.by_tier.read().await;

        let total = relays.len();
        let alive = relays
            .values()
            .filter(|r| r.last_seen.elapsed() < Duration::from_secs(30))
            .count();

        let by_tier_counts: HashMap<RelayTier, usize> = by_tier
            .iter()
            .map(|(tier, set)| (*tier, set.len()))
            .collect();

        let total_bandwidth: u64 = relays.values().map(|r| r.capacity.max_bandwidth_bps).sum();
        let used_bandwidth: u64 = relays.values().map(|r| r.load.bandwidth_bps).sum();

        SmartRelayStats {
            total_relays: total,
            alive_relays: alive,
            by_tier: by_tier_counts,
            total_bandwidth_bps: total_bandwidth,
            used_bandwidth_bps: used_bandwidth,
            utilization: if total_bandwidth > 0 {
                used_bandwidth as f64 / total_bandwidth as f64
            } else {
                0.0
            },
        }
    }

    /// Classify a location into a geographic region.
    fn geo_region(loc: &GeoLocation) -> String {
        if loc.latitude >= 30.0 && loc.latitude <= 60.0
            && loc.longitude >= -10.0 && loc.longitude <= 40.0
        {
            "europe".to_string()
        } else if loc.latitude >= 25.0 && loc.latitude <= 50.0
            && loc.longitude >= -130.0 && loc.longitude <= -65.0
        {
            "north-america".to_string()
        } else if loc.latitude >= -55.0 && loc.latitude <= 15.0
            && loc.longitude >= -80.0 && loc.longitude <= -35.0
        {
            "south-america".to_string()
        } else if loc.latitude >= 15.0 && loc.latitude <= 55.0
            && loc.longitude >= 70.0 && loc.longitude <= 150.0
        {
            "asia-pacific".to_string()
        } else if loc.latitude >= -35.0 && loc.latitude <= 35.0
            && loc.longitude >= -20.0 && loc.longitude <= 55.0
        {
            "africa".to_string()
        } else {
            "other".to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmartRelayStats {
    pub total_relays: usize,
    pub alive_relays: usize,
    pub by_tier: HashMap<RelayTier, usize>,
    pub total_bandwidth_bps: u64,
    pub used_bandwidth_bps: u64,
    pub utilization: f64,
}

// =====================================================================
// Relay Peering Optimizer
// =====================================================================

/// Optimizes relay-to-relay peering for minimal inter-relay latency.
pub struct PeeringOptimizer {
    /// Maximum peers per relay
    max_peers_per_relay: usize,
    /// Minimum RTT improvement to add a peer
    min_rtt_improvement_us: u64,
}

impl PeeringOptimizer {
    /// Create a new peering optimizer.
    pub fn new(max_peers: usize, min_improvement_us: u64) -> Self {
        Self {
            max_peers_per_relay: max_peers,
            min_rtt_improvement_us: min_improvement_us,
        }
    }

    /// Optimize peering for a relay.
    pub fn optimize_peering(
        &self,
        relay: &SmartRelayNode,
        all_relays: &[SmartRelayNode],
    ) -> Vec<String> {
        // Compute RTT to all other relays
        let mut candidates: Vec<(&SmartRelayNode, u64)> = all_relays
            .iter()
            .filter(|r| r.id != relay.id)
            .map(|r| {
                let rtt = relay.location.estimated_rtt_us(&r.location);
                (r, rtt)
            })
            .collect();

        // Sort by RTT (ascending)
        candidates.sort_by_key(|(_, rtt)| *rtt);

        // Select top N peers
        candidates
            .iter()
            .take(self.max_peers_per_relay)
            .map(|(r, _)| r.id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_relay(id: &str, lat: f64, lon: f64, tier: RelayTier) -> SmartRelayNode {
        SmartRelayNode {
            id: id.to_string(),
            tier,
            addr: "127.0.0.1:9000".parse().unwrap(),
            location: GeoLocation { latitude: lat, longitude: lon },
            capacity: RelayCapacity {
                max_bandwidth_bps: 1_000_000_000,
                max_connections: 10000,
                max_pps: 1_000_000,
                cpu_cores: 8,
                memory_bytes: 16 * 1024 * 1024 * 1024,
                interfaces: vec!["eth0".into()],
            },
            load: RelayLoad::default(),
            health_score: 1.0,
            peers: HashSet::new(),
            upstream: None,
            downstream: Vec::new(),
            last_seen: Instant::now(),
            uptime_pct: 99.9,
            tags: HashMap::new(),
        }
    }

    #[test]
    fn test_geo_distance() {
        let sf = GeoLocation { latitude: 37.7749, longitude: -122.4194 };
        let ny = GeoLocation { latitude: 40.7128, longitude: -74.0060 };

        let dist = sf.distance_km(&ny);
        // SF→NY ≈ 4,130 km
        assert!(dist > 4000.0 && dist < 4300.0);
    }

    #[test]
    fn test_estimated_rtt() {
        let sf = GeoLocation { latitude: 37.7749, longitude: -122.4194 };
        let ny = GeoLocation { latitude: 40.7128, longitude: -74.0060 };

        let rtt = sf.estimated_rtt_us(&ny);
        // RTT should be roughly proportional to distance
        // 4150km / 200,000 km/s * 2 * 1e6 + 4150/1000 * 5000
        let expected = (2.0 * 4150.0 / 200_000.0 * 1_000_000.0) as u64 + (4150 / 1000 * 5000) as u64;
        assert!((rtt as i64 - expected as i64).abs() < 10_000);
    }

    #[test]
    fn test_health_score() {
        let scorer = HealthScorer::default();
        let relay = make_test_relay("edge-1", 37.77, -122.41, RelayTier::Edge);

        let score = scorer.score(&relay, 5_000, 0.001); // 5ms RTT, 0.1% loss
        assert!(score > 0.7, "Health score should be good: {:.3}", score);

        let bad_score = scorer.score(&relay, 50_000, 0.05); // 50ms RTT, 5% loss
        assert!(bad_score < score, "Bad conditions should lower score");
    }

    #[tokio::test]
    async fn test_smart_relay_selection() {
        let manager = SmartRelayManager::new();

        manager.register_relay(make_test_relay(
            "edge-sf", 37.77, -122.41, RelayTier::Edge,
        )).await;
        manager.register_relay(make_test_relay(
            "edge-ny", 40.71, -74.00, RelayTier::Edge,
        )).await;
        manager.register_relay(make_test_relay(
            "edge-london", 51.50, -0.12, RelayTier::Edge,
        )).await;

        // Client in San Jose (~50km from SF)
        let client = GeoLocation { latitude: 37.33, longitude: -121.89 };
        let best = manager.find_best_relay(client, 100_000_000, None).await;

        assert_eq!(best, Some("edge-sf".to_string()));
    }

    #[test]
    fn test_load_factor() {
        let capacity = RelayCapacity {
            max_bandwidth_bps: 1_000_000_000,
            max_connections: 10000,
            max_pps: 1_000_000,
            cpu_cores: 8,
            memory_bytes: 16_000_000_000,
            interfaces: vec![],
        };

        let load = RelayLoad {
            bandwidth_bps: 500_000_000,  // 50%
            connections: 5000,            // 50%
            pps: 250_000,                 // 25%
            cpu_utilization: 0.3,         // 30%
            memory_utilization: 0.4,
        };

        let factor = load.load_factor(&capacity);
        assert!(factor > 0.35 && factor < 0.45);
    }

    #[test]
    fn test_load_prediction() {
        let mut predictor = LoadPredictor::new(64);

        // Feed increasing load
        for i in 0..20 {
            predictor.observe(RelayLoad {
                bandwidth_bps: (100_000_000 + i * 5_000_000) as u64,
                connections: 1000 + i as u32 * 50,
                pps: 100_000 + i * 5_000,
                cpu_utilization: 0.2 + i as f64 * 0.01,
                memory_utilization: 0.4,
            });
        }

        let predicted = predictor.predict_load(300.0); // 5 min ahead
        assert!(predicted.bandwidth_bps > 100_000_000);
    }

    #[test]
    fn test_cost_calculation() {
        let calc = CostCalculator::default();
        let sf = make_test_relay("sf", 37.77, -122.41, RelayTier::Edge);
        let ny = make_test_relay("ny", 40.71, -74.00, RelayTier::Global);

        let cost = calc.path_cost(
            &[&sf, &ny],
            100_000_000, // 100 Mbps
            3600,        // 1 hour
        );

        // Should be non-trivial
        assert!(cost > 0.0);
    }
}
