//! Babel Routing Protocol — RFC 8966 (Phase 3 Stage 2).
//!
//! Babel is a loop-avoiding distance-vector routing protocol designed for
//! wireless mesh and ad-hoc networks. It uses:
//! - Feasibility conditions (based on DSDV) for loop avoidance
//! - Sequenced route updates with feasibility distance
//! - Triggered updates on metric changes
//! - Hello protocol for neighbor discovery
//! - IHU (I Heard You) for bidirectional link quality
//!
//! This implementation targets Babel-Z (RFC 8966) with extensions
//! for P2P mesh: relay election and multi-path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Babel sequence number (16-bit, wraps around per RFC).
pub type SeqNo = u16;

/// Babel router ID (unique per node, 64-bit).
pub type RouterId = u64;

/// Feasibility distance for a route (the "fd" value in Babel).
pub type FeasibilityDistance = u32;

/// Babel metric (1-65535, with special values).
pub type BabelMetric = u16;
pub const BABEL_INFINITY: BabelMetric = 0xFFFF;

/// A Babel neighbor.
#[derive(Debug, Clone)]
pub struct BabelNeighbor {
    /// Neighbor router ID
    pub router_id: RouterId,
    /// Neighbor address
    pub addr: SocketAddr,
    /// Last Hello received from neighbor
    pub last_hello: Instant,
    /// Last IHU sent to neighbor
    pub last_ihu: Instant,
    /// Link quality: received hello count / expected count (0.0-1.0)
    pub rxcost: u16,
    /// Whether this neighbor is bidirectional (we received IHU)
    pub reachable: bool,
    /// Hello interval for this neighbor
    pub hello_interval: Duration,
    /// Neighbor's current sequence number
    pub seqno: SeqNo,
}

fn instant_now() -> Instant { Instant::now() }

/// A Babel route entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BabelRoute {
    /// Destination prefix
    pub prefix: Ipv4Net,
    /// Router ID of the originator
    pub router_id: RouterId,
    /// Next hop neighbor router ID
    pub next_hop: RouterId,
    /// Current metric to destination
    pub metric: BabelMetric,
    /// Feasibility distance (metric at time of last route increase)
    pub feasibility_distance: FeasibilityDistance,
    /// Source sequence number (from originator)
    pub seqno: SeqNo,
    /// Whether this route is selected (in routing table)
    pub selected: bool,
    /// When this route was last updated
    #[serde(skip, default = "instant_now")]
    pub updated: Instant,
    /// Route expiry time
    #[serde(skip, default = "instant_now")]
    pub expires: Instant,
    /// Whether this is a retracted route
    pub retracted: bool,
}

/// Babel Protocol Engine.
pub struct BabelProtocol {
    /// Our router ID
    router_id: RouterId,
    /// Neighbors table
    neighbors: RwLock<HashMap<RouterId, BabelNeighbor>>,
    /// Route table (prefix → list of route entries)
    route_table: RwLock<HashMap<Ipv4Net, Vec<BabelRoute>>>,
    /// Selected routes (prefix → selected BabelRoute)
    selected_routes: RwLock<HashMap<Ipv4Net, BabelRoute>>,
    /// Our current sequence number
    seqno: RwLock<SeqNo>,
    /// Hello interval
    hello_interval: Duration,
    /// IHU interval
    ihu_interval: Duration,
    /// Route hold time (routes expire after this)
    hold_time: Duration,
}

impl BabelProtocol {
    /// Create a new Babel protocol instance.
    pub fn new(router_id: RouterId) -> Self {
        Self {
            router_id,
            neighbors: RwLock::new(HashMap::new()),
            route_table: RwLock::new(HashMap::new()),
            selected_routes: RwLock::new(HashMap::new()),
            seqno: RwLock::new(0),
            hello_interval: Duration::from_secs(4),
            ihu_interval: Duration::from_secs(4),
            hold_time: Duration::from_secs(20),
        }
    }

    /// Build a Hello message.
    pub fn build_hello(&self) -> BabelMessage {
        BabelMessage {
            msg_type: BabelMsgType::Hello,
            router_id: self.router_id,
            seqno: 0, // Hello doesn't use seqno
            prefix: None,
            metric: 0,
            feasibility_distance: 0,
            interval: self.hello_interval,
        }
    }

    /// Build an IHU (I Heard You) message.
    pub fn build_ihu(&self, _neighbor_id: RouterId, rxcost: u16) -> BabelMessage {
        BabelMessage {
            msg_type: BabelMsgType::Ihu,
            router_id: self.router_id,
            seqno: 0,
            prefix: None,
            metric: rxcost,
            feasibility_distance: 0,
            interval: self.ihu_interval,
        }
    }

    /// Build an Update message for route advertisement.
    pub async fn build_update(
        &self,
        prefix: Ipv4Net,
        metric: BabelMetric,
        feasibility_distance: FeasibilityDistance,
    ) -> BabelMessage {
        let mut seqno = self.seqno.write().await;

        // Increment sequence number when advertising a significant route change
        // (e.g., route becomes unreachable or metric increases significantly)
        *seqno = seqno.wrapping_add(1);

        BabelMessage {
            msg_type: BabelMsgType::Update,
            router_id: self.router_id,
            seqno: *seqno,
            prefix: Some(prefix),
            metric,
            feasibility_distance,
            interval: self.hello_interval,
        }
    }

    /// Process an incoming Babel message.
    pub async fn process_message(
        &self,
        msg: BabelMessage,
        from_addr: SocketAddr,
    ) -> Option<Vec<BabelRoute>> {
        match msg.msg_type {
            BabelMsgType::Hello => {
                self.process_hello(msg.router_id, from_addr, msg.interval).await;
                None
            }
            BabelMsgType::Ihu => {
                self.process_ihu(msg.router_id, msg.metric).await;
                None
            }
            BabelMsgType::Update => {
                Some(self.process_update(msg).await)
            }
            BabelMsgType::Request => {
                None // Handled by build_full_update
            }
        }
    }

    /// Process a Hello message from a neighbor.
    async fn process_hello(
        &self,
        neighbor_id: RouterId,
        neighbor_addr: SocketAddr,
        interval: Duration,
    ) {
        let mut neighbors = self.neighbors.write().await;

        let neighbor = neighbors.entry(neighbor_id).or_insert_with(|| {
            log::info!("Babel: New neighbor {} at {}", neighbor_id, neighbor_addr);
            BabelNeighbor {
                router_id: neighbor_id,
                addr: neighbor_addr,
                last_hello: Instant::now(),
                last_ihu: Instant::now(),
                rxcost: 0,
                reachable: false,
                hello_interval: interval,
                seqno: 0,
            }
        });

        neighbor.last_hello = Instant::now();
        neighbor.addr = neighbor_addr;

        // Update RX cost based on received Hello frequency
        let expected_hellos = neighbor.hello_interval.as_secs() as u16;
        neighbor.rxcost = 65535 / expected_hellos.max(1);
    }

    /// Process an IHU message (bidirectional confirmation).
    async fn process_ihu(&self, neighbor_id: RouterId, rxcost: u16) {
        let mut neighbors = self.neighbors.write().await;
        if let Some(neighbor) = neighbors.get_mut(&neighbor_id) {
            neighbor.reachable = true;
            neighbor.last_ihu = Instant::now();
            neighbor.rxcost = rxcost;
        }
    }

    /// Process a route Update message.
    async fn process_update(&self, msg: BabelMessage) -> Vec<BabelRoute> {
        let prefix = match msg.prefix {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut routes = self.route_table.write().await;
        let prefix_routes = routes.entry(prefix).or_default();

        // Check if this is a retraction (metric == INFINITY)
        if msg.metric == BABEL_INFINITY {
            // Remove routes from this originator
            prefix_routes.retain(|r| r.router_id != msg.router_id);
            let is_empty = prefix_routes.is_empty();
            drop(routes);
            // If all routes for this prefix are gone, remove from selected table
            if is_empty {
                self.selected_routes.write().await.remove(&prefix);
            }
            log::info!("Babel: Route retraction for {} from router {}", prefix, msg.router_id);
            return Vec::new();
        }

        // Check feasibility condition (loop avoidance)
        let is_feasible = prefix_routes
            .iter()
            .filter(|r| r.router_id == msg.router_id)
            .any(|r| msg.feasibility_distance < r.feasibility_distance || msg.seqno > r.seqno);

        if !is_feasible && !prefix_routes.is_empty() {
            log::debug!("Babel: Update for {} from {} failed feasibility check", prefix, msg.router_id);
            return prefix_routes.clone();
        }

        // Add/update the route
        let now = Instant::now();
        let new_route = BabelRoute {
            prefix,
            router_id: msg.router_id,
            next_hop: msg.router_id,
            metric: msg.metric,
            feasibility_distance: msg.feasibility_distance,
            seqno: msg.seqno,
            selected: false,
            updated: now,
            expires: now + self.hold_time,
            retracted: false,
        };

        // Replace existing route from same originator
        prefix_routes.retain(|r| r.router_id != msg.router_id);
        prefix_routes.push(new_route);

        // Update selected route for this prefix
        let best = prefix_routes
            .iter()
            .filter(|r| !r.retracted)
            .min_by_key(|r| r.metric)
            .cloned();

        if let Some(mut best_route) = best {
            best_route.selected = true;
            let mut selected = self.selected_routes.write().await;
            selected.insert(prefix, best_route.clone());
        }

        log::debug!("Babel: Updated route {} → metric {} (feasibility {})",
            prefix, msg.metric, msg.feasibility_distance);

        prefix_routes.clone()
    }

    /// Select the best route for each prefix (route selection).
    async fn select_routes(&self) {
        let routes = self.route_table.read().await;
        let mut selected = self.selected_routes.write().await;

        for (prefix, prefix_routes) in routes.iter() {
            let best = prefix_routes
                .iter()
                .filter(|r| !r.retracted)
                .filter(|r| r.expires > Instant::now())
                .min_by_key(|r| r.metric)
                .cloned();

            if let Some(mut best_route) = best {
                best_route.selected = true;
                selected.insert(*prefix, best_route);
            } else {
                selected.remove(prefix);
            }
        }
    }

    /// Get the current routing table (for data plane).
    pub async fn get_routing_table(&self) -> Vec<BabelRoute> {
        let selected = self.selected_routes.read().await;
        selected.values().cloned().collect()
    }

    /// Remove a neighbor (on disconnect).
    pub async fn remove_neighbor(&self, neighbor_id: RouterId) {
        let mut neighbors = self.neighbors.write().await;
        neighbors.remove(&neighbor_id);

        // Mark all routes via this neighbor as retracted
        let mut routes = self.route_table.write().await;
        for (_, prefix_routes) in routes.iter_mut() {
            for route in prefix_routes.iter_mut() {
                if route.next_hop == neighbor_id {
                    route.retracted = true;
                }
            }
        }
        log::info!("Babel: Removed neighbor {}", neighbor_id);
    }

    /// Get all reachable neighbors.
    pub async fn get_neighbors(&self) -> Vec<BabelNeighbor> {
        let neighbors = self.neighbors.read().await;
        neighbors.values().cloned().collect()
    }
}

/// Babel message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BabelMsgType {
    Hello,
    Ihu,
    Update,
    Request,
}

/// Babel protocol message (generic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BabelMessage {
    pub msg_type: BabelMsgType,
    pub router_id: RouterId,
    pub seqno: SeqNo,
    pub prefix: Option<Ipv4Net>,
    pub metric: BabelMetric,
    pub feasibility_distance: FeasibilityDistance,
    pub interval: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_babel_hello_creates_neighbor() {
        let babel = BabelProtocol::new(1);
        let hello = babel.build_hello();
        let addr = "10.0.0.1:9999".parse().unwrap();

        babel.process_message(hello, addr).await;

        let neighbors = babel.get_neighbors().await;
        assert_eq!(neighbors.len(), 1);
        assert!(neighbors[0].router_id == 1);
    }

    #[tokio::test]
    async fn test_babel_route_update() {
        let babel = BabelProtocol::new(100);
        let prefix = Ipv4Net::from_str("100.64.1.0/24").unwrap();

        let update = babel.build_update(prefix, 10, 5).await;
        let addr = "10.0.0.2:9999".parse().unwrap();

        babel.process_message(update, addr).await;

        let routes = babel.get_routing_table().await;
        assert!(!routes.is_empty());
    }

    #[tokio::test]
    async fn test_babel_route_retraction() {
        let babel = BabelProtocol::new(100);
        let prefix = Ipv4Net::from_str("100.64.1.0/24").unwrap();

        // First add a route
        let update = babel.build_update(prefix, 10, 5).await;
        let addr = "10.0.0.2:9999".parse().unwrap();
        babel.process_message(update, addr).await;

        // Retract the route
        let retract = BabelMessage {
            msg_type: BabelMsgType::Update,
            router_id: 100,
            seqno: 0,
            prefix: Some(prefix),
            metric: BABEL_INFINITY,
            feasibility_distance: 0,
            interval: Duration::from_secs(4),
        };
        babel.process_message(retract, addr).await;

        let routes = babel.get_routing_table().await;
        assert!(routes.is_empty());
    }
}
