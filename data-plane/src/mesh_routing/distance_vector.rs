//! Mesh Routing — Distance Vector protocol with split horizon and poison reverse.
//!
//! Implements a simple but functional distance vector routing protocol
//! for the mesh network. This is Phase 3 Stage 1 of the roadmap.
//!
//! Features:
//! - Distance vector with split horizon (prevents count-to-infinity)
//! - Poison reverse for faster convergence
//! - Triggered updates (immediate on metric change)
//! - Periodic full table exchanges
//! - Route hold-down for stability
//! - Hop count limit (16 = infinity, like RIP)

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Maximum hop count (infinity = 16, like RIP).
pub const INFINITY: u32 = 16;

/// A single distance vector route entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DvRoute {
    /// Destination CIDR
    pub cidr: Ipv4Net,
    /// Metric (hop count or composite cost)
    pub metric: u32,
    /// Next hop peer ID
    pub next_hop: String,
    /// When this route was last updated
    pub last_updated: Instant,
    /// Whether this route is in hold-down
    pub hold_down: bool,
    /// Hold-down expiry time
    pub hold_down_until: Option<Instant>,
    /// Route flags
    pub flags: RouteFlags,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct RouteFlags {
    /// Route is directly connected
    pub connected: bool,
    /// Route was learned from a peer
    pub learned: bool,
    /// Route has been poisoned (metric = INFINITY)
    pub poisoned: bool,
    /// Route is static (not learned via DV)
    pub static_route: bool,
}

/// Distance Vector routing table for a single node.
#[derive(Debug, Clone)]
pub struct DistanceVectorTable {
    /// Our node ID
    pub node_id: String,
    /// Destination CIDR → route entry
    pub routes: HashMap<Ipv4Net, DvRoute>,
    /// Peer ID → last received DV update timestamp
    pub peer_updates: HashMap<String, Instant>,
    /// Peer ID → (peer's routing table snapshot)
    pub peer_tables: HashMap<String, HashMap<Ipv4Net, DvRoute>>,
    /// Sequence number for triggered updates
    pub seq_num: u32,
    /// Last full table exchange
    pub last_full_exchange: Instant,
}

/// Distance Vector Protocol Engine.
pub struct DistanceVector {
    /// Local routing table
    table: RwLock<DistanceVectorTable>,
    /// Update interval
    update_interval: Duration,
    /// Hold-down timer
    hold_down_duration: Duration,
    /// Split horizon enabled
    split_horizon: bool,
    /// Poison reverse enabled
    poison_reverse: bool,
}

impl DistanceVector {
    /// Create a new distance vector router.
    pub fn new(node_id: &str) -> Self {
        Self {
            table: RwLock::new(DistanceVectorTable {
                node_id: node_id.to_string(),
                routes: HashMap::new(),
                peer_updates: HashMap::new(),
                peer_tables: HashMap::new(),
                seq_num: 0,
                last_full_exchange: Instant::now(),
            }),
            update_interval: Duration::from_secs(30),
            hold_down_duration: Duration::from_secs(180),
            split_horizon: true,
            poison_reverse: true,
        }
    }

    /// Add a directly connected route.
    pub async fn add_connected_route(&self, cidr: Ipv4Net, metric: u32) {
        let mut table = self.table.write().await;
        table.routes.insert(cidr, DvRoute {
            cidr,
            metric,
            next_hop: table.node_id.clone(),
            last_updated: Instant::now(),
            hold_down: false,
            hold_down_until: None,
            flags: RouteFlags {
                connected: true,
                learned: false,
                poisoned: false,
                static_route: false,
            },
        });
        log::info!("DV: Added connected route {} (metric={})", cidr, metric);
    }

    /// Process an incoming distance vector update from a peer.
    ///
    /// Bellman-Ford with split horizon:
    /// For each route R from peer P:
    ///   if metric[R] + cost(P) < my_metric[R]:
    ///     update route with next_hop = P, metric = metric[R] + cost(P)
    pub async fn process_update(
        &self,
        from_peer: &str,
        peer_routes: &[(Ipv4Net, u32)],
        hop_cost: u32,
    ) -> Vec<(Ipv4Net, u32, String)> {
        let mut table = self.table.write().await;
        let mut changes = Vec::new();

        // Store peer's table snapshot
        let peer_snapshot: HashMap<Ipv4Net, DvRoute> = peer_routes
            .iter()
            .map(|(cidr, metric)| {
                (*cidr, DvRoute {
                    cidr: *cidr,
                    metric: *metric,
                    next_hop: from_peer.to_string(),
                    last_updated: Instant::now(),
                    hold_down: false,
                    hold_down_until: None,
                    flags: RouteFlags { learned: true, ..Default::default() },
                })
            })
            .collect();
        table.peer_tables.insert(from_peer.to_string(), peer_snapshot);
        table.peer_updates.insert(from_peer.to_string(), Instant::now());

        for (cidr, peer_metric) in peer_routes {
            let new_metric = peer_metric.saturating_add(hop_cost);

            // Don't accept routes with infinite metric
            if peer_metric >= INFINITY {
                // Poison reverse: if this route was via this peer, mark it poisoned
                if let Some(my_route) = table.routes.get_mut(cidr) {
                    if my_route.next_hop == from_peer && !my_route.flags.connected {
                        my_route.metric = INFINITY;
                        my_route.flags.poisoned = true;
                        my_route.last_updated = Instant::now();
                        changes.push((*cidr, INFINITY, from_peer.to_string()));
                    }
                }
                continue;
            }

            // Bellman-Ford update
            let should_update = match table.routes.get(cidr) {
                None => true,
                Some(existing) => {
                    if existing.next_hop == from_peer {
                        // Always accept updates from current next hop
                        new_metric != existing.metric
                    } else {
                        new_metric < existing.metric
                    }
                }
            };

            if should_update {
                table.routes.insert(*cidr, DvRoute {
                    cidr: *cidr,
                    metric: new_metric,
                    next_hop: from_peer.to_string(),
                    last_updated: Instant::now(),
                    hold_down: false,
                    hold_down_until: None,
                    flags: RouteFlags { learned: true, ..Default::default() },
                });
                changes.push((*cidr, new_metric, from_peer.to_string()));
            }
        }

        if !changes.is_empty() {
            log::info!("DV: {} route changes from peer {}", changes.len(), from_peer);
        }

        changes
    }

    /// Build a distance vector update to send to a specific peer.
    ///
    /// Split horizon: don't advertise routes learned from this peer.
    /// Poison reverse: advertise routes via this peer with INFINITY metric.
    pub async fn build_update(&self, to_peer: &str) -> Vec<(Ipv4Net, u32)> {
        let table = self.table.read().await;
        let mut update = Vec::new();

        for (cidr, route) in &table.routes {
            if route.metric >= INFINITY {
                continue;
            }

            if self.split_horizon && route.next_hop == to_peer {
                if self.poison_reverse {
                    // Poison reverse: advertise INFINITY
                    update.push((*cidr, INFINITY));
                }
                // If no poison reverse, skip (split horizon)
                continue;
            }

            update.push((*cidr, route.metric));
        }

        update
    }

    /// Build a full table update (for new peers or periodic exchange).
    pub async fn build_full_update(&self) -> Vec<(Ipv4Net, u32)> {
        let table = self.table.read().await;
        table.routes
            .iter()
            .filter(|(_, r)| r.metric < INFINITY)
            .map(|(cidr, r)| (*cidr, r.metric))
            .collect()
    }

    /// Expire stale routes (no update from peer in timeout period).
    pub async fn expire_stale_routes(&self, timeout: Duration) -> usize {
        let mut table = self.table.write().await;
        let now = Instant::now();
        let mut expired = 0;

        // Find peers that haven't updated recently
        let stale_peers: Vec<String> = table.peer_updates
            .iter()
            .filter(|(_, last)| now.duration_since(**last) > timeout)
            .map(|(peer, _)| peer.clone())
            .collect();

        for peer in &stale_peers {
            // Poison all routes via this peer
            for route in table.routes.values_mut() {
                if route.next_hop == *peer && route.flags.learned {
                    route.metric = INFINITY;
                    route.flags.poisoned = true;
                    route.last_updated = now;
                    route.hold_down = true;
                    route.hold_down_until = Some(now + self.hold_down_duration);
                    expired += 1;
                }
            }
            log::warn!("DV: Peer {} is stale — {} routes poisoned", peer, expired);
        }

        // Remove hold-down expired routes
        table.routes.retain(|_, r| {
            if r.hold_down {
                if let Some(until) = r.hold_down_until {
                    if now > until {
                        log::info!("DV: Hold-down expired for {}", r.cidr);
                        return false; // Remove
                    }
                }
            }
            true
        });

        expired
    }

    /// Get the route table for inspection.
    pub async fn get_routes(&self) -> Vec<DvRoute> {
        let table = self.table.read().await;
        table.routes.values().cloned().collect()
    }

    /// Get peer state info.
    pub async fn get_peers(&self) -> Vec<String> {
        let table = self.table.read().await;
        table.peer_updates.keys().cloned().collect()
    }

    /// Remove a peer (on disconnect).
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut table = self.table.write().await;
        table.peer_updates.remove(peer_id);
        table.peer_tables.remove(peer_id);

        // Mark all routes via this peer as stale
        for route in table.routes.values_mut() {
            if route.next_hop == peer_id && !route.flags.connected {
                route.hold_down = true;
                route.hold_down_until = Some(Instant::now() + self.hold_down_duration);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_dv_basic_update() {
        let dv = DistanceVector::new("node-a");

        let updates = vec![
            (Ipv4Net::from_str("100.64.1.0/24").unwrap(), 1),
            (Ipv4Net::from_str("100.64.2.0/24").unwrap(), 2),
        ];

        let changes = dv.process_update("node-b", &updates, 1).await;
        assert!(!changes.is_empty());

        let routes = dv.get_routes().await;
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|r| r.cidr.to_string() == "100.64.1.0/24" && r.metric == 2));
    }

    #[tokio::test]
    async fn test_split_horizon() {
        let dv = DistanceVector::new("node-a");

        // Add a route learned from node-b
        let updates = vec![(Ipv4Net::from_str("100.64.1.0/24").unwrap(), 1)];
        dv.process_update("node-b", &updates, 1).await;

        // Build update for node-b — should NOT include route learned from node-b
        let update_to_b = dv.build_update("node-b").await;
        // With poison reverse enabled, it SHOULD appear with INFINITY
        assert!(update_to_b.is_empty() ||
            update_to_b.iter().any(|(_, m)| *m >= INFINITY));
    }

    #[tokio::test]
    async fn test_bellman_ford_prefers_lower_metric() {
        let dv = DistanceVector::new("node-a");

        // First update: metric 5 via node-b
        let up1 = vec![(Ipv4Net::from_str("100.64.1.0/24").unwrap(), 3)];
        dv.process_update("node-b", &up1, 2).await;

        // Second update: metric 3 via node-c (better)
        let up2 = vec![(Ipv4Net::from_str("100.64.1.0/24").unwrap(), 2)];
        dv.process_update("node-c", &up2, 1).await;

        let routes = dv.get_routes().await;
        let r = routes.iter().find(|r| r.cidr.to_string() == "100.64.1.0/24").unwrap();
        assert_eq!(r.metric, 3); // 1 + 2 = 3
        assert_eq!(r.next_hop, "node-c");
    }

    #[tokio::test]
    async fn test_infinity_prevents_loops() {
        let dv = DistanceVector::new("node-a");

        let poison = vec![(Ipv4Net::from_str("100.64.1.0/24").unwrap(), INFINITY)];
        dv.process_update("node-b", &poison, 1).await;

        let routes = dv.get_routes().await;
        // Should not have any routes at metric INFINITY
        assert!(!routes.iter().any(|r| r.metric >= INFINITY && !r.flags.poisoned));
    }
}
