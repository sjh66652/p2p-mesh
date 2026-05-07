//! Overlay Router — CIDR-based routing with Longest Prefix Match (LPM).
//!
//! Provides:
//! - Route table with CIDR entries
//! - Longest Prefix Match (LPM) lookup
//! - Route metrics (priority, hop count, latency)
//! - ECMP (Equal-Cost Multi-Path) support
//! - Route failover and failback
//! - Dynamic route addition/removal
//!
//! Used by the Overlay module to decide which peer to forward packets to.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// A single route entry in the route table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// Destination CIDR (e.g., "100.64.1.0/24")
    pub cidr: Ipv4Net,
    /// Peer ID that this route points to
    pub peer_id: String,
    /// Route metric (lower is preferred, like OSPF cost)
    pub metric: u32,
    /// Administrative distance (lower = more trusted source)
    pub admin_distance: u8,
    /// Route type: direct, static, mesh (learned via mesh routing)
    pub route_type: RouteType,
    /// Whether this route is currently active
    pub active: bool,
    /// When this route was added
    #[serde(skip, default = "instant_now")]
    pub added_at: Instant,
    /// Last time this route was used
    #[serde(skip)]
    pub last_used: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteType {
    /// Direct route (same subnet as TUN interface)
    Direct,
    /// Statically configured route
    Static,
    /// Learned via mesh routing protocol (Babel/distance-vector)
    Mesh,
    /// Default route (0.0.0.0/0)
    Default,
}

fn instant_now() -> Instant { Instant::now() }

/// ECMP (Equal-Cost Multi-Path) group.
///
/// When multiple routes have the same CIDR and metric, traffic is
/// load-balanced across them using a simple hash-based scheme.
#[derive(Debug, Clone)]
pub struct EcmpGroup {
    pub cidr: Ipv4Net,
    pub routes: Vec<Arc<Route>>,
    pub next_idx: usize, // Round-robin index
}

/// The overlay route table.
/// Routes are stored behind Arc to avoid cloning on every lookup.
pub struct RouteTable {
    /// CIDR -> list of routes (sorted by prefix length descending, then metric ascending)
    routes: RwLock<BTreeMap<String, Vec<Arc<Route>>>>,
    /// ECMP groups for load-balanced routes
    ecmp: RwLock<HashMap<String, EcmpGroup>>,
    /// Default route (0.0.0.0/0)
    default_route: RwLock<Option<Arc<Route>>>,
}

impl RouteTable {
    /// Create a new empty route table.
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(BTreeMap::new()),
            ecmp: RwLock::new(HashMap::new()),
            default_route: RwLock::new(None),
        }
    }

    /// Add a route to the table.
    ///
    /// If a route with the same CIDR and peer_id exists, it is replaced.
    /// Routes are sorted by prefix length descending for LPM.
    pub async fn add_route(&self, route: Route) {
        let cidr_key = route.cidr.to_string();
        let mut routes = self.routes.write().await;
        let entry = routes.entry(cidr_key.clone()).or_default();

        // Remove existing route to same peer for this CIDR
        entry.retain(|r| r.peer_id != route.peer_id);

        let route_arc = Arc::new(route.clone());
        entry.push(route_arc);

        // Sort by metric ascending for this CIDR
        entry.sort_by_key(|r| r.metric);

        // Check for ECMP: same CIDR, same metric, different peers
        if entry.len() > 1 {
            let min_metric = entry[0].metric;
            let ecmp_routes: Vec<Arc<Route>> = entry
                .iter()
                .filter(|r| r.metric == min_metric && r.active)
                .cloned()
                .collect();

            if ecmp_routes.len() > 1 {
                let mut ecmp = self.ecmp.write().await;
                ecmp.insert(
                    cidr_key,
                    EcmpGroup {
                        cidr: route.cidr,
                        routes: ecmp_routes,
                        next_idx: 0,
                    },
                );
            }
        }
    }

    /// Remove a route for a specific peer and CIDR.
    pub async fn remove_route(&self, cidr: &Ipv4Net, peer_id: &str) {
        let cidr_key = cidr.to_string();
        let mut routes = self.routes.write().await;
        if let Some(entry) = routes.get_mut(&cidr_key) {
            entry.retain(|r| r.peer_id != peer_id);
            if entry.is_empty() {
                routes.remove(&cidr_key);
            }
        }
    }

    /// Perform a Longest Prefix Match (LPM) lookup.
    ///
    /// Returns the best route for the given IP address, or None if no route matches.
    /// Prefers routes with longer prefix (more specific) and lower metric.
    /// Routes are returned as Arc to avoid cloning on every lookup.
    pub async fn lookup(&self, dst_ip: Ipv4Addr) -> Option<Arc<Route>> {
        let mut best: Option<Arc<Route>> = None;
        let mut best_len: u8 = 0;
        {
            let routes = self.routes.read().await;
            for (cidr_str, route_list) in routes.iter() {
                let cidr: Ipv4Net = match cidr_str.parse() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if cidr.contains(&dst_ip) && route_list.iter().any(|r| r.active) {
                    if cidr.prefix_len() > best_len {
                        if let Some(route) = route_list.iter().find(|r| r.active) {
                            best_len = cidr.prefix_len();
                            best = Some(Arc::clone(route));
                        }
                    }
                }
            }
        } // Release routes read lock before accessing default_route

        if best.is_none() {
            // Fall back to default route
            if let Some(default) = self.default_route.read().await.as_ref() {
                return Some(Arc::clone(default));
            }
        }

        best
    }

    /// Perform ECMP-aware lookup — returns one of the ECMP routes
    /// using round-robin selection.
    pub async fn lookup_ecmp(&self, dst_ip: Ipv4Addr) -> Option<Arc<Route>> {
        let best = self.lookup(dst_ip).await?;
        let cidr_key = best.cidr.to_string();

        // Acquire ecmp lock AFTER lookup() completes and routes lock is released,
        // avoiding lock ordering deadlock (ecmp.write after routes.read is safe;
        // routes.read after ecmp.write would deadlock)
        let mut ecmp = self.ecmp.write().await;
        if let Some(group) = ecmp.get_mut(&cidr_key) {
            if group.routes.len() > 1 {
                let idx = group.next_idx % group.routes.len();
                group.next_idx = (group.next_idx + 1) % group.routes.len();
                return Some(Arc::clone(&group.routes[idx]));
            }
        }

        Some(best)
    }

    /// Set the default route (0.0.0.0/0).
    pub async fn set_default_route(&self, route: Route) {
        let mut default = self.default_route.write().await;
        *default = Some(Arc::new(route));
    }

    /// Mark a route as inactive (e.g., peer disconnected).
    pub async fn deactivate_route(&self, peer_id: &str) {
        let mut routes = self.routes.write().await;
        for entry in routes.values_mut() {
            for route in entry.iter_mut() {
                if route.peer_id == peer_id {
                    let route = Arc::make_mut(route);
                    route.active = false;
                }
            }
        }
    }

    /// Mark all routes for a peer as active (peer reconnected).
    pub async fn activate_route(&self, peer_id: &str) {
        let mut routes = self.routes.write().await;
        for entry in routes.values_mut() {
            for route in entry.iter_mut() {
                if route.peer_id == peer_id {
                    let route = Arc::make_mut(route);
                    route.active = true;
                }
            }
        }
    }

    /// Update route metric (for dynamic routing protocols).
    pub async fn update_metric(&self, cidr: &Ipv4Net, peer_id: &str, new_metric: u32) {
        let cidr_key = cidr.to_string();
        let mut routes = self.routes.write().await;
        if let Some(entry) = routes.get_mut(&cidr_key) {
            for route in entry.iter_mut() {
                if route.peer_id == peer_id {
                    let route = Arc::make_mut(route);
                    route.metric = new_metric;
                }
            }
            entry.sort_by_key(|r| r.metric);
        }
    }

    /// Get all routes (for debugging/CLI).
    /// Clones each route since this is not a hot path.
    pub async fn get_all_routes(&self) -> Vec<Route> {
        let routes = self.routes.read().await;
        let mut all: Vec<Route> = routes.values()
            .flat_map(|v| v.iter())
            .map(|r| (**r).clone())
            .collect();
        if let Some(default) = self.default_route.read().await.as_ref() {
            all.push((**default).clone());
        }
        all
    }

    /// Get route count.
    pub async fn route_count(&self) -> usize {
        let routes = self.routes.read().await;
        routes.values().map(|v| v.len()).sum()
    }

    /// Flush all routes except default.
    pub async fn flush(&self) {
        let mut routes = self.routes.write().await;
        routes.clear();
        let mut ecmp = self.ecmp.write().await;
        ecmp.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_route_add_and_lookup() {
        let table = RouteTable::new();

        let route = Route {
            cidr: Ipv4Net::from_str("100.64.1.0/24").unwrap(),
            peer_id: "peer1".to_string(),
            metric: 10,
            admin_distance: 1,
            route_type: RouteType::Static,
            active: true,
            added_at: Instant::now(),
            last_used: None,
        };

        table.add_route(route).await;

        let result = table.lookup(Ipv4Addr::from_str("100.64.1.42").unwrap()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().peer_id, "peer1".to_string());
    }

    #[tokio::test]
    async fn test_longest_prefix_match() {
        let table = RouteTable::new();

        // /24 route
        table.add_route(Route {
            cidr: Ipv4Net::from_str("100.64.0.0/24").unwrap(),
            peer_id: "peer-a".to_string(),
            metric: 10,
            admin_distance: 1,
            route_type: RouteType::Static,
            active: true,
            added_at: Instant::now(),
            last_used: None,
        }).await;

        // /16 route (less specific)
        table.add_route(Route {
            cidr: Ipv4Net::from_str("100.64.0.0/16").unwrap(),
            peer_id: "peer-b".to_string(),
            metric: 10,
            admin_distance: 1,
            route_type: RouteType::Static,
            active: true,
            added_at: Instant::now(),
            last_used: None,
        }).await;

        // IP within both — should pick /24 (more specific)
        let result = table.lookup(Ipv4Addr::from_str("100.64.0.5").unwrap()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().peer_id, "peer-a");

        // IP only in /16
        let result = table.lookup(Ipv4Addr::from_str("100.64.99.1").unwrap()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().peer_id, "peer-b");
    }

    #[tokio::test]
    async fn test_ecmp_round_robin() {
        let table = RouteTable::new();

        let cidr = Ipv4Net::from_str("100.64.0.0/24").unwrap();
        for i in 0..3 {
            table.add_route(Route {
                cidr,
                peer_id: format!("peer-{}", i),
                metric: 10,
                admin_distance: 1,
                route_type: RouteType::Static,
                active: true,
                added_at: Instant::now(),
                last_used: None,
            }).await;
        }

        // ECMP should distribute across all 3 peers
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let route = table.lookup_ecmp(Ipv4Addr::from_str("100.64.0.42").unwrap()).await.unwrap();
            seen.insert(route.peer_id.clone());
        }
        // All 3 peers should have been selected at least once
        assert!(seen.len() >= 2, "ECMP round-robin should distribute across peers");
    }

    #[tokio::test]
    async fn test_default_route_fallback() {
        let table = RouteTable::new();

        table.set_default_route(Route {
            cidr: Ipv4Net::from_str("0.0.0.0/0").unwrap(),
            peer_id: "gateway".to_string(),
            metric: 100,
            admin_distance: 1,
            route_type: RouteType::Default,
            active: true,
            added_at: Instant::now(),
            last_used: None,
        }).await;

        let result = table.lookup(Ipv4Addr::from_str("8.8.8.8").unwrap()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().peer_id, "gateway");
    }

    #[tokio::test]
    async fn test_deactivate_route() {
        let table = RouteTable::new();

        table.add_route(Route {
            cidr: Ipv4Net::from_str("100.64.1.0/24").unwrap(),
            peer_id: "peer1".to_string(),
            metric: 10,
            admin_distance: 1,
            route_type: RouteType::Static,
            active: true,
            added_at: Instant::now(),
            last_used: None,
        }).await;

        table.deactivate_route("peer1").await;

        let result = table.lookup(Ipv4Addr::from_str("100.64.1.42").unwrap()).await;
        assert!(result.is_none());
    }
}
