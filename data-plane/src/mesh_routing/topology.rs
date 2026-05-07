//! Topology Discovery & Management.
//!
//! Maintains a real-time view of the mesh network topology:
//! - Neighbor discovery via Hello protocol
//! - Link state tracking (RTT, loss, bandwidth per link)
//! - Topology graph for multi-hop path computation
//! - Relay election (selects optimal relay nodes)
//! - Topology change events for reactive routing

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// A single link in the topology graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLink {
    pub source: String,
    pub target: String,
    pub link_type: LinkType,
    pub created_at: Instant,
    pub last_heartbeat: Instant,
    pub metrics: LinkMetrics,
    pub capacity: LinkCapacity,
    pub state: LinkState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMetrics {
    pub rtt_us: u64,
    pub loss_rate: f64,
    pub jitter_us: u64,
    pub bandwidth_bps: u64,
    pub hop_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkType {
    Direct,
    Relay,
    MultiHop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkState {
    Up,
    Down,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkCapacity {
    pub max_bandwidth_bps: u64,
    pub max_connections: u32,
    pub current_connections: u32,
}

/// Topology graph node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub device_id: String,
    pub virtual_ip: Option<String>,
    pub public_addr: Option<SocketAddr>,
    pub node_type: NodeType,
    pub capabilities: NodeCapabilities,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Endpoint,
    Relay,
    Gateway,
    Mobile,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub supports_relay: bool,
    pub supports_ice: bool,
    pub supports_ipv6: bool,
    pub supports_multipath: bool,
    pub max_bandwidth_bps: u64,
}

/// Topology Manager — maintains the mesh network topology.
pub struct TopologyManager {
    /// All known nodes: device_id → TopologyNode
    nodes: RwLock<HashMap<String, TopologyNode>>,
    /// All known links: (source, target) → TopologyLink
    links: RwLock<HashMap<(String, String), TopologyLink>>,
    /// Adjacency list for path computation
    adjacency: RwLock<HashMap<String, HashSet<String>>>,
    /// Relay election results: region → relay_device_ids
    relay_elections: RwLock<HashMap<String, Vec<String>>>,
    /// Topology version (incremented on changes)
    version: RwLock<u64>,
}

impl TopologyManager {
    /// Create a new topology manager.
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            links: RwLock::new(HashMap::new()),
            adjacency: RwLock::new(HashMap::new()),
            relay_elections: RwLock::new(HashMap::new()),
            version: RwLock::new(0),
        }
    }

    /// Add or update a node.
    pub async fn upsert_node(&self, node: TopologyNode) {
        let device_id = node.device_id.clone();
        let mut nodes = self.nodes.write().await;
        nodes.insert(device_id.clone(), node);

        let mut adj = self.adjacency.write().await;
        adj.entry(device_id).or_default();

        let mut ver = self.version.write().await;
        *ver += 1;
    }

    /// Remove a node (offline).
    pub async fn remove_node(&self, device_id: &str) {
        let mut nodes = self.nodes.write().await;
        nodes.remove(device_id);

        let mut adj = self.adjacency.write().await;
        adj.remove(device_id);

        let mut ver = self.version.write().await;
        *ver += 1;
    }

    /// Add a link between two nodes.
    pub async fn add_link(&self, source: &str, target: &str, link: TopologyLink) {
        let mut links = self.links.write().await;
        links.insert((source.to_string(), target.to_string()), link);

        let mut adj = self.adjacency.write().await;
        adj.entry(source.to_string()).or_default().insert(target.to_string());
        adj.entry(target.to_string()).or_default().insert(source.to_string());

        let mut ver = self.version.write().await;
        *ver += 1;
    }

    /// Remove a link.
    pub async fn remove_link(&self, source: &str, target: &str) {
        let mut links = self.links.write().await;
        links.remove(&(source.to_string(), target.to_string()));

        let mut adj = self.adjacency.write().await;
        if let Some(neighbors) = adj.get_mut(source) {
            neighbors.remove(target);
        }
        if let Some(neighbors) = adj.get_mut(target) {
            neighbors.remove(source);
        }
    }

    /// Compute shortest path between two nodes (Dijkstra).
    pub async fn shortest_path(
        &self,
        src: &str,
        dst: &str,
    ) -> Option<(Vec<String>, u64)> {
        let adj = self.adjacency.read().await;

        if !adj.contains_key(src) || !adj.contains_key(dst) {
            return None;
        }

        // Dijkstra's algorithm
        let mut dist: HashMap<String, u64> = HashMap::new();
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();

        dist.insert(src.to_string(), 0);

        loop {
            let current = dist
                .iter()
                .filter(|(n, _)| !visited.contains(*n))
                .min_by_key(|(_, d)| *d)
                .map(|(n, _)| n.clone());

            let current = match current {
                Some(c) => c,
                None => break,
            };

            if current == dst {
                // Reconstruct path
                let mut path = vec![dst.to_string()];
                let mut node = dst.to_string();
                while let Some(prev_node) = prev.get(&node) {
                    path.push(prev_node.clone());
                    node = prev_node.clone();
                }
                path.reverse();
                return Some((path, dist[&current]));
            }

            visited.insert(current.clone());

            if let Some(neighbors) = adj.get(&current) {
                for neighbor in neighbors {
                    if visited.contains(neighbor) {
                        continue;
                    }

                    // Cost = 1 hop for simple topology
                    let alt = dist.get(&current).unwrap_or(&u64::MAX) + 1;
                    if alt < *dist.get(neighbor).unwrap_or(&u64::MAX) {
                        dist.insert(neighbor.clone(), alt);
                        prev.insert(neighbor.clone(), current.clone());
                    }
                }
            }
        }

        None
    }

    /// Elect relay nodes for a region.
    ///
    /// Criteria:
    /// 1. Node must have relay capability
    /// 2. Low latency to most peers
    /// 3. High bandwidth capacity
    /// 4. Reliable uptime
    pub async fn elect_relays(&self, region: &str) -> Vec<String> {
        let nodes = self.nodes.read().await;

        let mut candidates: Vec<(&String, &TopologyNode)> = nodes
            .iter()
            .filter(|(_, n)| n.capabilities.supports_relay && n.online)
            .collect();

        // Sort by bandwidth capacity (highest first)
        candidates.sort_by_key(|(_, n)| std::cmp::Reverse(n.capabilities.max_bandwidth_bps));

        // Select top 3
        let elected: Vec<String> = candidates
            .iter()
            .take(3)
            .map(|(id, _)| (*id).clone())
            .collect();

        let mut elections = self.relay_elections.write().await;
        elections.insert(region.to_string(), elected.clone());

        log::info!("Topology: Elected {} relays for region {}", elected.len(), region);
        elected
    }

    /// Get the current relay election results.
    pub async fn get_relays(&self) -> HashMap<String, Vec<String>> {
        let elections = self.relay_elections.read().await;
        elections.clone()
    }

    /// Get topology statistics.
    pub async fn get_stats(&self) -> TopologyStats {
        let nodes = self.nodes.read().await;
        let links = self.links.read().await;

        TopologyStats {
            total_nodes: nodes.len(),
            online_nodes: nodes.values().filter(|n| n.online).count(),
            total_links: links.len(),
            active_links: links.values().filter(|l| matches!(l.state, LinkState::Up)).count(),
            version: *self.version.read().await,
        }
    }

    /// Find the best relay for connecting two peers.
    pub async fn find_best_relay(&self, src: &str, dst: &str) -> Option<String> {
        let nodes = self.nodes.read().await;
        let adj = self.adjacency.read().await;

        // Find relays that are connected to both src and dst
        let src_neighbors = adj.get(src)?;
        let dst_neighbors = adj.get(dst)?;

        let common: HashSet<&String> = src_neighbors.intersection(dst_neighbors).collect();

        common
            .iter()
            .filter(|id| {
                nodes.get(**id).map(|n| n.capabilities.supports_relay).unwrap_or(false)
            })
            .max_by_key(|id| {
                nodes.get(**id).map(|n| n.capabilities.max_bandwidth_bps).unwrap_or(0)
            })
            .map(|id| (*id).clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyStats {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub total_links: usize,
    pub active_links: usize,
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_node(id: &str, is_relay: bool) -> TopologyNode {
        TopologyNode {
            device_id: id.to_string(),
            virtual_ip: None,
            public_addr: None,
            node_type: if is_relay { NodeType::Relay } else { NodeType::Endpoint },
            capabilities: NodeCapabilities {
                supports_relay: is_relay,
                supports_ice: true,
                supports_ipv6: false,
                supports_multipath: false,
                max_bandwidth_bps: if is_relay { 1_000_000_000 } else { 100_000_000 },
            },
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            online: true,
        }
    }

    #[tokio::test]
    async fn test_shortest_path() {
        let tm = TopologyManager::new();
        tm.upsert_node(make_test_node("A", false)).await;
        tm.upsert_node(make_test_node("B", false)).await;
        tm.upsert_node(make_test_node("C", false)).await;

        tm.add_link("A", "B", TopologyLink {
            source: "A".into(), target: "B".into(),
            link_type: LinkType::Direct,
            created_at: Instant::now(), last_heartbeat: Instant::now(),
            metrics: LinkMetrics { rtt_us: 1000, loss_rate: 0.0, jitter_us: 100, bandwidth_bps: 100_000_000, hop_count: 1 },
            capacity: LinkCapacity { max_bandwidth_bps: 100_000_000, max_connections: 100, current_connections: 1 },
            state: LinkState::Up,
        }).await;

        tm.add_link("B", "C", TopologyLink {
            source: "B".into(), target: "C".into(),
            link_type: LinkType::Direct,
            created_at: Instant::now(), last_heartbeat: Instant::now(),
            metrics: LinkMetrics { rtt_us: 2000, loss_rate: 0.0, jitter_us: 200, bandwidth_bps: 100_000_000, hop_count: 1 },
            capacity: LinkCapacity { max_bandwidth_bps: 100_000_000, max_connections: 100, current_connections: 1 },
            state: LinkState::Up,
        }).await;

        let (path, hops) = tm.shortest_path("A", "C").await.unwrap();
        assert_eq!(path, vec!["A", "B", "C"]);
        assert_eq!(hops, 2);
    }

    #[tokio::test]
    async fn test_relay_election() {
        let tm = TopologyManager::new();
        tm.upsert_node(make_test_node("relay1", true)).await;
        tm.upsert_node(make_test_node("relay2", true)).await;
        tm.upsert_node(make_test_node("endpoint1", false)).await;

        let relays = tm.elect_relays("us-east").await;
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&"relay1".to_string()));
        assert!(relays.contains(&"relay2".to_string()));
        assert!(!relays.contains(&"endpoint1".to_string()));
    }
}
