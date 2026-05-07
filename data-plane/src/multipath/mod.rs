//! Multi-path transport manager.
//!
//! Maintains multiple transport paths between peers:
//! - Direct P2P path (preferred, lowest latency)
//! - Relay path (fallback, higher latency)
//!
//! Dynamically switches between paths based on health metrics:
//! - RTT (round-trip time)
//! - Packet loss rate
//! - Bandwidth
//!
//! Strategy: prefer direct path when available, fall back to relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::metrics::{PathMetrics, QualityScore};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathType {
    Direct,
    Relay,
    Local,
}

#[derive(Debug, Clone)]
pub struct PathStatus {
    pub path_type: PathType,
    pub addr: SocketAddr,
    pub active: bool,
    pub established_at: Instant,
    pub metrics: PathMetrics,
    pub probes: u64,
}

pub struct MultiPathManager {
    paths: RwLock<HashMap<String, HashMap<PathType, PathStatus>>>,
    active_path: RwLock<HashMap<String, PathType>>,
    direct_rtt_threshold: Duration,
    probe_interval: Duration,
}

impl MultiPathManager {
    pub fn new() -> Self {
        Self {
            paths: RwLock::new(HashMap::new()),
            active_path: RwLock::new(HashMap::new()),
            direct_rtt_threshold: Duration::from_millis(300),
            probe_interval: Duration::from_secs(10),
        }
    }

    pub async fn register_path(&self, peer_id: &str, path_type: PathType, addr: SocketAddr) {
        let mut paths = self.paths.write().await;
        let peer_paths = paths.entry(peer_id.to_string()).or_insert_with(HashMap::new);
        peer_paths.insert(
            path_type.clone(),
            PathStatus {
                path_type: path_type.clone(),
                addr,
                active: true,
                established_at: Instant::now(),
                metrics: PathMetrics::default(),
                probes: 0,
            },
        );
        log::info!("Registered {:?} path to {} at {}", path_type, peer_id, addr);
    }

    pub async fn remove_path(&self, peer_id: &str, path_type: &PathType) {
        let mut paths = self.paths.write().await;
        if let Some(peer_paths) = paths.get_mut(peer_id) {
            peer_paths.remove(path_type);
            if peer_paths.is_empty() {
                paths.remove(peer_id);
            }
        }
        let mut active = self.active_path.write().await;
        if active.get(peer_id) == Some(path_type) {
            active.remove(peer_id);
        }
    }

    pub async fn select_best_path(&self, peer_id: &str) -> Option<PathType> {
        let paths = self.paths.read().await;
        let peer_paths = paths.get(peer_id)?;
        let path_order = [PathType::Local, PathType::Direct, PathType::Relay];
        for path_type in &path_order {
            if let Some(status) = peer_paths.get(path_type) {
                if status.active {
                    if *path_type == PathType::Direct || *path_type == PathType::Local {
                        if status.metrics.rtt_avg < self.direct_rtt_threshold {
                            return Some(path_type.clone());
                        }
                    } else if *path_type == PathType::Relay {
                        return Some(path_type.clone());
                    }
                }
            }
        }
        for status in peer_paths.values() {
            if status.active {
                return Some(status.path_type.clone());
            }
        }
        None
    }

    pub async fn update_metrics(
        &self, peer_id: &str, path_type: &PathType, rtt: Duration, loss_rate: f64, bandwidth: u64,
    ) {
        let mut paths = self.paths.write().await;
        if let Some(peer_paths) = paths.get_mut(peer_id) {
            if let Some(status) = peer_paths.get_mut(path_type) {
                status.metrics.update(rtt, loss_rate, bandwidth);
            }
        }
    }

    pub async fn get_active_addr(&self, peer_id: &str) -> Option<SocketAddr> {
        let active = self.active_path.read().await;
        let path_type = active.get(peer_id)?;
        let paths = self.paths.read().await;
        let peer_paths = paths.get(peer_id)?;
        let status = peer_paths.get(path_type)?;
        if status.active { Some(status.addr) } else { None }
    }

    pub async fn get_all_active_paths(&self, peer_id: &str) -> Vec<(PathType, SocketAddr)> {
        let paths = self.paths.read().await;
        let mut result = Vec::new();
        if let Some(peer_paths) = paths.get(peer_id) {
            for (path_type, status) in peer_paths {
                if status.active {
                    result.push((path_type.clone(), status.addr));
                }
            }
        }
        result.sort_by_key(|a| path_priority(&a.0));
        result
    }

    pub async fn get_path_quality(&self, peer_id: &str) -> HashMap<PathType, QualityScore> {
        let paths = self.paths.read().await;
        let mut result = HashMap::new();
        if let Some(peer_paths) = paths.get(peer_id) {
            for (path_type, status) in peer_paths {
                result.insert(path_type.clone(), status.metrics.score());
            }
        }
        result
    }

    pub async fn mark_inactive(&self, peer_id: &str, path_type: &PathType) {
        let mut paths = self.paths.write().await;
        if let Some(peer_paths) = paths.get_mut(peer_id) {
            if let Some(status) = peer_paths.get_mut(path_type) {
                status.active = false;
                log::warn!("Path {} {:?} marked inactive", peer_id, path_type);
            }
        }
        // Clean up the active_path map so get_active_addr returns None for this path
        let mut active = self.active_path.write().await;
        if active.get(peer_id) == Some(path_type) {
            active.remove(peer_id);
        }
    }

    pub async fn mark_active(&self, peer_id: &str, path_type: &PathType) {
        let mut paths = self.paths.write().await;
        if let Some(peer_paths) = paths.get_mut(peer_id) {
            if let Some(status) = peer_paths.get_mut(path_type) {
                status.active = true;
                status.established_at = Instant::now();
                log::info!("Path {} {:?} recovered", peer_id, path_type);
            }
        }
    }

    pub async fn is_peer_reachable(&self, peer_id: &str) -> bool {
        let paths = self.paths.read().await;
        if let Some(peer_paths) = paths.get(peer_id) {
            peer_paths.values().any(|s| s.active)
        } else {
            false
        }
    }
}

fn path_priority(path_type: &PathType) -> u8 {
    match path_type {
        PathType::Local => 0,
        PathType::Direct => 1,
        PathType::Relay => 2,
    }
}
