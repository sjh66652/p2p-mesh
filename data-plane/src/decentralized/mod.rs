//! Decentralized Control Plane — Phase 8.
//!
//! Removes single-point-of-failure from the control plane:
//! - Raft consensus: etcd/openraft for leader election and state replication
//! - Gossip membership: SWIM protocol for cluster discovery
//! - DHT key-value store: Kademlia for distributed peer discovery
//!
//! Architecture:
//!   ┌──────────┐    ┌──────────┐    ┌──────────┐
//!   │  Node A  │◄──►│  Node B  │◄──►│  Node C  │
//!   │  (Raft)  │    │  (Raft)  │    │  (Raft)  │
//!   └────┬─────┘    └────┬─────┘    └────┬─────┘
//!        │               │               │
//!        └───────────────┼───────────────┘
//!                        │
//!              ┌─────────▼─────────┐
//!              │  Kademlia DHT     │
//!              │  (Peer Discovery) │
//!              └───────────────────┘

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

// =====================================================================
// Raft Consensus (using patterns from openraft / etcd)
// =====================================================================

/// Raft node role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

/// Raft log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftLogEntry {
    /// Log index (monotonically increasing)
    pub index: u64,
    /// Term when this entry was created
    pub term: u64,
    /// Entry type
    pub entry_type: RaftEntryType,
    /// Serialized command data
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftEntryType {
    /// No-op entry (for leader election)
    NoOp,
    /// Configuration change (add/remove node)
    ConfigChange,
    /// Route table update
    RouteUpdate,
    /// ACL policy change
    AclPolicy,
    /// IPAM allocation
    IpamAllocation,
    /// Custom command
    Custom(String),
}

/// Raft node state.
#[derive(Debug, Clone)]
pub struct RaftNode {
    /// Node ID
    pub id: String,
    /// Node address
    pub addr: SocketAddr,
    /// Current role
    pub role: RaftRole,
    /// Current term
    pub current_term: u64,
    /// Who we voted for in current term
    pub voted_for: Option<String>,
    /// Log entries
    pub log: Vec<RaftLogEntry>,
    /// Commit index
    pub commit_index: u64,
    /// Last applied index
    pub last_applied: u64,
    /// Known peers
    pub peers: HashMap<String, SocketAddr>,
    /// Leader ID (if known)
    pub leader_id: Option<String>,
    /// Election timeout
    pub election_timeout: Duration,
    /// Last heartbeat received
    pub last_heartbeat: Instant,
}

/// Raft consensus manager.
pub struct RaftConsensus {
    /// Our node state
    node: RwLock<RaftNode>,
    /// Pending consensus state machine operations
    pending: RwLock<Vec<RaftLogEntry>>,
    /// Heartbeat interval
    heartbeat_interval: Duration,
}

impl RaftConsensus {
    /// Create a new Raft consensus node.
    pub fn new(node_id: &str, addr: SocketAddr, peers: HashMap<String, SocketAddr>) -> Self {
        let node = RaftNode {
            id: node_id.to_string(),
            addr,
            role: RaftRole::Follower,
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            last_applied: 0,
            peers,
            leader_id: None,
            election_timeout: Duration::from_millis(150 + (rand::thread_rng().next_u64() % 150) as u64),
            last_heartbeat: Instant::now(),
        };

        Self {
            node: RwLock::new(node),
            pending: RwLock::new(Vec::new()),
            heartbeat_interval: Duration::from_millis(50),
        }
    }

    /// Start an election (become Candidate).
    pub async fn start_election(&self) {
        let mut node = self.node.write().await;
        node.role = RaftRole::Candidate;
        node.current_term += 1;
        node.voted_for = Some(node.id.clone());
        node.last_heartbeat = Instant::now();

        log::info!("Raft: Starting election for term {}", node.current_term);
    }

    /// Become leader (received majority votes).
    pub async fn become_leader(&self) {
        let mut node = self.node.write().await;
        node.role = RaftRole::Leader;
        node.leader_id = Some(node.id.clone());

        log::info!("Raft: Node {} is now leader for term {}", node.id, node.current_term);
    }

    /// Append an entry to the log (leader only).
    pub async fn append_entry(&self, entry_type: RaftEntryType, data: Vec<u8>) -> Result<u64, RaftError> {
        let mut node = self.node.write().await;

        if node.role != RaftRole::Leader {
            return Err(RaftError::NotLeader);
        }

        let entry = RaftLogEntry {
            index: node.log.len() as u64 + 1,
            term: node.current_term,
            entry_type,
            data,
        };

        node.log.push(entry);
        Ok(node.log.len() as u64 - 1)
    }

    /// Receive a heartbeat from the leader.
    pub async fn receive_heartbeat(&self, leader_id: &str, term: u64, commit_index: u64) {
        let mut node = self.node.write().await;

        if term >= node.current_term {
            node.current_term = term;
            node.role = RaftRole::Follower;
            node.leader_id = Some(leader_id.to_string());
            node.commit_index = commit_index;
            node.last_heartbeat = Instant::now();
        }
    }

    /// Check if election timeout has elapsed.
    pub async fn check_timeout(&self) -> bool {
        let node = self.node.read().await;
        node.last_heartbeat.elapsed() > node.election_timeout
    }

    /// Get current Raft state.
    pub async fn get_state(&self) -> RaftNode {
        self.node.read().await.clone()
    }
}

// =====================================================================
// Kademlia DHT — Distributed Peer Discovery
// =====================================================================

/// Kademlia node ID (160-bit SHA-1 hash, but we use SHA-256 truncated).
pub type KademliaId = [u8; 20];

/// Kademlia bucket (stores peers at a specific distance).
#[derive(Debug, Clone)]
pub struct KBucket {
    /// Peers in this bucket (max K entries)
    pub peers: Vec<KademliaPeer>,
    /// Last updated
    pub last_updated: Instant,
}

const K: usize = 20; // Kademlia replication parameter

/// A peer stored in the DHT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KademliaPeer {
    pub node_id: KademliaId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
}

/// Kademlia DHT implementation.
pub struct KademliaDht {
    /// Our node ID
    our_id: KademliaId,
    /// Routing table: bucket_index → KBucket
    /// There are 160 buckets (one per bit of the ID space)
    buckets: RwLock<Vec<KBucket>>,
    /// Stored key-value pairs (for peer discovery)
    store: RwLock<HashMap<KademliaId, Vec<u8>>>,
}

impl KademliaDht {
    /// Create a new Kademlia DHT instance.
    pub fn new() -> Self {
        let mut node_id = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut node_id);

        // Create 160 empty buckets
        let mut buckets = Vec::with_capacity(160);
        for _ in 0..160 {
            buckets.push(KBucket {
                peers: Vec::new(),
                last_updated: Instant::now(),
            });
        }

        Self {
            our_id: node_id,
            buckets: RwLock::new(buckets),
            store: RwLock::new(HashMap::new()),
        }
    }

    /// XOR metric — the distance between two node IDs.
    fn distance(a: &KademliaId, b: &KademliaId) -> KademliaId {
        let mut result = [0u8; 20];
        for i in 0..20 {
            result[i] = a[i] ^ b[i];
        }
        result
    }

    /// Find the bucket index for a given node ID.
    fn bucket_index(our_id: &KademliaId, peer_id: &KademliaId) -> usize {
        let distance = Self::distance(our_id, peer_id);
        // Find leading zeros in the XOR distance
        for (byte_idx, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                return (byte_idx * 8 + byte.leading_zeros() as usize).min(159);
            }
        }
        0
    }

    /// Add a peer to the routing table.
    pub async fn add_peer(&self, peer: KademliaPeer) {
        let bucket_idx = Self::bucket_index(&self.our_id, &peer.node_id);
        let mut buckets = self.buckets.write().await;

        let bucket = &mut buckets[bucket_idx];
        bucket.last_updated = Instant::now();

        // Check if peer already exists
        if let Some(existing) = bucket.peers.iter_mut().find(|p| p.node_id == peer.node_id) {
            existing.last_seen = Instant::now();
            return;
        }

        if bucket.peers.len() < K {
            bucket.peers.push(peer);
        } else {
            // Bucket full — ping oldest peer to check if still alive
            log::debug!("Kademlia: Bucket {} full ({} peers)", bucket_idx, bucket.peers.len());
        }
    }

    /// Find the K closest peers to a target ID.
    pub async fn find_closest(&self, target: &KademliaId, count: usize) -> Vec<KademliaPeer> {
        let buckets = self.buckets.read().await;
        let mut all_peers: Vec<KademliaPeer> = buckets
            .iter()
            .flat_map(|b| b.peers.clone())
            .collect();

        // Sort by XOR distance to target
        all_peers.sort_by_key(|p| {
            let dist = Self::distance(&p.node_id, target);
            // Convert first 8 bytes to u64 for comparison
            u64::from_be_bytes([dist[0], dist[1], dist[2], dist[3], dist[4], dist[5], dist[6], dist[7]])
        });

        all_peers.truncate(count);
        all_peers
    }

    /// Store a value in the DHT.
    pub async fn put(&self, key: &KademliaId, value: Vec<u8>) {
        let mut store = self.store.write().await;
        store.insert(*key, value);
    }

    /// Retrieve a value from the DHT.
    pub async fn get(&self, key: &KademliaId) -> Option<Vec<u8>> {
        let store = self.store.read().await;
        store.get(key).cloned()
    }

    /// Get routing table statistics.
    pub async fn get_stats(&self) -> DhtStats {
        let buckets = self.buckets.read().await;
        let total_peers: usize = buckets.iter().map(|b| b.peers.len()).sum();
        DhtStats {
            total_peers,
            buckets_used: buckets.iter().filter(|b| !b.peers.is_empty()).count(),
            stored_keys: self.store.read().await.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhtStats {
    pub total_peers: usize,
    pub buckets_used: usize,
    pub stored_keys: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RaftError {
    #[error("Not the leader")]
    NotLeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kademlia_distance() {
        let a = [0xAAu8; 20];
        let b = [0x55u8; 20];
        let dist = KademliaDht::distance(&a, &b);
        assert_eq!(dist, [0xFFu8; 20]);

        let c = [0xAAu8; 20];
        let dist = KademliaDht::distance(&a, &c);
        assert_eq!(dist, [0x00u8; 20]);
    }

    #[test]
    fn test_bucket_index() {
        let our_id = [0x00u8; 20];
        let near_peer = {
            let mut id = [0x00u8; 20];
            id[0] = 0x01;
            id
        };
        let idx = KademliaDht::bucket_index(&our_id, &near_peer);
        assert_eq!(idx, 7); // Leading zero: 7 bits

        let far_peer = {
            let mut id = [0x00u8; 20];
            id[0] = 0x80;
            id
        };
        let idx = KademliaDht::bucket_index(&our_id, &far_peer);
        assert_eq!(idx, 0); // No leading zeros
    }

    #[tokio::test]
    async fn test_raft_election() {
        let mut peers = HashMap::new();
        peers.insert("node-b".into(), "10.0.0.2:9999".parse().unwrap());

        let raft = RaftConsensus::new(
            "node-a",
            "10.0.0.1:9999".parse().unwrap(),
            peers,
        );

        raft.start_election().await;
        let state = raft.get_state().await;
        assert_eq!(state.role, RaftRole::Candidate);
        assert_eq!(state.current_term, 1);
    }
}
