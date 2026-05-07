//! Gossip Protocol — SWIM-style membership and state dissemination.
//!
//! Provides epidemic-style gossip for:
//! - Membership dissemination (who is in the mesh)
//! - Topology state propagation
//! - Configuration updates
//! - Relay election results
//!
//! SWIM (Scalable Weakly-consistent Infection-style Membership) protocol:
//! - Each node periodically pings a random peer
//! - If ping fails, asks other peers to check (indirect ping)
//! - Suspect/dead state transitions with configurable thresholds

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

fn instant_now() -> Instant { Instant::now() }

/// Maximum gossip message size (payload).
const MAX_GOSSIP_PAYLOAD: usize = 1400;

/// Gossip fanout (number of peers to forward to).
const DEFAULT_FANOUT: usize = 3;

/// Gossip round interval.
const DEFAULT_GOSSIP_INTERVAL: Duration = Duration::from_secs(1);

/// Member states in SWIM protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemberState {
    Alive,
    Suspect,
    Dead,
    Left,
}

/// A mesh member tracked by gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMember {
    pub device_id: String,
    pub addr: SocketAddr,
    pub state: MemberState,
    pub incarnation: u64,
    #[serde(skip, default = "instant_now")]
    pub last_changed: Instant,
    pub metadata: HashMap<String, String>,
}

/// Gossip message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Direct ping to a peer
    Ping {
        seq_num: u64,
        target: String,
    },
    /// Response to a ping
    Ack {
        seq_num: u64,
        source: String,
    },
    /// Indirect ping request (ask peer to ping target)
    IndirectPing {
        seq_num: u64,
        target: String,
        requester: String,
    },
    /// Membership update
    MembershipUpdate {
        members: Vec<GossipMember>,
    },
    /// Topology change notification
    TopologyChange {
        link_id: String,
        change_type: String,
        metadata: HashMap<String, String>,
    },
    /// Relay election update
    RelayElection {
        region: String,
        relays: Vec<String>,
    },
}

/// SWIM-style Gossip Protocol.
pub struct GossipProtocol {
    /// Our device ID
    our_id: String,
    /// Our address
    our_addr: SocketAddr,
    /// Known members: device_id → GossipMember
    members: RwLock<HashMap<String, GossipMember>>,
    /// Incarnation number (monotonically increasing)
    incarnation: RwLock<u64>,
    /// Ping timeout
    ping_timeout: Duration,
    /// Number of indirect ping attempts before marking dead
    suspect_timeout: Duration,
    /// Fanout for gossip propagation
    fanout: usize,
    /// Sequence number for messages
    seq_num: RwLock<u64>,
}

impl GossipProtocol {
    /// Create a new gossip protocol instance.
    pub fn new(our_id: &str, our_addr: SocketAddr) -> Self {
        Self {
            our_id: our_id.to_string(),
            our_addr,
            members: RwLock::new(HashMap::new()),
            incarnation: RwLock::new(0),
            ping_timeout: Duration::from_millis(500),
            suspect_timeout: Duration::from_secs(3),
            fanout: DEFAULT_FANOUT,
            seq_num: RwLock::new(0),
        }
    }

    /// Join the mesh by introducing ourselves.
    pub async fn join(&self, seed_addr: SocketAddr) {
        let our_member = GossipMember {
            device_id: self.our_id.clone(),
            addr: self.our_addr,
            state: MemberState::Alive,
            incarnation: 0,
            last_changed: Instant::now(),
            metadata: HashMap::new(),
        };

        let mut members = self.members.write().await;
        members.insert(self.our_id.clone(), our_member);
        log::info!("Gossip: Joining mesh via seed {}", seed_addr);
    }

    /// Add a new member to our view.
    pub async fn add_member(&self, member: GossipMember) {
        let mut members = self.members.write().await;
        if let Some(existing) = members.get(&member.device_id) {
            // Only accept if incarnation is newer
            if member.incarnation > existing.incarnation {
                members.insert(member.device_id.clone(), member);
            }
        } else {
            members.insert(member.device_id.clone(), member);
        }
    }

    /// Select a random alive peer from our member list.
    pub async fn select_random_peer(&self) -> Option<GossipMember> {
        let members = self.members.read().await;
        let alive: Vec<&GossipMember> = members
            .values()
            .filter(|m| m.device_id != self.our_id && m.state == MemberState::Alive)
            .collect();

        if alive.is_empty() {
            return None;
        }

        let idx = rand::thread_rng().gen_range(0..alive.len());
        Some(alive[idx].clone())
    }

    /// Build a Ping message for protocol round.
    pub async fn build_ping(&self) -> Option<(GossipMessage, String)> {
        let target = self.select_random_peer().await?;
        let seq = {
            let mut s = self.seq_num.write().await;
            *s += 1;
            *s
        };

        Some((GossipMessage::Ping {
            seq_num: seq,
            target: target.device_id.clone(),
        }, target.device_id))
    }

    /// Process an incoming gossip message.
    pub async fn process_message(
        &self,
        msg: GossipMessage,
        from_addr: SocketAddr,
    ) -> Option<GossipMessage> {
        match msg {
            GossipMessage::Ping { seq_num, target } => {
                if target == self.our_id {
                    return Some(GossipMessage::Ack {
                        seq_num,
                        source: self.our_id.clone(),
                    });
                }
            }
            GossipMessage::Ack { seq_num, source } => {
                // Confirmed reachability
                let mut members = self.members.write().await;
                if let Some(member) = members.get_mut(&source) {
                    member.state = MemberState::Alive;
                    member.last_changed = Instant::now();
                }
            }
            GossipMessage::IndirectPing { seq_num, target, requester: _ } => {
                // Forward ping to target on behalf of requester
                if target != self.our_id {
                    return Some(GossipMessage::Ping { seq_num, target });
                }
            }
            GossipMessage::MembershipUpdate { members: new_members } => {
                let mut our_members = self.members.write().await;
                for member in new_members {
                    if member.device_id == self.our_id {
                        // Bump our incarnation if someone thinks we're dead
                        if member.state == MemberState::Dead {
                            let mut inc = self.incarnation.write().await;
                            *inc += 1;
                            log::warn!("Gossip: Detected dead rumor about us — bumping incarnation to {}", *inc);
                        }
                        continue;
                    }

                    if let Some(existing) = our_members.get(&member.device_id) {
                        if member.incarnation > existing.incarnation {
                            our_members.insert(member.device_id.clone(), member);
                        }
                    } else {
                        our_members.insert(member.device_id.clone(), member);
                    }
                }
            }
            GossipMessage::TopologyChange { link_id, change_type, metadata: _ } => {
                log::info!("Gossip: Topology change: {} {}", change_type, link_id);
            }
            GossipMessage::RelayElection { region, relays } => {
                log::info!("Gossip: Relay election for {}: {:?}", region, relays);
            }
        }
        None
    }

    /// Build a MembershipUpdate to propagate to peers.
    pub async fn build_membership_update(&self) -> GossipMessage {
        let members = self.members.read().await;
        let snapshot: Vec<GossipMember> = members.values().cloned().collect();
        GossipMessage::MembershipUpdate { members: snapshot }
    }

    /// Mark a member as suspect (indirect ping failed).
    pub async fn mark_suspect(&self, device_id: &str) {
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(device_id) {
            member.state = MemberState::Suspect;
            member.last_changed = Instant::now();
            log::warn!("Gossip: {} marked as suspect", device_id);
        }
    }

    /// Mark a member as dead (all pings failed).
    pub async fn mark_dead(&self, device_id: &str) {
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(device_id) {
            member.state = MemberState::Dead;
            member.last_changed = Instant::now();
            log::warn!("Gossip: {} marked as dead", device_id);
        }
    }

    /// Get all alive members.
    pub async fn get_alive_members(&self) -> Vec<GossipMember> {
        let members = self.members.read().await;
        members
            .values()
            .filter(|m| m.state == MemberState::Alive)
            .cloned()
            .collect()
    }

    /// Get member count by state.
    pub async fn get_member_counts(&self) -> HashMap<MemberState, usize> {
        let members = self.members.read().await;
        let mut counts = HashMap::new();
        for member in members.values() {
            *counts.entry(member.state).or_default() += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[tokio::test]
    async fn test_gossip_join_and_ping() {
        let gp = GossipProtocol::new("node-a", make_addr(10001));
        gp.join(make_addr(9000)).await;

        // Add a peer
        gp.add_member(GossipMember {
            device_id: "node-b".into(),
            addr: make_addr(10002),
            state: MemberState::Alive,
            incarnation: 0,
            last_changed: Instant::now(),
            metadata: HashMap::new(),
        }).await;

        let (ping_msg, target) = gp.build_ping().await.unwrap();
        assert_eq!(target, "node-b");
    }

    #[tokio::test]
    async fn test_incarnation_bumps_on_conflict() {
        let gp = GossipProtocol::new("node-a", make_addr(10001));
        gp.join(make_addr(9000)).await;

        // Receive update claiming we're dead
        let update = GossipMessage::MembershipUpdate {
            members: vec![GossipMember {
                device_id: "node-a".into(),
                addr: make_addr(10001),
                state: MemberState::Dead,
                incarnation: 5,
                last_changed: Instant::now(),
                metadata: HashMap::new(),
            }],
        };

        gp.process_message(update, make_addr(9000)).await;

        let inc = gp.incarnation.read().await;
        assert!(*inc > 0, "Incarnation should have been bumped");
    }
}
