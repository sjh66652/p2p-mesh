//! Mesh Routing — Phase 3 multi-hop routing protocols.
//!
//! Modules:
//! - distance_vector: Simple DV with split horizon + poison reverse
//! - babel: Babel-Z routing protocol (RFC 8966) for loop-free mesh routing
//! - topology: Topology graph, relay election, shortest path computation
//! - gossip: SWIM-style membership and state dissemination

pub mod distance_vector;
pub mod babel;
pub mod topology;
pub mod gossip;
