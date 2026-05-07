//! P2P Mesh Network - Data Plane Library
//!
//! Shared library for mesh-tunnel, mesh-relay, and mesh-stun binaries.
//! Provides:
//! - Cryptographic primitives (ChaCha20-Poly1305 AEAD)
//! - STUN client/server for NAT traversal
//! - UDP hole punching with HELLO/ACK protocol
//! - Tunnel management with encrypted channels
//! - QUIC transport layer
//! - Multi-path routing (direct + relay)
//! - Network quality metrics (RTT, loss, bandwidth)
//! - Relay packet forwarding (zero-trust)

pub mod crypto;
pub mod stun;
pub mod puncher;
pub mod tunnel;
pub mod quic;
pub mod multipath;
pub mod metrics;
pub mod relay;
