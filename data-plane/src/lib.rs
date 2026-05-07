//! P2P Mesh Network - Data Plane Library
//!
//! Shared library for mesh-tunnel, mesh-relay, mesh-stun, and mesh-overlay binaries.
//! Provides:
//! - Cryptographic primitives (ChaCha20-Poly1305 AEAD, Noise Protocol)
//! - STUN client/server for NAT traversal
//! - Full ICE state machine (RFC 8445) for reliable connectivity
//! - TURN relay (RFC 8656) for enterprise NAT environments
//! - UDP hole punching with HELLO/ACK protocol
//! - Tunnel management with encrypted channels
//! - QUIC transport layer
//! - Multi-path routing (direct + relay)
//! - Network quality metrics (RTT, loss, bandwidth)
//! - Relay packet forwarding (zero-trust)
//! - TUN/TAP virtual network interface
//! - Overlay Router with CIDR/LPM routing
//! - IPAM (IP Address Management)
//! - ACL network policy system
//! - Mesh DNS resolver

pub mod crypto;
pub mod stun;
pub mod puncher;
pub mod tunnel;
pub mod quic;
pub mod multipath;
pub mod metrics;
pub mod relay;

// Phase 1 — Overlay Network
pub mod tun;
pub mod router;
pub mod overlay;
pub mod ipam;
pub mod acl;
pub mod dns;
pub mod ice;
pub mod turn;
