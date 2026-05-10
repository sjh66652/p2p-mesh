//! P2P Mesh Network — Data Plane Library v2.0
//!
//! Ten-phase evolution from advanced P2P project to production-grade
//! overlay mesh network platform.
//!
//! Phase 1 — Overlay Network Foundation:
//!   tun, router, overlay, ipam, acl, dns, ice, turn, crypto, noise
//!
//! Phase 2 — ICE Path Optimization:
//!   connectivity manager, path selection with Happy Eyeballs
//!
//! Phase 3 — Dynamic Mesh Routing:
//!   distance_vector (Bellman-Ford), babel (RFC 8966), topology, gossip (SWIM)
//!
//! Phase 4 — FastPath Accelerator:
//!   zero-copy batch packet processing with buffer pools
//!
//! Phase 5 — Enterprise Deployment:
//!   PostgreSQL HA, Redis Cluster, ClickHouse, PgBouncer (docker-compose)
//!
//! Phase 6 — eBPF/XDP Kernel Acceleration:
//!   XDP/TC/SocketFilter for kernel-level packet processing
//!
//! Phase 7 — Mobile Platform Integration:
//!   Android (JNI), iOS (C FFI), battery optimization, network switching
//!
//! Phase 8 — Decentralized Control Plane:
//!   Raft consensus, Kademlia DHT, gossip membership
//!
//! Phase 9 — AI-Powered Intelligent Routing:
//!   ML path prediction, congestion forecasting, anomaly detection
//!
//! Phase 10 — Research-Grade Network System:
//!   DPDK, io_uring, QUIC multipath, Post-Quantum Crypto, Smart Relay

// Crate-level lint configuration
#![allow(dead_code)]
#![allow(clippy::new_without_default)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

// Core (Phase 1) — cross-platform
pub mod crypto;
pub mod stun;
pub mod puncher;
pub mod tunnel;
pub mod quic;
pub mod multipath;
pub mod metrics;
pub mod relay;

// External service connectivity — cross-platform
pub mod http_gateway;

// Overlay Network (Phase 1) — Linux/macOS only (requires TUN device)
#[cfg(not(target_os = "windows"))]
pub mod tun;
#[cfg(not(target_os = "windows"))]
pub mod router;
#[cfg(not(target_os = "windows"))]
pub mod overlay;
#[cfg(not(target_os = "windows"))]
pub mod ipam;
#[cfg(not(target_os = "windows"))]
pub mod acl;
#[cfg(not(target_os = "windows"))]
pub mod dns;
#[cfg(not(target_os = "windows"))]
pub mod ice;
#[cfg(not(target_os = "windows"))]
pub mod turn;

// Dynamic Mesh Routing (Phase 3) — cross-platform
pub mod mesh_routing;

// FastPath Accelerator (Phase 4) — cross-platform
pub mod fastpath;

// eBPF/XDP Kernel Acceleration (Phase 6) — Linux-only
#[cfg(target_os = "linux")]
pub mod ebpf;

// Mobile Platform Integration (Phase 7) — cross-platform
pub mod mobile;

// Decentralized Control Plane (Phase 8) — cross-platform
pub mod decentralized;

// AI-Powered Intelligent Routing (Phase 9) — cross-platform
pub mod ai_routing;

// Research-Grade Network System (Phase 10)
#[cfg(not(target_os = "windows"))]
pub mod dpdk;           // Linux DPDK userspace networking
#[cfg(not(target_os = "windows"))]
pub mod io_uring;       // Linux io_uring async I/O
pub mod quic_multipath; // Cross-platform QUIC multipath
pub mod post_quantum;   // Cross-platform post-quantum crypto
pub mod smart_relay;    // Cross-platform smart relay selection
