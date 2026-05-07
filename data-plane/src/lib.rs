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
//! Phase 9 — AI-Powered Intelli