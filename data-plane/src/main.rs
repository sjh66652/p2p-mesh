//! P2P Mesh Network - Data Plane
//!
//! Build specific binaries:
//!   cargo build --release --bin mesh-tunnel
//!   cargo build --release --bin mesh-relay
//!
//! Library modules: crypto, tunnel, relay (see src/lib.rs)

fn main() {
    println!("P2P Mesh Data Plane v1.0.0");
    println!("  mesh-tunnel - Client P2P endpoint");
    println!("  mesh-relay  - Relay forwarding node");
    println!();
    println!("Build with: cargo build --release --bin mesh-<name>");
}
