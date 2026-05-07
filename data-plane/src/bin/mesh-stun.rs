//! mesh-stun — P2P Mesh Network STUN server.
//!
//! A lightweight STUN server that helps mesh clients discover their
//! public IP:port mapping behind NATs.
//!
//! Protocol: client sends "ping", server responds with "IP:PORT".
//!
//! Run:
//!   cargo build --release --bin mesh-stun
//!   ./target/release/mesh-stun --port 3478

use clap::Parser;

/// P2P Mesh Network STUN Server
#[derive(Parser, Debug)]
#[command(name = "mesh-stun")]
struct Args {
    /// Port to listen on (default: standard STUN port 3478)
    #[arg(long, default_value = "3478")]
    port: u16,

    /// Bind address (default: all interfaces)
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    let bind_addr = format!("{}:{}", args.bind, args.port);
    log::info!("Starting STUN server on {}", bind_addr);

    p2p_mesh_dataplane::stun::run_stun_server(&bind_addr).await?;

    Ok(())
}
