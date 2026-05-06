//! mesh-relay — P2P Mesh Network relay forwarding node.
//!
//! Runs on relay servers deployed across regions:
//! 1. Registers with the control plane
//! 2. Accepts encrypted packets from mesh clients
//! 3. Forwards packets without decrypting (zero-trust)
//! 4. Reports load and health metrics via heartbeat

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use p2p_mesh_dataplane::relay::{self, ForwardingTable};
use tokio::net::UdpSocket;

/// P2P Mesh Network Relay Node
#[derive(Parser, Debug)]
#[command(name = "mesh-relay")]
struct Args {
    #[arg(long, default_value = "http://localhost:8000")]
    api_url: String,

    #[arg(long)]
    relay_id: String,

    #[arg(long, default_value = "default")]
    region: String,

    #[arg(long, default_value = "51821")]
    port: u16,

    #[arg(long, default_value = "1000")]
    max_connections: usize,

    #[arg(long, default_value = "1000")]
    bandwidth_mbps: f64,

    #[arg(long, default_value = "30")]
    heartbeat_interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    log::info!(
        "Starting mesh-relay {} in region {} on port {}",
        args.relay_id, args.region, args.port
    );

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let socket = Arc::new(socket);
    log::info!("Relay socket bound to {}", bind_addr);

    let forwarding_table = Arc::new(ForwardingTable::new());
    let client = reqwest::Client::new();
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    let register_payload = serde_json::json!({
        "name": format!("relay-{}", args.relay_id),
        "ip": local_ip,
        "port": args.port,
        "region": args.region,
        "max_capacity": args.max_connections,
        "bandwidth_capacity_mbps": args.bandwidth_mbps,
    });

    match client
        .post(format!("{}/api/v1/relay/register", args.api_url))
        .json(&register_payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::info!("Registered with control plane successfully");
            } else {
                log::warn!("Registration returned: {}", resp.status());
            }
        }
        Err(e) => log::error!("Registration failed: {}", e),
    }

    let relay_table = forwarding_table.clone();
    let relay_socket = socket.clone();
    let relay_task = tokio::spawn(async move {
        relay::relay_loop(relay_socket, relay_table).await;
    });

    let heartbeat_api = args.api_url.clone();
    let heartbeat_id = args.relay_id.clone();
    let heartbeat_interval = args.heartbeat_interval;
    let heartbeat_table = forwarding_table.clone();

    let heartbeat_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(heartbeat_interval)).await;

            let (total_bytes, total_packets, device_count) =
                heartbeat_table.get_stats().await;

            let load = (device_count as f64 / args.max_connections.max(1) as f64).min(1.0);

            let payload = serde_json::json!({
                "load": load,
                "current_connections": device_count,
                "bandwidth_used_mbps": 0.0,
            });

            match client
                .post(format!(
                    "{}/api/v1/relay/{}/heartbeat",
                    heartbeat_api, heartbeat_id
                ))
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        log::debug!(
                            "Heartbeat sent: load={:.2}, connections={}, bytes={}, packets={}",
                            load, device_count, total_bytes, total_packets
                        );
                    }
                }
                Err(e) => log::error!("Heartbeat failed: {}", e),
            }
        }
    });

    tokio::select! {
        _ = relay_task => log::error!("Relay loop exited unexpectedly"),
        _ = heartbeat_task => log::error!("Heartbeat loop exited unexpectedly"),
    }

    Ok(())
}

fn get_local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}
