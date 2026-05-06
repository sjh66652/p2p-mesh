//! mesh-tunnel — P2P Mesh Network client endpoint.
//!
//! This binary runs on end-user devices and:
//! 1. Connects to the control plane WebSocket for signaling
//! 2. Establishes P2P tunnels with peers via NAT hole punching
//! 3. Manages encrypted data channels
//! 4. Reports traffic statistics to the control plane

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

mod mod_import {
    pub use crate::crypto;
    pub use crate::tunnel::{self, TunnelManager};
}

use mod_import::*;

/// P2P Mesh Network Client
#[derive(Parser, Debug)]
#[command(name = "mesh-tunnel")]
struct Args {
    /// Control plane API URL
    #[arg(long, default_value = "http://localhost:8000")]
    api_url: String,

    /// JWT token for authentication
    #[arg(long, env = "MESH_TOKEN")]
    token: String,

    /// Local UDP port for P2P traffic
    #[arg(long, default_value = "51820")]
    local_port: u16,

    /// WebSocket signaling URL
    #[arg(long, default_value = "ws://localhost:8000/api/v1/ws")]
    ws_url: String,

    /// Device ID as registered in the control plane
    #[arg(long)]
    device_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    log::info!("Starting mesh-tunnel (device: {})", args.device_id);

    // Bind local UDP socket for P2P traffic
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.local_port).parse()?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let socket = Arc::new(socket);
    log::info!("P2P socket bound to {}", bind_addr);

    // Initialize tunnel manager
    let tunnel_manager = Arc::new(Mutex::new(TunnelManager::new(socket.clone())));

    // Connect to control plane WebSocket for signaling
    let ws_connect_url = format!(
        "{}/{}?token={}",
        args.ws_url, args.device_id, args.token
    );

    log::info!("Connecting to signaling server: {}", ws_connect_url);

    // In a full implementation, this would:
    // 1. Connect WebSocket to ws_connect_url
    // 2. Listen for signaling messages (offers, answers, ICE candidates)
    // 3. Perform UDP hole punching
    // 4. Establish encrypted tunnels
    // 5. Start the data forwarding loop

    // Main loop: receive P2P packets and forward to local TUN interface
    let mut buf = vec![0u8; 65536];
    let mut traffic_batch: Vec<u64> = Vec::new();
    let report_interval = Duration::from_secs(60);
    let mut last_report = tokio::time::Instant::now();

    log::info!("Tunnel active. Listening for P2P traffic...");

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        log::trace!("Received {} bytes from {}", n, src_addr);
                        // Attempt to decrypt with known session keys
                        // In a full implementation, iterate over tunnels and try decryption

                        traffic_batch.push(n as u64);
                    }
                    Err(e) => {
                        log::error!("Socket receive error: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                // Periodic traffic reporting
                if last_report.elapsed() >= report_interval && !traffic_batch.is_empty() {
                    report_traffic(&args.api_url, &args.token, &args.device_id, &traffic_batch).await;
                    traffic_batch.clear();
                    last_report = tokio::time::Instant::now();
                }
            }
        }
    }

    Ok(())
}

/// Report traffic statistics to the control plane API.
async fn report_traffic(
    api_url: &str,
    token: &str,
    device_id: &str,
    bytes_list: &[u64],
) {
    let total_bytes: u64 = bytes_list.iter().sum();
    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "device_id": device_id,
        "bytes_received": total_bytes,
        "bytes_sent": 0,
        "connection_type": "p2p",
    });

    match client
        .post(format!("{}/api/v1/traffic/report", api_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::debug!("Traffic reported: {} bytes", total_bytes);
            } else {
                log::warn!("Traffic report failed: {}", resp.status());
            }
        }
        Err(e) => log::error!("Traffic report error: {}", e),
    }
}
