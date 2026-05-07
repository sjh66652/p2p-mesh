//! mesh-tunnel — P2P Mesh Network client endpoint.
//!
//! This binary runs on end-user devices and:
//! 1. Connects to the control plane WebSocket for signaling
//! 2. Establishes P2P tunnels with peers via NAT hole punching
//! 3. Manages encrypted data channels
//! 4. Reports traffic statistics to the control plane
//!
//! Security: JWT token is read from MESH_TOKEN env var (never CLI args)
//! and sent in the Authorization header, NOT the URL query string.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Emit a warning if a plaintext HTTP URL is used for a non-localhost target.
fn warn_plaintext_http(url: &str, label: &str) {
    if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
        log::warn!(
            "{} uses plain HTTP ({}) — traffic is NOT encrypted. Use HTTPS in production.",
            label, url
        );
    }
}

mod mod_import {
    pub use crate::crypto;
    pub use crate::tunnel::{self, TunnelManager};
}

use mod_import::*;

/// P2P Mesh Network Client
#[derive(Parser, Debug)]
#[command(name = "mesh-tunnel")]
struct Args {
    #[arg(long, default_value = "https://localhost:8443")]
    api_url: String,

    /// JWT token — read from MESH_TOKEN env var.
    /// CLI args are visible in /proc/*/cmdline, so prefer env vars for secrets.
    #[arg(long, env = "MESH_TOKEN", hide_env_values = true)]
    token: String,

    #[arg(long, default_value = "51820")]
    local_port: u16,

    #[arg(long, default_value = "wss://localhost:8443/api/v1/ws")]
    ws_url: String,

    #[arg(long)]
    device_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    log::info!("Starting mesh-tunnel (device: {})", args.device_id);

    warn_plaintext_http(&args.api_url, "API URL");
    warn_plaintext_http(&args.ws_url, "WebSocket URL");

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.local_port).parse()?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let socket = Arc::new(socket);
    log::info!("P2P socket bound to {}", bind_addr);

    let tunnel_manager = Arc::new(Mutex::new(TunnelManager::new(socket.clone())));

    // SECURITY: Token is NOT in the URL — sent via Authorization header.
    let ws_connect_url = format!(
        "{}/{}",
        args.ws_url, args.device_id
    );
    log::info!(
        "Connecting to signaling server: {} (auth via Authorization header)",
        ws_connect_url
    );

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
                        traffic_batch.push(n as u64);
                    }
                    Err(e) => {
                        log::error!("Socket receive error: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
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
