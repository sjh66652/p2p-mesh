//! mesh-relay — P2P Mesh Network relay forwarding node.
//!
//! Runs on relay servers deployed across regions:
//! 1. Registers with the control plane (admin pre-registers, relay connects)
//! 2. Accepts encrypted packets from mesh clients
//! 3. Forwards packets without decrypting (zero-trust)
//! 4. Reports load and health metrics via heartbeat
//!
//! Security: Authenticates with RELAY_AUTH_TOKEN (env var), not JWT.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use p2p_mesh_dataplane::relay::{self, ForwardingTable};
use tokio::net::UdpSocket;

/// Emit a warning if a plaintext HTTP URL is used for a non-localhost target.
fn warn_plaintext_http(url: &str, label: &str) {
    if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
        log::warn!(
            "{} uses plain HTTP ({}) — traffic is NOT encrypted. Use HTTPS in production.",
            label, url
        );
    }
}

/// P2P Mesh Network Relay Node
#[derive(Parser, Debug)]
#[command(name = "mesh-relay")]
struct Args {
    /// Control plane API URL — reads API_URL env var.
    #[arg(long, env = "API_URL", default_value = "https://localhost:8443")]
    api_url: String,

    /// Relay auth token — reads RELAY_AUTH_TOKEN env var.
    #[arg(long, env = "RELAY_AUTH_TOKEN", hide_env_values = true)]
    relay_auth_token: String,

    /// Relay node ID — reads RELAY_ID env var.
    #[arg(long, env = "RELAY_ID")]
    relay_id: String,

    /// Region identifier — reads REGION env var.
    #[arg(long, env = "REGION", default_value = "default")]
    region: String,

    /// UDP port for relay traffic.
    #[arg(long, env = "RELAY_PORT", default_value = "51821")]
    port: u16,

    /// Maximum concurrent connections.
    #[arg(long, env = "RELAY_MAX_CONNECTIONS", default_value = "1000")]
    max_connections: usize,

    /// Bandwidth capacity in Mbps.
    #[arg(long, env = "RELAY_BANDWIDTH_MBPS", default_value = "1000")]
    bandwidth_mbps: f64,

    /// Heartbeat interval in seconds.
    #[arg(long, env = "HEARTBEAT_INTERVAL", default_value = "30")]
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

    warn_plaintext_http(&args.api_url, "API URL");

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let socket = Arc::new(socket);
    log::info!("Relay socket bound to {}", bind_addr);

    let forwarding_table = Arc::new(ForwardingTable::new());

    // Relay nodes are pre-registered by an admin through the API.
    // The relay only sends heartbeats — it does NOT self-register.

    let client = reqwest::Client::new();

    let relay_table = forwarding_table.clone();
    let relay_socket = socket.clone();
    let relay_task = tokio::spawn(async move {
        relay::relay_loop(relay_socket, relay_table).await;
    });

    let heartbeat_api = args.api_url.clone();
    let heartbeat_id = args.relay_id.clone();
    let heartbeat_interval = args.heartbeat_interval;
    let heartbeat_table = forwarding_table.clone();
    let relay_token = args.relay_auth_token.clone();
    let max_conn = args.max_connections;

    let heartbeat_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(heartbeat_interval)).await;

            let (total_bytes, total_packets, device_count) =
                heartbeat_table.get_stats().await;

            let load = (device_count as f64 / max_conn.max(1) as f64).min(1.0);

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
                .header("Authorization", format!("Bearer {}", relay_token))
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
                    } else {
                        log::warn!("Heartbeat rejected: HTTP {} — check RELAY_AUTH_TOKEN", resp.status());
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
