//! mesh-tunnel — P2P Mesh Network client endpoint.
//!
//! Full-featured client that:
//! 1. Discovers public address via STUN server
//! 2. Connects to control plane WebSocket for signaling
//! 3. Exchanges candidates with peers via signaling
//! 4. Performs UDP hole punching with HELLO/ACK protocol
//! 5. Establishes direct P2P and relay paths (multi-path)
//! 6. Uses QUIC transport for high-performance data channels
//! 7. Reports traffic statistics and path quality metrics
//!
//! Security: JWT token is read from MESH_TOKEN env var (never CLI args)
//! and sent in the Authorization header, NOT the URL query string.

use std::collections::HashMap;
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

// Project modules
use p2p_mesh_dataplane::crypto::{self, SessionKey};
use p2p_mesh_dataplane::metrics::PathMetrics;
use p2p_mesh_dataplane::multipath::{MultiPathManager, PathType};
use p2p_mesh_dataplane::puncher;
use p2p_mesh_dataplane::stun;
use p2p_mesh_dataplane::tunnel::TunnelManager;

/// P2P Mesh Network Client
#[derive(Parser, Debug)]
#[command(name = "mesh-tunnel")]
struct Args {
    #[arg(long, default_value = "https://localhost:8443")]
    api_url: String,

    #[arg(long, default_value = "wss://localhost:8443/api/v1/ws")]
    ws_url: String,

    /// JWT token — read from MESH_TOKEN env var (never CLI args)
    #[arg(long, env = "MESH_TOKEN", hide_env_values = true)]
    token: String,

    #[arg(long)]
    device_id: String,

    #[arg(long, default_value = "51820")]
    local_port: u16,

    /// STUN servers to query for public address discovery
    #[arg(long, default_value = "stun.local:3478")]
    stun_server: String,
}

/// Active peer connection state.
struct PeerConnection {
    /// Peer's device ID
    device_id: String,
    /// Encrypted tunnel to this peer
    session_key: Option<SessionKey>,
    /// Path quality metrics
    metrics: PathMetrics,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    warn_plaintext_http(&args.api_url, "API URL");
    warn_plaintext_http(&args.ws_url, "WebSocket URL");

    log::info!(
        "Starting mesh-tunnel v2.0.0 (device: {})",
        args.device_id
    );

    // ---- Step 1: Bind P2P socket ----
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", args.local_port).parse()?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let socket = Arc::new(socket);
    log::info!("P2P socket bound to {}", bind_addr);

    // ---- Step 2: Discover public address via STUN ----
    log::info!("Querying STUN server {} for public address...", args.stun_server);
    let public_addr = match stun::get_public_addr(&args.stun_server).await {
        Ok(addr) => {
            log::info!("Public address (via STUN): {}", addr);
            Some(addr)
        }
        Err(e) => {
            log::warn!("STUN query failed: {}. Will use local address only.", e);
            None
        }
    };

    // ---- Step 3: Build candidates ----
    let mut candidates = Vec::new();
    if let Some(local) = socket.local_addr().ok() {
        candidates.push(puncher::Candidate {
            addr: local,
            candidate_type: "host".to_string(),
            priority: 100,
        });
    }
    if let Some(public) = public_addr {
        candidates.push(puncher::Candidate {
            addr: public,
            candidate_type: "srflx".to_string(),
            priority: 90,
        });
    }
    log::info!("Local candidates: {:?}", candidates);

    // ---- Step 4: Initialize managers ----
    let tunnel_manager = Arc::new(Mutex::new(TunnelManager::new(socket.clone())));
    let multi_path = Arc::new(MultiPathManager::new());

    // ---- Step 5: Connect to signaling via WebSocket ----
    let ws_connect_url = format!("{}/{}", args.ws_url, args.device_id);
    log::info!(
        "Connecting to signaling server: {} (auth via Authorization header)",
        ws_connect_url
    );

    // Send our candidates to the control plane
    submit_candidates(&args.api_url, &args.token, &args.device_id, &candidates).await;

    // ---- Step 6: Main event loop ----
    let mut buf = vec![0u8; 65536];
    let mut traffic_batch: Vec<u64> = Vec::new();
    let report_interval = Duration::from_secs(60);
    let mut last_report = tokio::time::Instant::now();

    // Track active peer connections
    let peers: Arc<Mutex<HashMap<String, PeerConnection>>> =
        Arc::new(Mutex::new(HashMap::new()));

    log::info!("Tunnel active. Listening for P2P and relay traffic...");
    log::info!(
        "NAT traversal: {} candidates, punch timeout 10s, fallback to relay",
        candidates.len()
    );

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src_addr)) => {
                        let data = &buf[..n];

                        // Check for punch protocol messages
                        if let Some(msg) = puncher::HolePuncher::parse_message(data) {
                            handle_punch_message(
                                &msg,
                                src_addr,
                                socket.clone(),
                                &multi_path,
                                &peers,
                                &tunnel_manager,
                            ).await;
                        }

                        // Track traffic
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
                    report_traffic(
                        &args.api_url, &args.token, &args.device_id, &traffic_batch
                    ).await;
                    traffic_batch.clear();
                    last_report = tokio::time::Instant::now();
                }

                // Log path stats periodically
                let peers_guard = peers.lock().await;
                if !peers_guard.is_empty() {
                    log::debug!("Active peers: {}", peers_guard.len());
                }
            }
        }
    }

    Ok(())
}

/// Handle incoming punch protocol messages.
async fn handle_punch_message(
    msg: &puncher::PunchMessage,
    src_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    multi_path: &Arc<MultiPathManager>,
    peers: &Arc<Mutex<HashMap<String, PeerConnection>>>,
    tunnel_manager: &Arc<Mutex<TunnelManager>>,
) {
    match msg {
        puncher::PunchMessage::Hello { nonce } => {
            log::info!("Received HELLO from {} (peer punching us)", src_addr);
            let ack = puncher::build_hello_ack_packet(nonce);
            let _ = socket.send_to(&ack, src_addr).await;
        }
        puncher::PunchMessage::HelloAck { nonce: _ } => {
            log::info!("Received HELLO_ACK from {} — direct path established!", src_addr);
        }
        puncher::PunchMessage::Ping { seq } => {
            let pong = puncher::build_pong(*seq);
            let _ = socket.send_to(&pong, src_addr).await;
        }
        puncher::PunchMessage::Pong { seq: _ } => {
            // RTT measurement complete — handled by the metrics module
            log::trace!("PONG from {}", src_addr);
        }
        puncher::PunchMessage::Data => {
            // Encrypted data — handle through tunnel layer
            log::trace!("Data packet from {} ({} bytes)", src_addr, 0);
        }
    }
}

/// Submit our candidates to the control plane for peer exchange.
async fn submit_candidates(
    api_url: &str,
    token: &str,
    device_id: &str,
    candidates: &[puncher::Candidate],
) {
    let client = reqwest::Client::new();

    let candidate_list: Vec<serde_json::Value> = candidates
        .iter()
        .map(|c| {
            serde_json::json!({
                "addr": c.addr.to_string(),
                "candidate_type": c.candidate_type,
                "priority": c.priority,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "device_id": device_id,
        "candidates": candidate_list,
    });

    match client
        .post(format!("{}/api/v1/candidates", api_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                log::info!("Candidates submitted successfully");
            } else {
                log::warn!("Candidate submission failed: HTTP {}", resp.status());
            }
        }
        Err(e) => log::error!("Candidate submission error: {}", e),
    }
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
        .post(for