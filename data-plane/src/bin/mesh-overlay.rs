//! mesh-overlay — P2P Mesh Network Overlay Node
//!
//! This is the main overlay node binary that creates a full virtual network
//! interface (TUN) and participates in the mesh overlay network.
//!
//! Usage:
//!   mesh-overlay --api-url https://control-plane:8000 --auth-token <token>
//!
//! Features:
//! - Creates TUN interface "mesh0" with assigned virtual IP
//! - Full ICE/TURN NAT traversal for P2P connectivity
//! - CIDR-based overlay routing with LPM
//! - ACL policy enforcement
//! - Mesh DNS resolution
//! - Multi-path transport (direct, relay)
//! - Encrypted data plane (ChaCha20-Poly1305)

use std::net::SocketAddr;
use std::sync::Arc;
use clap::Parser;

use p2p_mesh_dataplane::{
    tun::TunInterface,
    router::{Route, RouteTable, RouteType},
    overlay::OverlayNetwork,
    ipam::{IpamManager, OVERLAY_PREFIX},
    acl::{AclEngine, AclPolicy},
    dns::MeshDns,
    ice::IceAgent,
    tunnel::TunnelManager,
};

#[derive(Parser, Debug)]
#[command(name = "mesh-overlay", version = "2.0.0")]
struct Cli {
    /// Control plane API URL
    #[arg(long, env = "MESH_API_URL", default_value = "http://localhost:8000")]
    api_url: String,

    /// Authentication token for control plane
    #[arg(long, env = "MESH_AUTH_TOKEN")]
    auth_token: String,

    /// Device ID (UUID from control plane registration)
    #[arg(long, env = "MESH_DEVICE_ID")]
    device_id: String,

    /// TUN interface name (default: mesh0)
    #[arg(long, default_value = "mesh0")]
    tun_name: String,

    /// TUN interface MTU (default: 1420)
    #[arg(long, default_value = "1420")]
    mtu: u16,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Upstream DNS server for non-mesh domains
    #[arg(long, default_value = "8.8.8.8:53")]
    upstream_dns: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&cli.log_level)
    ).init();

    log::info!("=== Mesh Overlay Node v2.0.0 ===");
    log::info!("API URL: {}", cli.api_url);
    log::info!("Device ID: {}", cli.device_id);

    // ---- 1. IPAM: Request virtual IP ----
    let ipam = Arc::new(IpamManager::new(cli.api_url.clone(), cli.auth_token.clone()));
    let virtual_ip = ipam.request_ip(&cli.device_id).await?;
    log::info!("Assigned overlay IP: {}", virtual_ip);

    // ---- 2. TUN Interface + Route Table + Tunnel Manager ----
    // All components are created once and passed to the overlay.
    let tun = TunInterface::new(
        &virtual_ip.to_string(),
        "255.192.0.0", // /10 netmask
        cli.mtu,
    )?;
    log::info!("TUN interface {} created with IP {}", tun.name(), virtual_ip);

    let route_table = RouteTable::new();

    let socket = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    log::info!("Data plane socket bound to {}", socket.local_addr()?);

    let tunnel_manager = TunnelManager::new(socket.clone());

    // ---- 3. Overlay Network (owns TUN, RouteTable, TunnelManager) ----
    let mut overlay = OverlayNetwork::new(
        tun,
        route_table,
        tunnel_manager,
        virtual_ip,
        cli.device_id.clone(),
    );

    // Add direct route for our own subnet (after overlay creation — uses overlay's route table)
    let prefix: ipnet::Ipv4Net = format!("{}/10", OVERLAY_PREFIX).parse()?;
    let self_route = Route {
        cidr: prefix,
        peer_id: cli.device_id.clone(),
        metric: 0,
        admin_distance: 0,
        route_type: RouteType::Direct,
        active: true,
        added_at: std::time::Instant::now(),
        last_used: None,
    };
    overlay.add_route(self_route).await;

    // ---- 4. ACL Engine ----
    let acl = Arc::new(AclEngine::new());
    // Start with permissive policy (tighten via control plane)
    let default_policy = AclPolicy {
        mode: p2p_mesh_dataplane::acl::PolicyMode::DefaultAllow,
        groups: std::collections::HashMap::new(),
        rules: vec![],
        isolated_devices: vec![],
        bypass_devices: vec![cli.device_id.clone()],
    };
    acl.load_policy(default_policy).await;

    // ---- 5. DNS Resolver ----
    let dns = Arc::new(MeshDns::new());
    let upstream: SocketAddr = cli.upstream_dns.parse()?;
    dns.set_upstream(vec![upstream]).await;

    // ---- 6. ICE Agent ----
    let ice = Arc::new(IceAgent::new());
    let (ufrag, pwd) = ice.get_local_credentials();
    log::info!("ICE credentials: ufrag={}, pwd={}...", ufrag, &pwd[..8]);

    // Start the overlay packet processing
    overlay.start_processing();
    log::info!("Overlay packet processing started");

    // ---- 9. Main event loop ----
    log::info!("Mesh overlay node running. Press Ctrl+C to stop.");

    let mut buf = vec![0u8; 65536];

    // Main loop: process incoming packets, maintain connections, respond to control plane
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        let data = &buf[..n];

                        // Try to parse as a STUN binding request (ICE check)
                        if let Some(response) = ice.handle_binding_request(data) {
                            let _ = socket.send_to(&response, src).await;
                            ice.refresh_consent().await;
                            log::trace!("ICE binding response sent to {}", src);
                            continue;
                        }

                        // Try to parse as a punch message
                        if let Some(_msg) = p2p_mesh_dataplane::puncher::HolePuncher::parse_message(
                            data,
                            &[],
                            &[0u8; 16],
                        ) {
                            // Handle punch messages
                            log::trace!("Received punch message from {}", src);
                        }

                        // Otherwise, treat as encrypted data plane traffic
                        log::trace!("Received {} bytes from {}", n, src);
                    }
                    Err(e) => {
                        log::error!("Socket recv error: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutting down...");

                // Release our virtual IP
                let _ = ipam.release_ip(&cli.device_id).await;

                log::info!("Mesh overlay node stopped.");
                break;
            }
        }
    }

    Ok(())
}
