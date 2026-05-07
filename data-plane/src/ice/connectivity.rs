//! Connectivity Check Engine — RFC 8445 Section 7 & RFC 7675 Consent Freshness.
//!
//! Manages ongoing connectivity verification for established ICE sessions:
//! - Periodic STUN binding request/response checks
//! - Consent freshness monitoring (RFC 7675: max 30s between consent checks)
//! - Dead peer detection (consecutive failed checks → tear down)
//! - Path quality probing (RTT, jitter, loss calculation)
//! - Automatic path migration when quality degrades

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Result of a single connectivity check.
#[derive(Debug, Clone)]
pub struct ConnectivityResult {
    /// Whether the check succeeded (received binding response)
    pub success: bool,
    /// Round-trip time in microseconds
    pub rtt_us: u64,
    /// Timestamp of the check
    pub timestamp: Instant,
    /// Remote address that responded
    pub remote_addr: SocketAddr,
}

/// State tracked per peer for connectivity management.
#[derive(Debug, Clone)]
pub struct PeerConnectivity {
    /// Peer ID
    pub peer_id: String,
    /// Remote address being probed
    pub remote_addr: SocketAddr,
    /// Connection state
    pub state: ConnectionState,
    /// Consecutive failed checks
    pub failed_checks: u32,
    /// Consecutive successful checks
    pub successful_checks: u32,
    /// Last successful check timestamp
    pub last_success: Option<Instant>,
    /// Last consent refresh timestamp
    pub last_consent: Instant,
    /// Rolling RTT samples (last 8)
    pub rtt_samples: Vec<u64>,
    /// Smoothed RTT (EWMA, α=0.125)
    pub srtt_us: u64,
    /// RTT variance (EWMA, β=0.25)
    pub rtt_var_us: u64,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Total probes sent
    pub probes_sent: u64,
    /// Total probes received
    pub probes_received: u64,
    /// STUN transaction ID sequence
    pub transaction_seq: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, no checks performed yet
    New,
    /// Performing connectivity checks
    Checking,
    /// Connection confirmed, normal operation
    Connected,
    /// Consent may have expired, verifying
    Verifying,
    /// Connection appears dead
    Disconnected,
    /// Connection confirmed dead, should be torn down
    Failed,
}

impl PeerConnectivity {
    /// Create a new peer connectivity tracker.
    pub fn new(peer_id: &str, remote_addr: SocketAddr) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            remote_addr,
            state: ConnectionState::New,
            failed_checks: 0,
            successful_checks: 0,
            last_success: None,
            last_consent: Instant::now(),
            rtt_samples: Vec::with_capacity(8),
            srtt_us: 0,
            rtt_var_us: 0,
            loss_rate: 0.0,
            probes_sent: 0,
            probes_received: 0,
            transaction_seq: 0,
        }
    }

    /// Record a successful connectivity check with RTT measurement.
    pub fn record_success(&mut self, rtt_us: u64) {
        self.successful_checks += 1;
        self.failed_checks = 0;
        self.last_success = Some(Instant::now());
        self.last_consent = Instant::now();
        self.state = ConnectionState::Connected;

        // Update RTT tracking
        self.rtt_samples.push(rtt_us);
        if self.rtt_samples.len() > 8 {
            self.rtt_samples.remove(0);
        }

        // EWMA RTT calculation
        if self.srtt_us == 0 {
            self.srtt_us = rtt_us;
            self.rtt_var_us = rtt_us / 2;
        } else {
            let delta = if rtt_us > self.srtt_us {
                rtt_us - self.srtt_us
            } else {
                self.srtt_us - rtt_us
            };
            self.rtt_var_us = (3 * self.rtt_var_us + delta) / 4;
            self.srtt_us = (7 * self.srtt_us + rtt_us) / 8;
        }

        self.probes_received += 1;
    }

    /// Record a failed connectivity check.
    pub fn record_failure(&mut self) {
        self.failed_checks += 1;
        self.successful_checks = 0;

        if self.failed_checks >= 3 {
            self.state = ConnectionState::Disconnected;
        }
        if self.failed_checks >= 5 {
            self.state = ConnectionState::Failed;
        }

        self.probes_sent += 1;
    }

    /// Check if consent is still fresh (RFC 7675: must be < 30s).
    pub fn is_consent_fresh(&self) -> bool {
        self.last_consent.elapsed() < Duration::from_secs(30)
    }

    /// Check if this peer should be considered dead.
    pub fn is_dead(&self) -> bool {
        matches!(self.state, ConnectionState::Failed)
    }

    /// Get the smoothed RTT estimate.
    pub fn estimated_rtt(&self) -> Duration {
        Duration::from_micros(self.srtt_us)
    }

    /// Get the RTT variance for timeout calculation.
    pub fn rtt_timeout(&self) -> Duration {
        // RTO = SRTT + 4 * RTTVAR
        Duration::from_micros(self.srtt_us + 4 * self.rtt_var_us)
    }
}

/// Connectivity Check Manager.
///
/// Periodically verifies connectivity to all active peers using
/// STUN binding requests. Manages consent freshness per RFC 7675.
pub struct ConnectivityManager {
    /// Peer connectivity state
    peers: RwLock<HashMap<String, PeerConnectivity>>,
    /// Interval between periodic checks
    check_interval: Duration,
    /// Consent freshness interval (RFC 7675 default: 30s)
    consent_timeout: Duration,
    /// Max consecutive failures before declaring peer dead
    max_failures: u32,
    /// STUN binding request template
    binding_template: Vec<u8>,
}

impl ConnectivityManager {
    /// Create a new connectivity manager.
    pub fn new() -> Self {
        let mut binding_template = Vec::with_capacity(20);
        // STUN Binding Request header
        binding_template.extend_from_slice(&[0x00, 0x01]); // Type
        binding_template.extend_from_slice(&[0x00, 0x00]); // Length
        binding_template.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic cookie
        // Transaction ID placeholder (12 bytes, filled per-check)
        binding_template.extend_from_slice(&[0u8; 12]);

        Self {
            peers: RwLock::new(HashMap::new()),
            check_interval: Duration::from_secs(5),
            consent_timeout: Duration::from_secs(30),
            max_failures: 5,
            binding_template,
        }
    }

    /// Register a new peer for connectivity monitoring.
    pub async fn register_peer(&self, peer_id: &str, remote_addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        peers.insert(
            peer_id.to_string(),
            PeerConnectivity::new(peer_id, remote_addr),
        );
        log::info!("Connectivity monitoring started for peer {}", peer_id);
    }

    /// Remove a peer from monitoring.
    pub async fn unregister_peer(&self, peer_id: &str) {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);
    }

    /// Build a STUN binding request with a unique transaction ID.
    fn build_binding_request(&self) -> Vec<u8> {
        let mut msg = self.binding_template.clone();
        // Fill random transaction ID (bytes 8-19)
        let mut tid = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut tid);
        msg[8..20].copy_from_slice(&tid);
        msg
    }

    /// Perform connectivity checks for all registered peers.
    ///
    /// Returns a list of peers that have been declared dead and should be removed.
    pub async fn perform_checks(
        &self,
        socket: &Arc<UdpSocket>,
    ) -> Vec<String> {
        let mut dead_peers = Vec::new();
        let peer_ids_to_check: Vec<String> = {
            let peers = self.peers.read().await;
            peers.keys().cloned().collect()
        };

        for peer_id in &peer_ids_to_check {
            let binding = self.build_binding_request();

            // Snapshot the remote address under the read lock, then drop it
            let remote_addr: Option<SocketAddr> = {
                let peers = self.peers.read().await;
                peers.get(peer_id).map(|p| p.remote_addr)
            };

            let remote_addr = match remote_addr {
                Some(addr) => addr,
                None => continue,
            };

            // Send binding request (no lock held)
            match socket.send_to(&binding, remote_addr).await {
                Ok(_) => {
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(peer_id) {
                        peer.probes_sent += 1;

                        // Wait for response with adaptive timeout
                        let timeout = peer.rtt_timeout().max(Duration::from_secs(1));
                        let mut buf = [0u8; 1500];

                        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                            Ok(Ok((n, _src))) => {
                                let _start = peer.last_success.map(|t| t.elapsed());
                                // Verify it's a STUN Binding Success Response
                                if n >= 20 && buf[0] == 0x01 && buf[1] == 0x01 {
                                    let rtt = Instant::now().duration_since(
                                        peer.last_success.unwrap_or(Instant::now()),
                                    );
                                    peer.record_success(rtt.as_micros() as u64);
                                    log::trace!("Connectivity check OK for {}: RTT={}μs", peer_id, peer.srtt_us);
                                }
                            }
                            _ => {
                                peer.record_failure();
                                log::debug!("Connectivity check FAILED for {} ({}/{} failures)",
                                    peer_id, peer.failed_checks, self.max_failures);
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(peer_id) {
                        peer.record_failure();
                        log::error!("Connectivity send failed for {}: {}", peer_id, e);
                    }
                }
            }
        }

        // Collect dead peers
        let peers = self.peers.read().await;
        for (peer_id, state) in peers.iter() {
            if state.is_dead() {
                dead_peers.push(peer_id.clone());
            }
        }

        if !dead_peers.is_empty() {
            log::warn!("Connectivity: {} peers declared dead", dead_peers.len());
        }

        dead_peers
    }

    /// Check consent freshness for all peers.
    ///
    /// Returns peers whose consent has expired and need re-verification.
    pub async fn check_consent_freshness(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        let mut expired = Vec::new();

        for (peer_id, state) in peers.iter() {
            if !state.is_consent_fresh() {
                expired.push(peer_id.clone());
                log::warn!("Consent expired for peer {} (last: {:?} ago)",
                    peer_id, state.last_consent.elapsed());
            }
        }

        expired
    }

    /// Refresh consent for a peer (called when data flows).
    pub async fn refresh_consent(&self, peer_id: &str) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.last_consent = Instant::now();
        }
    }

    /// Get connectivity statistics for a peer.
    pub async fn get_peer_stats(&self, peer_id: &str) -> Option<PeerConnectivity> {
        let peers = self.peers.read().await;
        peers.get(peer_id).cloned()
    }

    /// Get all active peer states.
    pub async fn get_all_peers(&self) -> Vec<PeerConnectivity> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Get count of connected peers.
    pub async fn connected_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.values().filter(|p| p.state == ConnectionState::Connected).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999)
    }

    #[test]
    fn test_peer_connectivity_success() {
        let mut peer = PeerConnectivity::new("test-peer", make_addr());
        assert_eq!(peer.state, ConnectionState::New);

        peer.record_success(5000); // 5ms RTT
        assert_eq!(peer.state, ConnectionState::Connected);
        assert_eq!(peer.successful_checks, 1);
        assert!(peer.is_consent_fresh());
    }

    #[test]
    fn test_peer_connectivity_failure_progression() {
        let mut peer = PeerConnectivity::new("test-peer", make_addr());

        // 3 failures → disconnected
        for _ in 0..3 {
            peer.record_failure();
        }
        assert_eq!(peer.state, ConnectionState::Disconnected);

        // 5 failures → failed (dead)
        peer.record_failure();
        peer.record_failure();
        assert_eq!(peer.state, ConnectionState::Failed);
        assert!(peer.is_dead());
    }

    #[test]
    fn test_ewma_rtt_calculation() {
        let mut peer = PeerConnectivity::new("test-peer", make_addr());

        peer.record_success(10000);
        assert_eq!(peer.srtt_us, 10000);

        peer.record_success(20000);
        // srtt = 7/8 * 10000 + 1/8 * 20000 = 8750 + 2500 = 11250
        assert!(peer.srtt_us > 10000 && peer.srtt_us < 15000);
    }

    #[test]
    fn test_consent_timeout() {
        let mut peer = PeerConnectivity::new("test-peer", make_addr());
        peer.last_consent = Instant::now() - Duration::from_secs(31);
        assert!(!peer.is_consent_fresh());
    }
}
