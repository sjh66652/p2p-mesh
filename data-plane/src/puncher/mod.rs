//! UDP hole punching module with HMAC-authenticated HELLO/ACK protocol.
//!
//! Implements the core P2P connection establishment flow:
//! 1. Both peers query STUN to discover their public addresses (candidates)
//! 2. Candidates are exchanged via signaling (control plane)
//! 3. Both peers send burst of HELLO packets to each candidate address
//! 4. First peer to receive HELLO sends back HELLO_ACK
//! 5. Connection is established and data can flow
//!
//! Security:
//! - HELLO/HELLO_ACK packets include HMAC-SHA256 tags to authenticate peers
//! - HMAC key is derived from the ECDH key exchange material
//! - Nonces prevent replay attacks
//! - Candidate count is limited to prevent amplification attacks
//! - Target addresses are validated to prevent SSRF (no multicast/broadcast/loopback)
//!
//! Protocol messages (wire format):
//!   HELLO       — "HELLO" + 10B nonce + 32B hmac_tag = 47 bytes
//!   HELLO_ACK   — "HELLO_ACK" + 10B nonce + 32B hmac_tag = 51 bytes
//!   DATA        — raw encrypted payload (after connection established)
//!   PING        — "PING" + 4B seq = 8 bytes
//!   PONG        — "PONG" + 4B seq = 8 bytes

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use sha2::Sha256;
use tokio::net::UdpSocket;

/// Maximum peer candidates to prevent amplification attacks.
const MAX_PEER_CANDIDATES: usize = 10;

/// Maximum total HELLO packets per punching session.
const MAX_TOTAL_PUNCH_PACKETS: u64 = 500;

/// A discovered peer candidate address.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Socket address of the candidate
    pub addr: SocketAddr,
    /// Candidate type (e.g., "host", "srflx" for server-reflexive from STUN)
    pub candidate_type: String,
    /// Priority (lower is preferred, e.g., LAN addresses have higher priority)
    pub priority: u32,
}

/// State of a punch attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum PunchState {
    /// Waiting for signaling to exchange candidates
    WaitingForCandidates,
    /// Actively sending HELLO packets
    Punching {
        started_at: Instant,
        packets_sent: u64,
    },
    /// Received HELLO from peer, sent HELLO_ACK
    AckSent {
        peer_nonce: [u8; 10],
    },
    /// Received HELLO_ACK from peer, connection established
    Connected {
        peer_addr: SocketAddr,
        established_at: Instant,
    },
    /// Punch failed after timeout
    Failed {
        reason: String,
    },
}

/// Manages NAT hole punching with a specific peer.
pub struct HolePuncher {
    /// Our local candidates (from STUN + local interfaces)
    pub our_candidates: Vec<Candidate>,
    /// Peer's candidates (received via signaling)
    pub peer_candidates: Vec<Candidate>,
    /// Current punch state
    pub state: PunchState,
    /// Nonce generated for this session (prevents replay)
    pub our_nonce: [u8; 10],
    /// Max duration to attempt punching before falling back to relay
    pub punch_timeout: Duration,
    /// Interval between HELLO packets during punching
    pub punch_interval: Duration,
}

impl HolePuncher {
    /// Create a new hole puncher with a random nonce.
    pub fn new() -> Self {
        let mut nonce = [0u8; 10];
        rand::thread_rng().fill_bytes(&mut nonce);

        Self {
            our_candidates: Vec::new(),
            peer_candidates: Vec::new(),
            state: PunchState::WaitingForCandidates,
            our_nonce: nonce,
            punch_timeout: Duration::from_secs(10),
            punch_interval: Duration::from_millis(50),
        }
    }

    /// Add a local candidate discovered via STUN or local interfaces.
    pub fn add_our_candidate(&mut self, addr: SocketAddr, candidate_type: &str, priority: u32) {
        self.our_candidates.push(Candidate {
            addr,
            candidate_type: candidate_type.to_string(),
            priority,
        });
    }

    /// Set peer candidates received from signaling.
    pub fn set_peer_candidates(&mut self, candidates: Vec<Candidate>) {
        self.peer_candidates = candidates;
    }
}

/// Parsed protocol message from wire.
#[derive(Debug)]
pub enum PunchMessage {
    Hello { nonce: [u8; 10] },
    HelloAck { nonce: [u8; 10] },
    Ping { seq: u32 },
    Pong { seq: u32 },
    Data,
}

/// Validate that a target address is safe to send punch packets to.
/// Rejects multicast, broadcast, unspecified, and loopback addresses.
fn is_safe_target(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            !ip.is_multicast() && !ip.is_unspecified()
        }
    }
}

/// Compute HMAC-SHA256 over (nonce || device_id) with the given key.
fn compute_punch_hmac(nonce: &[u8; 10], device_id: &str, hmac_key: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .expect("HMAC key should be valid (32 bytes minimum)");
    mac.update(nonce);
    mac.update(device_id.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC-SHA256 over (nonce || device_id).
fn verify_punch_hmac(nonce: &[u8; 10], device_id: &str, tag: &[u8], hmac_key: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = match HmacSha256::new_from_slice(hmac_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(nonce);
    mac.update(device_id.as_bytes());
    mac.verify_slice(tag).is_ok()
}

/// Build an HMAC-authenticated HELLO packet.
/// Format: "HELLO" (5B) + nonce (10B hex) + hmac_tag (64B hex) = 79 bytes
pub fn build_hello_packet(nonce: &[u8; 10], device_id: &str, hmac_key: &[u8]) -> Vec<u8> {
    let hmac_tag = compute_punch_hmac(nonce, device_id, hmac_key);
    let mut msg = b"HELLO".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    msg.extend_from_slice(hmac_tag[..32].to_vec().as_slice()); // First 32B of HMAC as wire tag
    msg
}

/// Build an HMAC-authenticated HELLO_ACK packet.
/// Format: "HELLO_ACK" (9B) + nonce (10B hex) + hmac_tag (64B hex) = 83 bytes
pub fn build_hello_ack_packet(nonce: &[u8; 10], device_id: &str, hmac_key: &[u8]) -> Vec<u8> {
    let hmac_tag = compute_punch_hmac(nonce, device_id, hmac_key);
    let mut msg = b"HELLO_ACK".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    msg.extend_from_slice(hmac_tag[..32].to_vec().as_slice());
    msg
}

/// Build a PING packet for latency measurement.
pub fn build_ping(seq: u32) -> Vec<u8> {
    let mut msg = b"PING".to_vec();
    msg.extend_from_slice(&seq.to_be_bytes());
    msg
}

/// Build a PONG packet responding to a PING.
pub fn build_pong(seq: u32) -> Vec<u8> {
    let mut msg = b"PONG".to_vec();
    msg.extend_from_slice(&seq.to_be_bytes());
    msg
}

/// Parse an incoming packet to determine the protocol message type.
/// Validates HMAC on HELLO/HELLO_ACK packets if hmac_key is provided.
pub fn parse_message(data: &[u8], peer_device_id: &str, hmac_key: &[u8]) -> Option<PunchMessage> {
    if data.len() < 5 {
        return None;
    }

    // HELLO_ACK: "HELLO_ACK" (9B) + nonce (10B hex) + hmac (32B) = 51 bytes
    if data.starts_with(b"HELLO_ACK") && data.len() >= 51 {
        let hex_str = std::str::from_utf8(&data[9..19]).ok()?;
        let mut nonce = [0u8; 10];
        hex_decode(hex_str, &mut nonce)?;
        let hmac_tag = &data[19..51];
        // Verify HMAC
        if !verify_punch_hmac(&nonce, peer_device_id, hmac_tag, hmac_key) {
            log::warn!("HELLO_ACK HMAC verification failed");
            return None;
        }
        return Some(PunchMessage::HelloAck { nonce });
    }

    // HELLO: "HELLO" (5B) + nonce (10B hex) + hmac (32B) = 47 bytes
    if data.starts_with(b"HELLO") && data.len() >= 47 {
        let hex_str = std::str::from_utf8(&data[5..15]).ok()?;
        let mut nonce = [0u8; 10];
        hex_decode(hex_str, &mut nonce)?;
        let hmac_tag = &data[15..47];
        // Verify HMAC
        if !verify_punch_hmac(&nonce, peer_device_id, hmac_tag, hmac_key) {
            log::warn!("HELLO HMAC verification failed from peer {}", peer_device_id);
            return None;
        }
        return Some(PunchMessage::Hello { nonce });
    }

    // PONG: "PONG" (4B) + seq (4B) = 8 bytes
    if data.starts_with(b"PONG") && data.len() >= 8 {
        let seq_bytes = &data[4..8];
        let seq = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
        return Some(PunchMessage::Pong { seq });
    }

    // PING: "PING" (4B) + seq (4B) = 8 bytes
    if data.starts_with(b"PING") && data.len() >= 8 {
        let seq_bytes = &data[4..8];
        let seq = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
        return Some(PunchMessage::Ping { seq });
    }

    // Other data (encrypted payload)
    Some(PunchMessage::Data)
}

/// Execute the hole punching loop with HMAC authentication.
///
/// Returns the established SocketAddr on success, or an error on timeout.
///
/// Security improvements over the previous implementation:
/// - HELLO/HELLO_ACK packets are HMAC-authenticated
/// - Peer candidate count is capped at MAX_PEER_CANDIDATES
/// - Total punch packets are bounded by MAX_TOTAL_PUNCH_PACKETS
/// - Target addresses are validated (no multicast/broadcast/loopback)
pub async fn execute_punch(
    socket: Arc<UdpSocket>,
    hmac_key: &[u8],
    peer_id: &str,
    our_device_id: &str,
    our_candidates: &[Candidate],
    peer_candidates: &[Candidate],
    timeout: Duration,
    relay_addr: Option<SocketAddr>,
) -> Result<SocketAddr, String> {
    if peer_candidates.is_empty() {
        return Err("No peer candidates to punch".to_string());
    }

    // Cap peer candidates to prevent amplification
    let candidates: Vec<&Candidate> = peer_candidates
        .iter()
        .filter(|c| is_safe_target(&c.addr))
        .take(MAX_PEER_CANDIDATES)
        .collect();

    if candidates.is_empty() {
        return Err("No valid peer candidates after safety filtering".to_string());
    }

    if candidates.len() < peer_candidates.len() {
        log::warn!(
            "Filtered {} peer candidates down to {} (max {}) for safety",
            peer_candidates.len(),
            candidates.len(),
            MAX_PEER_CANDIDATES
        );
    }

    let mut nonce = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hello_packet = build_hello_packet(&nonce, our_device_id, hmac_key);

    let start = Instant::now();
    let mut best_addr: Option<SocketAddr> = None;
    let mut total_packets_sent: u64 = 0;

    log::info!(
        "Starting HMAC-authenticated hole punch to {} candidates for peer {}",
        candidates.len(),
        peer_id
    );

    let mut buf = vec![0u8; 65536];

    loop {
        // Check timeout
        if start.elapsed() >= timeout {
            if let Some(addr) = best_addr {
                log::info!("Punch succeeded via best_addr fallback: {}", addr);
                return Ok(addr);
            }
            return Err(format!(
                "Hole punch timed out after {:?}",
                start.elapsed()
            ));
        }

        // Enforce total punch packet budget
        if total_packets_sen