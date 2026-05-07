//! UDP hole punching module with HELLO/ACK protocol.
//!
//! Implements the core P2P connection establishment flow:
//! 1. Both peers query STUN to discover their public addresses (candidates)
//! 2. Candidates are exchanged via signaling (control plane)
//! 3. Both peers send burst of HELLO packets to each candidate address
//! 4. First peer to receive HELLO sends back HELLO_ACK
//! 5. Connection is established and data can flow
//!
//! Protocol messages (wire format) — now with HMAC-SHA256 authentication:
//!   HELLO       — "HELLO{nonce}{hmac}"  (47 bytes: 5 + 10-byte hex nonce + 32-byte HMAC)
//!   HELLO_ACK   — "HELLO_ACK{nonce}{hmac}" (51 bytes: 9 + 10-byte hex nonce + 32-byte HMAC)
//!   DATA        — raw encrypted payload (after connection established)
//!   PING        — "PING{seq}" (8 bytes: 4 + 4-byte seq)
//!   PONG        — "PONG{seq}" (8 bytes: 4 + 4-byte seq)
//!
//! HMAC covers: device_id_bytes (16B) || message_prefix || nonce_bytes (10B)
//! This prevents unauthorized devices from triggering punch operations.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Maximum number of peer candidates to accept (prevents memory exhaustion).
pub const MAX_PEER_CANDIDATES: usize = 10;

/// Maximum total punch packets sent per session (DoS prevention).
const MAX_TOTAL_PUNCH_PACKETS: u64 = 500;

type HmacSha256 = Hmac<Sha256>;

/// Check if a target address is safe to send punch packets to.
///
/// Rejects multicast, broadcast, unspecified, and loopback addresses
/// to prevent amplification attacks and SSRF.
fn is_safe_target(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.is_loopback()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
        }
    }
}

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

    /// Generate a HELLO packet with HMAC-SHA256 authentication.
    pub fn build_hello(&self, hmac_key: &[u8], device_id: &[u8; 16]) -> Vec<u8> {
        let mut msg = b"HELLO".to_vec();
        msg.extend_from_slice(&hex_encode(&self.our_nonce));
        let hmac_tag = compute_punch_hmac(hmac_key, device_id, b"HELLO", &self.our_nonce);
        msg.extend_from_slice(&hmac_tag);
        msg
    }

    /// Generate a HELLO_ACK packet with HMAC-SHA256 authentication.
    pub fn build_hello_ack(&self, peer_nonce: &[u8; 10], hmac_key: &[u8], device_id: &[u8; 16]) -> Vec<u8> {
        let mut msg = b"HELLO_ACK".to_vec();
        msg.extend_from_slice(&hex_encode(peer_nonce));
        let hmac_tag = compute_punch_hmac(hmac_key, device_id, b"HELLO_ACK", peer_nonce);
        msg.extend_from_slice(&hmac_tag);
        msg
    }

    /// Parse an incoming packet, verifying HMAC on HELLO/HELLO_ACK messages.
    ///
    /// Returns None if the packet is malformed, HMAC verification fails,
    /// or the packet type is unrecognized with insufficient data.
    pub fn parse_message(data: &[u8], hmac_key: &[u8], device_id: &[u8; 16]) -> Option<PunchMessage> {
        if data.len() < 5 {
            return None;
        }

        // HELLO_ACK: "HELLO_ACK" (9) + nonce_hex (10) + hmac (32) = 51 bytes
        if data.starts_with(b"HELLO_ACK") && data.len() >= 51 {
            let hex_str = std::str::from_utf8(&data[9..19]).ok()?;
            let mut nonce = [0u8; 10];
            hex_decode(hex_str, &mut nonce)?;
            let hmac_tag = &data[19..51];
            if !verify_punch_hmac(hmac_key, device_id, b"HELLO_ACK", &nonce, hmac_tag) {
                log::warn!("HMAC verification failed for HELLO_ACK packet");
                return None;
            }
            Some(PunchMessage::HelloAck { nonce })
        // HELLO: "HELLO" (5) + nonce_hex (10) + hmac (32) = 47 bytes
        } else if data.starts_with(b"HELLO") && data.len() >= 47 {
            let hex_str = std::str::from_utf8(&data[5..15]).ok()?;
            let mut nonce = [0u8; 10];
            hex_decode(hex_str, &mut nonce)?;
            let hmac_tag = &data[15..47];
            if !verify_punch_hmac(hmac_key, device_id, b"HELLO", &nonce, hmac_tag) {
                log::warn!("HMAC verification failed for HELLO packet");
                return None;
            }
            Some(PunchMessage::Hello { nonce })
        } else if data.starts_with(b"PONG") && data.len() >= 8 {
            let seq_bytes = &data[4..8];
            let seq = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
            Some(PunchMessage::Pong { seq })
        } else if data.starts_with(b"PING") && data.len() >= 8 {
            let seq_bytes = &data[4..8];
            let seq = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
            Some(PunchMessage::Ping { seq })
        } else {
            Some(PunchMessage::Data)
        }
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

/// Execute the hole punching loop with HMAC authentication and DoS protection.
///
/// Returns the established SocketAddr on success, or an error on timeout.
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

    // Security: limit peer candidates to prevent memory exhaustion
    if peer_candidates.len() > MAX_PEER_CANDIDATES {
        return Err(format!(
            "Too many peer candidates: {} (max {})",
            peer_candidates.len(),
            MAX_PEER_CANDIDATES
        ));
    }

    // Validate all candidates are safe targets
    for c in peer_candidates {
        if !is_safe_target(&c.addr) {
            return Err(format!("Unsafe target address rejected: {}", c.addr));
        }
    }

    // Convert device_id to fixed 16-byte array for HMAC computation
    let mut our_dev_id_bytes = [0u8; 16];
    let id_bytes = our_device_id.as_bytes();
    let copy_len = id_bytes.len().min(16);
    our_dev_id_bytes[..copy_len].copy_from_slice(&id_bytes[..copy_len]);

    let mut peer_dev_id_bytes = [0u8; 16];
    let peer_id_bytes = peer_id.as_bytes();
    let copy_len = peer_id_bytes.len().min(16);
    peer_dev_id_bytes[..copy_len].copy_from_slice(&peer_id_bytes[..copy_len]);

    let mut nonce = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut nonce);
    
    // Build HELLO with HMAC using PEER's device ID (peer verifies against its own ID)
    let hello_packet = build_hello_packet_with_hmac(hmac_key, &peer_dev_id_bytes, &nonce);

    let start = Instant::now();
    let mut total_packets_sent: u64 = 0;
    let mut best_addr: Option<SocketAddr> = None;

    log::info!(
        "Starting authenticated hole punch to {} candidates for peer {}",
        peer_candidates.len(),
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

        // Enforce total punch packet budget (DoS prevention)
        if total_packets_sent >= MAX_TOTAL_PUNCH_PACKETS {
            return Err(format!(
                "Punch packet budget exceeded ({})", MAX_TOTAL_PUNCH_PACKETS
            ));
        }

        // Send HELLO to all peer candidates (with HMAC)
        for candidate in peer_candidates {
            if let Err(e) = socket.send_to(&hello_packet, candidate.addr).await {
                log::trace!("Punch send failed to {}: {}", candidate.addr, e);
            }
            total_packets_sent += 1;
        }

        // Listen for incoming packets (non-blocking, short timeout)
        match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src_addr))) => {
                let data = &buf[..n];
                // Verify HMAC using OUR device ID (packets sent to us are HMAC'd with our ID)
                if let Some(msg) = HolePuncher::parse_message(data, hmac_key, &our_dev_id_bytes) {
                    match msg {
                        PunchMessage::Hello { nonce: peer_nonce } => {
                            log::info!(
                                "Received authenticated HELLO from {} (peer punching us)",
                                src_addr
                            );
                            let ack = build_hello_ack_packet_with_hmac(
                                hmac_key, &peer_dev_id_bytes, &peer_nonce
                            );
                            let _ = socket.send_to(&ack, src_addr).await;
                            total_packets_sent += 1;
                            best_addr = Some(src_addr);
                        }
                        PunchMessage::HelloAck { nonce: ack_nonce } => {
                            if ack_nonce == nonce {
                                log::info!(
                                    "Received valid HELLO_ACK from {} — connection established!",
                                    src_addr
                                );
                                return Ok(src_addr);
                            } else {
                                log::debug!(
                                    "Received HELLO_ACK with wrong nonce from {}",
                                    src_addr
                                );
                            }
                        }
                        _ => {
                            log::trace!(
                                "Received non-punch message from {} during punching",
                                src_addr
                            );
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                log::error!("Socket error during punch: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                // Timeout on recv — normal, continue sending HELLO
            }
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Build a HELLO packet with HMAC-SHA256 authentication.
/// Format: "HELLO" (5) + nonce_hex (10) + hmac_tag (32) = 47 bytes
pub fn build_hello_packet_with_hmac(
    hmac_key: &[u8],
    device_id: &[u8; 16],
    nonce: &[u8; 10],
) -> Vec<u8> {
    let mut msg = b"HELLO".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    let hmac_tag = compute_punch_hmac(hmac_key, device_id, b"HELLO", nonce);
    msg.extend_from_slice(&hmac_tag);
    msg
}

/// Build a HELLO_ACK packet with HMAC-SHA256 authentication.
/// Format: "HELLO_ACK" (9) + nonce_hex (10) + hmac_tag (32) = 51 bytes
pub fn build_hello_ack_packet_with_hmac(
    hmac_key: &[u8],
    device_id: &[u8; 16],
    nonce: &[u8; 10],
) -> Vec<u8> {
    let mut msg = b"HELLO_ACK".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    let hmac_tag = compute_punch_hmac(hmac_key, device_id, b"HELLO_ACK", nonce);
    msg.extend_from_slice(&hmac_tag);
    msg
}

/// Parse an incoming punch message WITHOUT HMAC verification.
///
/// This is the backward-compatible parser for scenarios where the HMAC key
/// is not yet established (e.g., initial peer discovery). Use parse_message()
/// with HMAC verification in production.
pub fn parse_message_unauthenticated(data: &[u8]) -> Option<PunchMessage> {
    if data.len() < 5 {
        return None;
    }

    if data.starts_with(b"HELLO_ACK") && data.len() >= 19 {
        let hex_str = std::str::from_utf8(&data[9..19]).ok()?;
        let mut nonce = [0u8; 10];
        hex_decode(hex_str, &mut nonce)?;
        Some(PunchMessage::HelloAck { nonce })
    } else if data.starts_with(b"HELLO") && data.len() >= 15 {
        let hex_str = std::str::from_utf8(&data[5..15]).ok()?;
        let mut nonce = [0u8; 10];
        hex_decode(hex_str, &mut nonce)?;
        Some(PunchMessage::Hello { nonce })
    } else if data.starts_with(b"PONG") && data.len() >= 8 {
        let seq_bytes = &data[4..8];
        let seq = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
        Some(PunchMessage::Pong { seq })
    } else if data.starts_with(b"PING") && data.len() >= 8 {
        let seq_bytes = &data[4..8];
        let seq = u32::from_be_bytes([seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3]]);
        Some(PunchMessage::Ping { seq })
    } else {
        Some(PunchMessage::Data)
    }
}

// Backward-compatible wrappers (without HMAC — for use when HMAC is not available)
/// Build a HELLO packet without HMAC (15 bytes: "HELLO" + 10 hex chars).
/// Use build_hello_packet_with_hmac() in production.
pub fn build_hello_packet(nonce: &[u8; 10]) -> Vec<u8> {
    let mut msg = b"HELLO".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    msg
}

/// Build a HELLO_ACK packet without HMAC (19 bytes: "HELLO_ACK" + 10 hex chars).
/// Use build_hello_ack_packet_with_hmac() in production.
pub fn build_hello_ack_packet(nonce: &[u8; 10]) -> Vec<u8> {
    let mut msg = b"HELLO_ACK".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    msg
}

/// Compute HMAC-SHA256 for punch packet authentication.
///
/// HMAC covers: device_id (16B) || message_type || nonce (10B)
/// This binds each packet to a specific device, preventing cross-device replay.
fn compute_punch_hmac(
    hmac_key: &[u8],
    device_id: &[u8; 16],
    message_type: &[u8],
    nonce: &[u8; 10],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .expect("HMAC key should be valid");
    mac.update(device_id);
    mac.update(message_type);
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

/// Verify an HMAC tag on a received punch packet.
fn verify_punch_hmac(
    hmac_key: &[u8],
    device_id: &[u8; 16],
    message_type: &[u8],
    nonce: &[u8; 10],
    tag: &[u8],
) -> bool {
    let mut mac = match HmacSha256::new_from_slice(hmac_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(device_id);
    mac.update(message_type);
    mac.update(nonce);
    mac.verify_slice(tag).is_ok()
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

/// Hex encode bytes to ASCII.
fn hex_encode(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|b| {
            let high = (b >> 4) & 0x0F;
            let low = b & 0x0F;
            vec![hex_char(high), hex_char(low)]
        })
        .collect()
}

fn hex_char(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn hex_decode(hex: &str, out: &mut [u8]) -> Option<()> {
    if hex.len() != out.len() * 2 {
        return None;
    }
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_val(chunk[0])?;
        let low = hex_val(chunk[1])?;
        out[i] = (high << 4) | low;
    }
    Some(())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
