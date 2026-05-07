//! UDP hole punching module with HELLO/ACK protocol.
//!
//! Implements the core P2P connection establishment flow:
//! 1. Both peers query STUN to discover their public addresses (candidates)
//! 2. Candidates are exchanged via signaling (control plane)
//! 3. Both peers send burst of HELLO packets to each candidate address
//! 4. First peer to receive HELLO sends back HELLO_ACK
//! 5. Connection is established and data can flow
//!
//! Protocol messages (wire format):
//!   HELLO       — "HELLO{nonce}"  (15 bytes: 5 + 10-byte hex nonce)
//!   HELLO_ACK   — "HELLO_ACK{nonce}" (19 bytes: 9 + 10-byte hex nonce)
//!   DATA        — raw encrypted payload (after connection established)
//!   PING        — "PING{seq}" (8 bytes: 4 + 4-byte seq)
//!   PONG        — "PONG{seq}" (8 bytes: 4 + 4-byte seq)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

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

    /// Generate a HELLO packet with our nonce.
    pub fn build_hello(&self) -> Vec<u8> {
        let mut msg = b"HELLO".to_vec();
        msg.extend_from_slice(&hex_encode(&self.our_nonce));
        msg
    }

    /// Generate a HELLO_ACK packet responding to a peer's nonce.
    pub fn build_hello_ack(&self, peer_nonce: &[u8; 10]) -> Vec<u8> {
        let mut msg = b"HELLO_ACK".to_vec();
        msg.extend_from_slice(&hex_encode(peer_nonce));
        msg
    }

    /// Parse an incoming packet to determine the protocol message type.
    pub fn parse_message(data: &[u8]) -> Option<PunchMessage> {
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

/// Execute the hole punching loop: send HELLO bursts to all peer candidates,
/// listen for HELLO_ACK, and respond to peer's HELLO with HELLO_ACK.
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

    let mut nonce = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hello_packet = build_hello_packet(&nonce);

    let start = Instant::now();
    let mut best_addr: Option<SocketAddr> = None;

    log::info!(
        "Starting hole punch to {} candidates for peer {}",
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

        // Send HELLO to all peer candidates
        for candidate in peer_candidates {
            if let Err(e) = socket.send_to(&hello_packet, candidate.addr).await {
                log::trace!("Punch send failed to {}: {}", candidate.addr, e);
            }
        }

        // Listen for incoming packets (non-blocking, short timeout)
        match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src_addr))) => {
                let data = &buf[..n];
                if let Some(msg) = HolePuncher::parse_message(data) {
                    match msg {
                        PunchMessage::Hello { nonce: peer_nonce } => {
                            // Peer is punching us — send back HELLO_ACK
                            log::info!("Received HELLO from {} (peer punching us)", src_addr);
                            let ack = build_hello_ack_packet(&peer_nonce);
                            let _ = socket.send_to(&ack, src_addr).await;
                            best_addr = Some(src_addr);
                            // Don't return yet — continue listening for our HELLO_ACK
                        }
                        PunchMessage::HelloAck { nonce: ack_nonce } => {
                            // Peer ACKed our HELLO — verify nonce
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
                            // Other message — might be data from an existing connection
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

/// Build a HELLO packet (15 bytes: "HELLO" + 10 hex chars).
pub fn build_hello_packet(nonce: &[u8; 10]) -> Vec<u8> {
    let mut msg = b"HELLO".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
    msg
}

/// Build a HELLO_ACK packet (19 bytes: "HELLO_ACK" + 10 hex chars).
pub fn build_hello_ack_packet(nonce: &[u8; 10]) -> Vec<u8> {
    let mut msg = b"HELLO_ACK".to_vec();
    msg.extend_from_slice(&hex_encode(nonce));
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
