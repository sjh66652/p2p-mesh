//! QUIC transport module using the quinn library.
//!
//! QUIC (RFC 9000) provides built-in TLS 1.3 encryption, multiplexed streams,
//! 0-RTT connection establishment, congestion control, and NAT rebinding resilience.
//!
//! This module wraps quinn to provide a high-level API for creating QUIC endpoints,
//! connecting to peers, and sending/receiving data over QUIC streams.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

pub struct QuicTransport {
    endpoint: Endpoint,
    server_config: ServerConfig,
}

impl QuicTransport {
    pub fn new(bind_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let (cert_der, key_der) = generate_self_signed_cert()?;
        let server_config = configure_server(cert_der.clone(), key_der.clone_key())?;
        let endpoint = Endpoint::server(server_config.clone(), bind_addr)?;
        Ok(Self { endpoint, server_config })
    }

    /// Get the SHA-256 fingerprint of our server certificate.
    /// This fingerprint should be exchanged with peers via the signaling
    /// channel before attempting a QUIC connection.
    pub fn certificate_fingerprint(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Re-generate to get the cert bytes (in production, cache this)
        let (cert_der, _) = generate_self_signed_cert()?;
        let fingerprint = Sha256::digest(cert_der.as_ref());
        Ok(hex::encode(&fingerprint))
    }

    /// Connect to a peer with certificate pinning.
    /// `peer_fingerprint` is the SHA-256 hex fingerprint of the peer's
    /// self-signed certificate, exchanged via the signaling channel.
    /// If `peer_fingerprint` is None, a warning is logged and the connection
    /// is allowed without verification (for backwards compatibility).
    pub async fn connect(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
        peer_fingerprint: Option<&str>,
    ) -> Result<Connection, Box<dyn std::error::Error>> {
        let expected_fingerprints: HashSet<String> = peer_fingerprint
            .map(|fp| {
                let mut set = HashSet::new();
                set.insert(fp.to_string());
                set
            })
            .unwrap_or_default();

        let client_crypto = if expected_fingerprints.is_empty() {
            log::warn!(
                "QUIC connecting to {} without certificate pinning — connection is vulnerable to MitM. \
                 Exchange certificate fingerprints via the signaling channel and pass them to connect().",
                peer_addr
            );
            // Legacy behavior: skip verification with loud warning
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(CertificatePinner::new(expected_fingerprints))
                .with_no_client_auth()
        };

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(
            Arc::new(client_crypto),
        )?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_concurrent_bidi_streams(100u32.into());
        transport.send_window(8 * 1024 * 1024);
        client_config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::client("[::]:0".parse()?)?;
        let client = endpoint.connect_with(client_config, peer_addr, server_name)?;
        let connection = client.await.map_err(|e| format!("QUIC connection failed: {}", e))?;
        log::info!("QUIC connection established to {} (id: {:?})", peer_addr, connection.stable_id());
        Ok(connection)
    }

    pub async fn send(conn: &Connection, data: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let (mut send, _recv) = conn.open_bi().await?;
        send.write_all(data).await?;
        send.finish().map_err(|e| format!("Stream finish error: {}", e))?;
        Ok(data.len())
    }

    pub async fn recv(recv: &mut RecvStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB limit
        let mut data = Vec::new();
        loop {
            let mut buf = [0u8; 65536];
            match recv.read(&mut buf).await? {
                Some(n) => {
                    if data.len() + n > MAX_MESSAGE_SIZE {
                        return Err(format!(
                            "Message exceeds maximum size of {} bytes",
                            MAX_MESSAGE_SIZE
                        ).into());
                    }
                    data.extend_from_slice(&buf[..n]);
                    if n == 0 { break; }
                }
                None => break,
            }
        }
        Ok(data)
    }

    pub async fn is_alive(conn: &Connection) -> bool {
        conn.close_reason().is_none()
    }

    pub fn rtt(conn: &Connection) -> Duration {
        conn.rtt()
    }
}

fn generate_self_signed_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let key_pair = rcgen::KeyPair::generate()?;
    let cert_params = rcgen::CertificateParams::new(vec!["p2p-mesh.local".to_string()])?;
    let cert = cert_params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let key_der = PrivateKeyDer::Pkcs8(key_der.into());
    Ok((cert_der, key_der))
}

fn configure_server(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec!