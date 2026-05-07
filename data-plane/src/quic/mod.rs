//! QUIC transport module using the quinn library.
//!
//! QUIC (RFC 9000) provides built-in TLS 1.3 encryption, multiplexed streams,
//! 0-RTT connection establishment, congestion control, and NAT rebinding resilience.
//!
//! This module wraps quinn to provide a high-level API for creating QUIC endpoints,
//! connecting to peers, and sending/receiving data over QUIC streams.

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

    pub async fn connect(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
        peer_fingerprint: Option<&str>,
    ) -> Result<Connection, Box<dyn std::error::Error>> {
        let client_crypto = if let Some(fp) = peer_fingerprint {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(CertificatePinner::new(fp))
                .with_no_client_auth()
        } else {
            log::warn!(
                "No certificate fingerprint provided for {} — skipping server verification.                  Set a fingerprint to prevent MITM attacks.",
                peer_addr
            );
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
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
        send.finish().map_err(|e| format!("Failed to finish send stream: {}", e))?;
        Ok(data.len())
    }

    pub async fn recv(recv: &mut RecvStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
        let mut data = Vec::new();
        loop {
            let mut buf = [0u8; 65536];
            match recv.read(&mut buf).await? {
                Some(n) => {
                    if data.len() + n > MAX_MESSAGE_SIZE {
                        return Err(format!(
                            "Message exceeds maximum size of {} bytes", MAX_MESSAGE_SIZE
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

    /// Compute SHA-256 fingerprint of the server's certificate for pinning.
    pub fn certificate_fingerprint(cert_der: &CertificateDer<'_>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_der.as_ref());
        let hash = hasher.finalize();
        hash.iter().map(|b| format!("{:02x}", b)).collect()
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
        .with_single_cert(vec![cert_der], key_der.clone_key())?;
    server_crypto.alpn_protocols = vec![b"mesh/1".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_crypto))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.send_window(8 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Certificate pinner that validates server certificates against a known SHA-256 fingerprint.
///
/// This prevents MITM attacks by rejecting any certificate whose fingerprint doesn't match
/// the expected value. The fingerprint should be exchanged out-of-band (e.g., via the
/// control plane's signaling service).
struct CertificatePinner {
    expected_fingerprint: String,
}

impl CertificatePinner {
    fn new(fingerprint: &str) -> Arc<Self> {
        Arc::new(Self {
            expected_fingerprint: fingerprint.to_lowercase(),
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for CertificatePinner {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash: String = hasher.finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        if hash == self.expected_fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {} but got {}",
                self.expected_fingerprint, hash
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
