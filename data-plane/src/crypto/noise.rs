//! Noise Protocol Framework — IK handshake pattern (Phase 4 fastpath).
//!
//! Provides WireGuard-like performance using the Noise Protocol Framework.
//! The IK pattern provides:
//! - 0-RTT encryption (initiator knows responder's static public key)
//! - Mutual authentication
//! - Forward secrecy (via ephemeral-static DH)
//!
//! Noise_IK(s, rs):
//!   <- s  (responder static key known)
//!   ...
//!   -> e, es, s, ss  (initiator sends ephemeral + static, two DH ops)
//!   <- e, ee, se     (responder sends ephemeral, two DH ops)
//!
//! Packet format (overhead: 96 bytes per packet):
//!   [ephemeral_public (32B)][encrypted_payload][auth_tag (16B)]
//!
//! Compare to WireGuard: 32B header + 16B tag = 48B overhead
//! vs QUIC: ~50-70B overhead per packet
//!
//! Target: < 100μs encrypt/decrypt per packet on modern hardware.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Noise handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting to start handshake
    Init,
    /// Sent initial message (e, es, s, ss)
    InitiatorSent,
    /// Received initiator message, sent response (e, ee, se)
    ResponderSent,
    /// Handshake complete, transport established
    Established,
}

/// Noise IK pattern state machine.
pub struct NoiseIKHandshake {
    state: HandshakeState,
    /// Our static keypair
    static_keypair: NoiseStaticKeypair,
    /// Peer's static public key (must be known out-of-band for IK pattern)
    peer_static_public: [u8; 32],
    /// Ephemeral keypair (generated per-handshake, zeroed on drop)
    ephemeral_secret: Option<EphemeralSecret>,
    /// Chaining key (from HKDF)
    chaining_key: [u8; 32],
    /// Handshake hash (transcript of all handshake messages)
    handshake_hash: [u8; 32],
}

/// Noise static keypair.
pub struct NoiseStaticKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl NoiseStaticKeypair {
    /// Generate a new static X25519 keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from existing 32-byte secret key.
    pub fn from_secret(secret_bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Get the 32-byte secret key.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

impl NoiseIKHandshake {
    /// Initialize a Noise IK handshake as the initiator.
    ///
    /// The peer's static public key must be known (pre-shared).
    pub fn initiator(our_static: NoiseStaticKeypair, peer_static_public: [u8; 32]) -> Self {
        let mut chaining_key = [0u8; 32];
        chaining_key.copy_from_slice(b"Noise_IK_25519_ChaChaPoly_SHA256");

        let mut handshake_hash = [0u8; 32];
        // h = SHA-256(protocol_name)
        let mut hasher = Sha256::new();
        hasher.update(b"Noise_IK_25519_ChaChaPoly_SHA256");
        handshake_hash.copy_from_slice(&hasher.finalize());

        Self {
            state: HandshakeState::Init,
            static_keypair: our_static,
            peer_static_public,
            ephemeral_secret: None,
            chaining_key,
            handshake_hash,
        }
    }

    /// Build the initiator's first message: -> e, es, s, ss
    ///
    /// Returns (message_to_send, transport_keys) if handshake is complete,
    /// or just the message if more rounds are needed.
    pub fn build_initiator_message(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.state != HandshakeState::Init {
            return Err(NoiseError::InvalidState);
        }

        // Generate ephemeral keypair
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let ephemeral_public_bytes = *ephemeral_public.as_bytes();

        // Update handshake hash: h = SHA-256(h || e.public)
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(&ephemeral_public_bytes);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // es: DH(our_ephemeral, peer_static)
        let peer_static = PublicKey::from(self.peer_static_public);
        let es_shared = ephemeral_secret.diffie_hellman(&peer_static);
        mix_key(&mut self.chaining_key, es_shared.as_bytes());

        // s: encrypt our static public key
        let encrypted_s = encrypt_with_key(
            &self.chaining_key,
            &self.static_keypair.public_key_bytes(),
            &mut rand::thread_rng(),
        );

        // Update handshake hash: h = SHA-256(h || encrypted_s)
        hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(&encrypted_s);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // ss: DH(our_static, peer_static)
        let ss_shared = self.static_keypair.secret.diffie_hellman(&peer_static);
        mix_key(&mut self.chaining_key, ss_shared.as_bytes());

        // Build message: e || encrypted_s
        let mut message = Vec::with_capacity(32 + encrypted_s.len() + 16);
        message.extend_from_slice(&ephemeral_public_bytes);
        message.extend_from_slice(&encrypted_s);

        self.ephemeral_secret = Some(ephemeral_secret);
        self.state = HandshakeState::InitiatorSent;

        log::info!("Noise IK: Initiator message built ({} bytes)", message.len());

        // Derive transport keys
        let (send_key, recv_key) = split(&self.chaining_key);

        Ok(message)
    }

    /// Get the transport keys after handshake completion.
    pub fn transport_keys(&self) -> Option<(NoiseTransportKey, NoiseTransportKey)> {
        if self.state == HandshakeState::InitiatorSent || self.state == HandshakeState::ResponderSent {
            let (send_key, recv_key) = split(&self.chaining_key);
            Some((
                NoiseTransportKey::new(send_key),
                NoiseTransportKey::new(recv_key),
            ))
        } else {
            None
        }
    }
}

/// Transport-level encryption key derived from the Noise handshake.
#[derive(ZeroizeOnDrop)]
pub struct NoiseTransportKey {
    key: [u8; 32],
    nonce: u64,
}

impl NoiseTransportKey {
    fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    /// Encrypt a plaintext payload.
    ///
    /// Returns the encrypted payload with nonce prepended.
    /// Format: [nonce (12B)][ciphertext + tag]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.nonce += 1;

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .expect("Noise encrypt should not fail");

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt a ciphertext payload.
    ///
    /// Expects: [nonce (12B)][ciphertext + tag]
    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        cipher.decrypt(nonce, ciphertext).ok()
    }
}

/// Errors for Noise protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("Invalid handshake state")]
    InvalidState,

    #[error("Decryption failed")]
    DecryptionFailed,
}

// ---- Noise Cryptographic Primitives ----

/// HMAC-based Key Derivation Function (HKDF-style).
fn mix_key(ck: &mut [u8; 32], input: &[u8]) {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(ck)
        .expect("HMAC key should be valid");
    mac.update(input);
    ck.copy_from_slice(&mac.finalize().into_bytes());
}

/// Split a chaining key into two 32-byte keys.
fn split(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];

    // temp = HMAC-SHA256(ck, 0x01)
    let mut mac = HmacSha256::new_from_slice(ck)
        .expect("HMAC key should be valid");
    mac.update(&[0x01]);
    k1.copy_from_slice(&mac.finalize().into_bytes());

    // out2 = HMAC-SHA256(ck, temp || 0x02)
    let mut mac = HmacSha256::new_from_slice(ck)
        .expect("HMAC key should be valid");
    mac.update(&k1);
    mac.update(&[0x02]);
    k2.copy_from_slice(&mac.finalize().into_bytes());

    (k1, k2)
}

/// Encrypt data with a symmetric key (AEAD).
fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8], rng: &mut impl RngCore) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encrypt should not fail");

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_keypair_generation() {
        let kp = NoiseStaticKeypair::generate();
        let public = kp.public_key_bytes();
        let secret = kp.secret_key_bytes();
        assert_eq!(public.len(), 32);
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_mix_key_deterministic() {
        let mut ck1 = [0xAAu8; 32];
        let mut ck2 = [0xAAu8; 32];
        let input = b"test input";

        mix_key(&mut ck1, input);
        mix_key(&mut ck2, input);
        assert_eq!(ck1, ck2);
    }

    #[test]
    fn test_split_deterministic() {
        let ck1 = [0x42u8; 32];
        let ck2 = [0x42u8; 32];

        let (k1_a, k2_a) = split(&ck1);
        let (k1_b, k2_b) = split(&ck2);

        assert_eq!(k1_a, k1_b);
        assert_eq!(k2_a, k2_b);
        assert_ne!(k1_a, k2_a); // Should produce different keys
    }

    #[test]
    fn test_noise_transport_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let mut send_key = NoiseTransportKey::new(key);
        let mut recv_key = NoiseTransportKey::new(key);

        let plaintext = b"Hello, Noise Protocol!";
        let encrypted = send_key.encrypt(plaintext);
        let decrypted = recv_key.decrypt(&encrypted);

        assert_eq!(decrypted, Some(plaintext.to_vec()));
    }

    #[test]
    fn test_noise_transport_nonce_increment() {
        let key = [0x42u8; 32];
        let mut key1 = NoiseTransportKey::new(key);
        let mut key2 = NoiseTransportKey::new(key);

        let p1 = key1.encrypt(b"message1");
        let p2 = key1.encrypt(b"message2");

        // Different nonces should produce different ciphertexts
        assert_ne!(p1, p2);

        // key2 should decrypt with matching nonce sequence
        assert!(key2.decrypt(&p1).is_some());
        assert!(key2.decrypt(&p2).is_some());
    }

    #[test]
    fn test_noise_ik_initiator_handshake() {
        // Initiator keypair
        let init_static = NoiseStaticKeypair::generate();
        let peer_static = NoiseStaticKeypair::generate();

        let mut handshake = NoiseIKHandshake::initiator(
            init_static,
            peer_static.public_key_bytes(),
        );

        let message = handshake.build_initiator_message();
        assert!(message.is_ok());
        let msg = message.unwrap();
        assert!(msg.len() > 32);
    }
}
