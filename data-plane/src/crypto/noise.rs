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
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, EphemeralSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Noise handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
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
#[derive(ZeroizeOnDrop)]
pub struct NoiseIKHandshake {
    state: HandshakeState,
    /// Our static keypair
    static_keypair: NoiseStaticKeypair,
    /// Peer's static public key (must be known out-of-band for IK pattern)
    peer_static_public: [u8; 32],
    /// Our ephemeral keypair (generated per-handshake, zeroed on drop).
    /// On initiator side: stores the initiator's ephemeral secret for ee/se DH.
    /// On responder side: stores the responder's ephemeral secret after generation.
    /// Uses EphemeralSecret (not EphemeralSecret) because the same secret must
    /// be used for multiple diffie_hellman calls (es then later ee/se).
    ephemeral_secret: Option<EphemeralSecret>,
    /// Peer's ephemeral public key (set during handshake processing).
    /// Used for DH operations against the remote party's ephemeral key.
    peer_ephemeral_public: [u8; 32],
    /// Chaining key (from HKDF)
    chaining_key: [u8; 32],
    /// Handshake hash (transcript of all handshake messages)
    handshake_hash: [u8; 32],
}

/// Noise static keypair.
pub struct NoiseStaticKeypair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl Zeroize for NoiseStaticKeypair {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        // PublicKey doesn't contain sensitive material, but zero it for hygiene
        // PublicKey doesn't implement Zeroize, so we zero the underlying bytes
        let bytes = self.public.as_bytes();
        // We can't zeroize PublicKey directly since it doesn't implement Zeroize
        // Instead, just drop and recreate — sensitive material is in the secret only
        let _ = bytes; // PublicKey is public by definition, no need to zeroize
    }
}

impl NoiseStaticKeypair {
    /// Generate a new static X25519 keypair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from existing 32-byte secret key.
    pub fn from_secret(secret_bytes: &[u8; 32]) -> Self {
        let secret = EphemeralSecret::from(*secret_bytes);
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
            peer_ephemeral_public: [0u8; 32],
            chaining_key,
            handshake_hash,
        }
    }

    /// Build the initiator's first message: -> e, es, s, ss
    ///
    /// Returns the message to send. After calling this, the initiator should
    /// wait for the responder's reply and call `process_responder_message`.
    pub fn build_initiator_message(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.state != HandshakeState::Init {
            return Err(NoiseError::InvalidState);
        }

        // Generate ephemeral keypair using EphemeralSecret so the same secret
        // can be used for es DH now and ee/se DH later in process_responder_message.
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let ephemeral_public_bytes = *ephemeral_public.as_bytes();

        // Save before using: ephem must live for ee/se in process_responder_message
        self.ephemeral_secret = Some(ephemeral_secret);

        // Update handshake hash: h = SHA-256(h || e.public)
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(&ephemeral_public_bytes);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // es: DH(our_ephemeral, peer_static)
        let peer_static = PublicKey::from(self.peer_static_public);
        let es_shared = self.ephemeral_secret.as_ref().unwrap().diffie_hellman(&peer_static);
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
        let mut message = Vec::with_capacity(32 + encrypted_s.len());
        message.extend_from_slice(&ephemeral_public_bytes);
        message.extend_from_slice(&encrypted_s);

        self.state = HandshakeState::InitiatorSent;

        log::info!("Noise IK: Initiator message built ({} bytes)", message.len());
        Ok(message)
    }

    /// Process the responder's reply: <- e, ee, se
    ///
    /// Takes the raw response (responder's ephemeral public key, 32 bytes)
    /// and completes the handshake, transitioning to Established.
    /// Returns the transport (send, recv) keys.
    pub fn process_responder_message(
        &mut self,
        response: &[u8],
    ) -> Result<(NoiseTransportKey, NoiseTransportKey), NoiseError> {
        if self.state != HandshakeState::InitiatorSent {
            return Err(NoiseError::InvalidState);
        }
        if response.len() < 32 {
            return Err(NoiseError::InvalidState);
        }

        let ephem = self.ephemeral_secret.as_ref()
            .ok_or(NoiseError::InvalidState)?;

        // Parse responder's ephemeral public key
        let mut resp_ephemeral_bytes = [0u8; 32];
        resp_ephemeral_bytes.copy_from_slice(&response[..32]);
        let resp_ephemeral = PublicKey::from(resp_ephemeral_bytes);

        // Update handshake hash: h = SHA-256(h || e.public)
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(&resp_ephemeral_bytes);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // ee: DH(our_ephemeral, responder_ephemeral) — provides forward secrecy
        let ee_shared = ephem.diffie_hellman(&resp_ephemeral);
        mix_key(&mut self.chaining_key, ee_shared.as_bytes());

        // se: DH(our_static, responder_ephemeral)
        let se_shared = self.static_keypair.secret.diffie_hellman(&resp_ephemeral);
        mix_key(&mut self.chaining_key, se_shared.as_bytes());

        self.state = HandshakeState::Established;

        let (send_key, recv_key) = split(&self.chaining_key);
        log::info!("Noise IK: Handshake established (initiator)");
        Ok((
            NoiseTransportKey::new(send_key),
            NoiseTransportKey::new(recv_key),
        ))
    }

    /// Initialize a Noise IK handshake as the responder.
    ///
    /// The initiator's static public key is not known until the first
    /// message is processed via `process_initiator_message`.
    pub fn responder(our_static: NoiseStaticKeypair) -> Self {
        let mut chaining_key = [0u8; 32];
        chaining_key.copy_from_slice(b"Noise_IK_25519_ChaChaPoly_SHA256");

        let mut handshake_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"Noise_IK_25519_ChaChaPoly_SHA256");
        handshake_hash.copy_from_slice(&hasher.finalize());

        Self {
            state: HandshakeState::Init,
            static_keypair: our_static,
            peer_static_public: [0u8; 32], // unknown until initiator message
            ephemeral_secret: None,
            peer_ephemeral_public: [0u8; 32],
            chaining_key,
            handshake_hash,
        }
    }

    /// Process the initiator's first message: -> e, es, s, ss
    ///
    /// Decrypts and stores the initiator's static public key, derives the
    /// shared secrets, and returns the initiator's static public key bytes.
    pub fn process_initiator_message(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; 32], NoiseError> {
        if self.state != HandshakeState::Init {
            return Err(NoiseError::InvalidState);
        }
        if message.len() < 32 + 12 + 16 {
            return Err(NoiseError::InvalidState);
        }

        // Parse initiator's ephemeral public key (first 32 bytes)
        let mut init_ephemeral_bytes = [0u8; 32];
        init_ephemeral_bytes.copy_from_slice(&message[..32]);
        let init_ephemeral = PublicKey::from(init_ephemeral_bytes);

        // Update handshake hash: h = SHA-256(h || e.public)
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(&init_ephemeral_bytes);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // es: DH(our_static, initiator_ephemeral)
        let es_shared = self.static_keypair.secret.diffie_hellman(&init_ephemeral);
        mix_key(&mut self.chaining_key, es_shared.as_bytes());

        // Store initiator's ephemeral public for later ee/se DH
        self.peer_ephemeral_public = init_ephemeral_bytes;

        // The remainder is the encrypted initiator static public key
        let encrypted_s = &message[32..];

        // Update handshake hash: h = SHA-256(h || encrypted_s)
        hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(encrypted_s);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // s: decrypt initiator's static public key
        let init_static_bytes = decrypt_with_key(
            &self.chaining_key,
            encrypted_s,
        ).ok_or(NoiseError::DecryptionFailed)?;

        let mut init_static_pub = [0u8; 32];
        if init_static_bytes.len() != 32 {
            return Err(NoiseError::DecryptionFailed);
        }
        init_static_pub.copy_from_slice(&init_static_bytes);
        self.peer_static_public = init_static_pub;

        let init_static = PublicKey::from(init_static_pub);

        // ss: DH(our_static, initiator_static)
        let ss_shared = self.static_keypair.secret.diffie_hellman(&init_static);
        mix_key(&mut self.chaining_key, ss_shared.as_bytes());

        self.state = HandshakeState::ResponderSent;

        log::info!("Noise IK: Initiator message processed, initiator static key decrypted");
        Ok(init_static_pub)
    }

    /// Build the responder's reply: <- e, ee, se
    ///
    /// Call after `process_initiator_message`. Returns the message to send
    /// and the transport keys.
    pub fn build_responder_message(
        &mut self,
    ) -> Result<(Vec<u8>, NoiseTransportKey, NoiseTransportKey), NoiseError> {
        if self.state != HandshakeState::ResponderSent {
            return Err(NoiseError::InvalidState);
        }

        // Reconstruct initiator's ephemeral public key
        let init_ephemeral = PublicKey::from(self.peer_ephemeral_public);

        // Generate responder's ephemeral keypair using EphemeralSecret so
        // the same secret can be used in multiple diffie_hellman calls if needed.
        let resp_ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let resp_ephemeral_public = PublicKey::from(&resp_ephemeral_secret);
        let resp_ephemeral_bytes = *resp_ephemeral_public.as_bytes();

        // Update handshake hash: h = SHA-256(h || e.public)
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(&resp_ephemeral_bytes);
        self.handshake_hash.copy_from_slice(&hasher.finalize());

        // ee: DH(our_ephemeral, initiator_ephemeral) — forward secrecy
        let ee_shared = resp_ephemeral_secret.diffie_hellman(&init_ephemeral);
        mix_key(&mut self.chaining_key, ee_shared.as_bytes());

        // se: DH(our_static, initiator_ephemeral) — forward secrecy component
        let se_shared = self.static_keypair.secret.diffie_hellman(&init_ephemeral);
        mix_key(&mut self.chaining_key, se_shared.as_bytes());

        self.state = HandshakeState::Established;

        let (send_key, recv_key) = split(&self.chaining_key);

        log::info!("Noise IK: Handshake established (responder)");
        Ok((
            resp_ephemeral_bytes.to_vec(),
            NoiseTransportKey::new(send_key),
            NoiseTransportKey::new(recv_key),
        ))
    }

    /// Get the transport keys after handshake completion.
    /// Only returns keys when the handshake is fully established,
    /// ensuring forward secrecy from both `ee` and `se` exchanges.
    pub fn transport_keys(&self) -> Option<(NoiseTransportKey, NoiseTransportKey)> {
        if self.state == HandshakeState::Established {
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
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.nonce += 1;

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| NoiseError::EncryptionFailed)?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
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

    #[error("Encryption failed")]
    EncryptionFailed,
}

// ---- Noise Cryptographic Primitives ----

/// HMAC-based Key Derivation Function (HKDF-style).
fn mix_key(ck: &mut [u8; 32], input: &[u8]) {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    // HMAC-SHA256 accepts any key length, so new_from_slice on a [u8; 32]
    // is guaranteed to succeed. The fallback here is a defensive measure only.
    match <HmacSha256 as hmac::Mac>::new_from_slice(ck) {
        Ok(mut mac) => {
            mac.update(input);
            ck.copy_from_slice(&mac.finalize().into_bytes());
        }
        Err(e) => {
            // This should never happen — HMAC-SHA256 accepts any key length.
            log::error!("mix_key: HMAC initialization failed (impossible): {}", e);
        }
    }
}

/// Split a chaining key into two 32-byte keys.
fn split(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];

    // HMAC-SHA256 accepts any key length, so new_from_slice on a [u8; 32]
    // is guaranteed to succeed. Log and return zero keys as safety net.
    match <HmacSha256 as hmac::Mac>::new_from_slice(ck) {
        Ok(mut mac) => {
            // temp = HMAC-SHA256(ck, 0x01)
            mac.update(&[0x01]);
            k1.copy_from_slice(&mac.finalize().into_bytes());
        }
        Err(e) => {
            log::error!("split(k1): HMAC initialization failed (impossible): {}", e);
        }
    }

    match <HmacSha256 as hmac::Mac>::new_from_slice(ck) {
        Ok(mut mac) => {
            // out2 = HMAC-SHA256(ck, temp || 0x02)
            mac.update(&k1);
            mac.update(&[0x02]);
            k2.copy_from_slice(&mac.finalize().into_bytes());
        }
        Err(e) => {
            log::error!("split(k2): HMAC initialization failed (impossible): {}", e);
        }
    }

    (k1, k2)
}

/// Encrypt data with a symmetric key (AEAD).
/// Panics: ChaCha20-Poly1305 encryption only fails on incorrect nonce length,
/// which is always 12 bytes here. This is an internal helper used during
/// handshake only — panic is acceptable as it indicates a programming error.
fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8], rng: &mut impl RngCore) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("encrypt_with_key: ChaCha20-Poly1305 encrypt must not fail with valid 12-byte nonce");

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt data with a symmetric key (AEAD).
/// Expects format: [nonce (12B)][ciphertext + tag].
fn decrypt_with_key(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 + 16 {
        return None;
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, ciphertext).ok()
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
        let encrypted = send_key.encrypt(plaintext).unwrap();
        let decrypted = recv_key.decrypt(&encrypted);

        assert_eq!(decrypted, Some(plaintext.to_vec()));
    }

    #[test]
    fn test_noise_transport_nonce_increment() {
        let key = [0x42u8; 32];
        let mut key1 = NoiseTransportKey::new(key);
        let mut key2 = NoiseTransportKey::new(key);

        let p1 = key1.encrypt(b"message1").unwrap();
        let p2 = key1.encrypt(b"message2").unwrap();

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

    #[test]
    fn test_noise_ik_full_handshake() {
        let init_static = NoiseStaticKeypair::generate();
        let resp_static = NoiseStaticKeypair::generate();

        // Initator side
        let mut initiator = NoiseIKHandshake::initiator(
            init_static,
            resp_static.public_key_bytes(),
        );

        let init_msg = initiator.build_initiator_message().unwrap();
        assert_eq!(initiator.state, HandshakeState::InitiatorSent);

        // Responder side
        let mut responder = NoiseIKHandshake::responder(resp_static);
        let init_static_decrypted = responder.process_initiator_message(&init_msg).unwrap();

        assert_eq!(init_static_decrypted.len(), 32);
        assert_eq!(responder.state, HandshakeState::ResponderSent);

        let (resp_msg, mut resp_send, mut resp_recv) = responder.build_responder_message().unwrap();
        assert_eq!(responder.state, HandshakeState::Established);

        // Initator processes response
        let (mut init_send, mut init_recv) = initiator.process_responder_message(&resp_msg).unwrap();
        assert_eq!(initiator.state, HandshakeState::Established);

        // Verify bidirectional encryption works
        let plaintext = b"Hello, Noise IK!";
        let encrypted_a = init_send.encrypt(plaintext).unwrap();
        let decrypted_b = resp_recv.decrypt(&encrypted_a);
        assert_eq!(decrypted_b, Some(plaintext.to_vec()));

        let reply = b"Hello back!";
        let encrypted_b = resp_send.encrypt(reply).unwrap();
        let decrypted_a = init_recv.decrypt(&encrypted_b);
        assert_eq!(decrypted_a, Some(reply.to_vec()));
    }
}
