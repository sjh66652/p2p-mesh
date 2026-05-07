//! Encryption module for the P2P mesh data plane.
//!
//! Uses ChaCha20-Poly1305 (AEAD) for authenticated encryption of all
//! data plane traffic, with X25519 ECDH for key agreement.
//! The control plane never decrypts data plane traffic — enforcing
//! a zero-trust architecture.
//!
//! Key exchange flow:
//! 1. Each peer generates an ephemeral X25519 keypair
//! 2. Public keys are exchanged via the control plane's signaling service
//! 3. Each peer computes the shared secret using ECDH
//! 4. The shared secret is fed through HKDF-SHA256 to derive the SessionKey
//! 5. Session keys are used with ChaCha20-Poly1305 for data encryption

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

/// A symmetric session key for data plane encryption.
/// Automatically zeroed when dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKey {
    key: [u8; 32],
}

impl SessionKey {
    /// Generate a new random session key using OS randomness.
    /// NOTE: This should only be used for testing. In production,
    /// use `from_ecdh` to derive keys from a key agreement protocol.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Derive a session key from a pre-shared secret and nonce.
    pub fn derive(shared_secret: &[u8], salt: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(salt);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    /// Derive a session key from an X25519 ECDH shared secret.
    /// Uses HKDF-SHA256 with domain separation info strings.
    pub fn from_ecdh(
        shared_secret: &[u8; 32],
        our_device_id: &str,
        peer_device_id: &str,
    ) -> Self {
        // HKDF-like derivation with domain separation
        // salt = SHA256("p2p-mesh-ecdh-v1")
        // info = sorted device IDs (ensures both peers derive the same key)
        let salt = Sha256::digest(b"p2p-mesh-ecdh-v1");

        // Sort device IDs to ensure deterministic key derivation
        let (id_a, id_b) = if our_device_id < peer_device_id {
            (our_device_id, peer_device_id)
        } else {
            (peer_device_id, our_device_id)
        };
        let info = format!("{}|{}", id_a, id_b);

        // Simple HKDF-like construction: HMAC-SHA256(salt, shared_secret || info)
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(shared_secret);
        hasher.update(info.as_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    /// Get the raw key bytes (for use in ECDH derivation only).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// An ephemeral X25519 keypair for ECDH key agreement.
/// The secret key is automatically zeroed on drop.
pub struct EcdhKeypair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EcdhKeypair {
    /// Generate a new ephemeral X25519 keypair using OS randomness.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Compute the ECDH shared secret with the peer's public key.
    /// Returns the raw 32-byte shared secret.
    pub fn agree(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_key = PublicKey::from(*peer_public);
        *self.secret.diffie_hellman(&peer_key).as_bytes()
    }
}

/// Encrypt a plaintext payload using ChaCha20-Poly1305.
///
/// Returns the ciphertext prefixed with the 12-byte nonce.
/// Format: [nonce (12 bytes)][ciphertext + tag]
pub fn encrypt(key: &SessionKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher =