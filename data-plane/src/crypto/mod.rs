//! Encryption module for the P2P mesh data plane.
//!
//! Uses ChaCha20-Poly1305 (AEAD) for authenticated encryption of all
//! data plane traffic. The control plane never decrypts data plane
//! traffic — enforcing a zero-trust architecture.
//!
//! Key exchange is performed out-of-band through the control plane's
//! signaling service (WebSocket). This module handles symmetric
//! encryption once keys are established.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
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
}

/// Encrypt a plaintext payload using ChaCha20-Poly1305.
///
/// Returns the ciphertext prefixed with the 12-byte nonce.
/// Format: [nonce (12 bytes)][ciphertext + tag]
pub fn encrypt(key: &SessionKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("Encryption failed");

    // Prepend nonce for the recipient
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt a ChaCha20-Poly1305 ciphertext (nonce-prefixed format).
///
/// Expects: [nonce (12 bytes)][ciphertext + tag]
/// Returns the plaintext on success, or None if decryption/verification fails.
pub fn decrypt(key: &SessionKey, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None; // Too short to contain a nonce
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.key));

    cipher.decrypt(nonce, ciphertext).ok()
}

/// Generate a key fingerprint for logging/debugging (first 8 hex chars of SHA-256).
pub fn key_fingerprint(key: &SessionKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&key.key);
    let hash = hasher.finalize();
    hex::encode(&hash[..4])
}

/// Simple hex encoding (avoiding external dependency for just this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SessionKey::generate();
        let plaintext = b"Hello, P2P Mesh Network!";

        let encrypted = encrypt(&key, plaintext);
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt(&key, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = SessionKey::generate();
        let plaintext = b"Sensitive data";
        let mut encrypted = encrypt(&key, plaintext);

        // Tamper with the ciphertext
        if encrypted.len() > 13 {
            encrypted[13] ^= 0xFF;
        }

        assert!(decrypt(&key, &encrypted).is_none());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let secret = b"shared-secret-12345";
        let salt = b"salt-67890";

        let key1 = SessionKey::derive(secret, salt);
        let key2 = SessionKey::derive(secret, salt);

        assert_eq!(key1.key, key2.key);
    }
}
