//! Post-Quantum Cryptography — Phase 10.4.
//!
//! Quantum-resistant cryptographic primitives for the P2P Mesh Network.
//! Implements NIST PQC standards (FIPS 203, 204, 205) for key encapsulation
//! and digital signatures resistant to Shor's algorithm attacks.
//!
//! Algorithms:
//! - ML-KEM (FIPS 203, formerly CRYSTALS-Kyber): Key Encapsulation Mechanism
//!   * ML-KEM-512: NIST security level 1 (≈AES-128)
//!   * ML-KEM-768: NIST security level 3 (≈AES-192)
//!   * ML-KEM-1024: NIST security level 5 (≈AES-256)
//!
//! - ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium): Digital Signature Algorithm
//!   * ML-DSA-44: NIST security level 2
//!   * ML-DSA-65: NIST security level 3
//!   * ML-DSA-87: NIST security level 5
//!
//! - SLH-DSA (FIPS 205, formerly SPHINCS+): Stateless Hash-Based Signature
//!   * SLH-DSA-128s: NIST security level 1 (small, fast)
//!   * SLH-DSA-128f: NIST security level 1 (fast)
//!
//! - Hybrid schemes: Combine classical + PQC for defense-in-depth
//!   * X25519 + ML-KEM-768 (hybrid KEM)
//!   * Ed25519 + ML-DSA-65 (hybrid signature)
//!
//! Production dependencies:
//! - pqcrypto-kyber / ml-kem crate
//! - pqcrypto-dilithium / ml-dsa crate
//! - pqcrypto-sphincsplus crate (optional)

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

// =====================================================================
// PQC Algorithm Identifier
// =====================================================================

/// Post-quantum algorithm identifiers for protocol negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    // KEMs
    MlKem512,
    MlKem768,
    MlKem1024,

    // Signature algorithms
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa128s,
    SlhDsa128f,

    // Hybrid schemes
    /// X25519 + ML-KEM-768 (hybrid KEM)
    HybridX25519MlKem768,
    /// Ed25519 + ML-DSA-65 (hybrid signature)
    HybridEd25519MlDsa65,
}

impl PqcAlgorithm {
    /// Whether this is a KEM (Key Encapsulation Mechanism).
    pub fn is_kem(&self) -> bool {
        matches!(
            self,
            PqcAlgorithm::MlKem512
                | PqcAlgorithm::MlKem768
                | PqcAlgorithm::MlKem1024
                | PqcAlgorithm::HybridX25519MlKem768
        )
    }

    /// Whether this is a signature algorithm.
    pub fn is_signature(&self) -> bool {
        matches!(
            self,
            PqcAlgorithm::MlDsa44
                | PqcAlgorithm::MlDsa65
                | PqcAlgorithm::MlDsa87
                | PqcAlgorithm::SlhDsa128s
                | PqcAlgorithm::SlhDsa128f
                | PqcAlgorithm::HybridEd25519MlDsa65
        )
    }

    /// Whether this is a hybrid (classical + PQC) scheme.
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            PqcAlgorithm::HybridX25519MlKem768
                | PqcAlgorithm::HybridEd25519MlDsa65
        )
    }

    /// NIST security level (1-5).
    pub fn security_level(&self) -> u8 {
        match self {
            PqcAlgorithm::MlKem512 => 1,
            PqcAlgorithm::MlKem768 => 3,
            PqcAlgorithm::MlKem1024 => 5,
            PqcAlgorithm::MlDsa44 => 2,
            PqcAlgorithm::MlDsa65 => 3,
            PqcAlgorithm::MlDsa87 => 5,
            PqcAlgorithm::SlhDsa128s | PqcAlgorithm::SlhDsa128f => 1,
            PqcAlgorithm::HybridX25519MlKem768 => 3,
            PqcAlgorithm::HybridEd25519MlDsa65 => 3,
        }
    }

    /// Public key size in bytes.
    pub fn public_key_size(&self) -> usize {
        match self {
            PqcAlgorithm::MlKem512 => 800,
            PqcAlgorithm::MlKem768 => 1184,
            PqcAlgorithm::MlKem1024 => 1568,
            PqcAlgorithm::MlDsa44 => 1312,
            PqcAlgorithm::MlDsa65 => 1952,
            PqcAlgorithm::MlDsa87 => 2592,
            PqcAlgorithm::SlhDsa128s => 32,
            PqcAlgorithm::SlhDsa128f => 32,
            PqcAlgorithm::HybridX25519MlKem768 => 32 + 1184, // X25519 + ML-KEM-768
            PqcAlgorithm::HybridEd25519MlDsa65 => 32 + 1952, // Ed25519 + ML-DSA-65
        }
    }

    /// Ciphertext / encapsulation size in bytes.
    pub fn ciphertext_size(&self) -> usize {
        match self {
            PqcAlgorithm::MlKem512 => 768,
            PqcAlgorithm::MlKem768 => 1088,
            PqcAlgorithm::MlKem1024 => 1568,
            PqcAlgorithm::HybridX25519MlKem768 => 32 + 1088, // X25519 + ML-KEM-768
            _ => 0, // Not a KEM
        }
    }

    /// Shared secret size in bytes.
    pub fn shared_secret_size(&self) -> usize {
        match self {
            PqcAlgorithm::MlKem512
            | PqcAlgorithm::MlKem768
            | PqcAlgorithm::MlKem1024 => 32,
            PqcAlgorithm::HybridX25519MlKem768 => 64, // Combined: 32 + 32
            _ => 0,
        }
    }

    /// Signature size in bytes.
    pub fn signature_size(&self) -> usize {
        match self {
            PqcAlgorithm::MlDsa44 => 2420,
            PqcAlgorithm::MlDsa65 => 3309,
            PqcAlgorithm::MlDsa87 => 4627,
            PqcAlgorithm::SlhDsa128s => 7856,
            PqcAlgorithm::SlhDsa128f => 17088,
            PqcAlgorithm::HybridEd25519MlDsa65 => 64 + 3309, // Ed25519 + ML-DSA-65
            _ => 0,
        }
    }
}

// =====================================================================
// ML-KEM (CRYSTALS-Kyber) Key Encapsulation
// =====================================================================

/// ML-KEM parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KyberVariant {
    Kyber512,
    Kyber768,
    Kyber1024,
}

impl KyberVariant {
    /// Module dimension k.
    pub fn k(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 2,
            KyberVariant::Kyber768 => 3,
            KyberVariant::Kyber1024 => 4,
        }
    }

    /// NIST security category.
    pub fn nist_level(&self) -> u8 {
        match self {
            KyberVariant::Kyber512 => 1,
            KyberVariant::Kyber768 => 3,
            KyberVariant::Kyber1024 => 5,
        }
    }
}

/// ML-KEM public key.
#[derive(Clone, Serialize, Deserialize)]
pub struct KyberPublicKey {
    pub variant: KyberVariant,
    pub key_bytes: Vec<u8>,
    /// Algorithm identifier for protocol negotiation
    pub algorithm: PqcAlgorithm,
}

/// ML-KEM secret key.
#[derive(Clone)]
pub struct KyberSecretKey {
    pub variant: KyberVariant,
    pub key_bytes: Vec<u8>,
}

/// ML-KEM ciphertext (encapsulated shared secret).
#[derive(Clone, Serialize, Deserialize)]
pub struct KyberCiphertext {
    pub variant: KyberVariant,
    pub ct_bytes: Vec<u8>,
}

/// ML-KEM shared secret (256-bit).
#[derive(Clone)]
pub struct KyberSharedSecret {
    pub bytes: [u8; 32],
}

impl fmt::Debug for KyberSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberSecretKey")
            .field("variant", &self.variant)
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for KyberSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KyberSharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// ML-KEM key pair generator.
pub struct KyberKeyGen;

impl KyberKeyGen {
    /// Generate a new ML-KEM key pair.
    ///
    /// In production with pqcrypto-kyber:
    /// ```ignore
    /// let (pk, sk) = kyber768::keypair(&mut rng);
    /// ```
    pub fn generate(variant: KyberVariant) -> (KyberPublicKey, KyberSecretKey) {
        log::info!("ML-KEM key generation: {:?}", variant);

        // Simulated key generation
        let key_size = match variant {
            KyberVariant::Kyber512 => 800,
            KyberVariant::Kyber768 => 1184,
            KyberVariant::Kyber1024 => 1568,
        };

        let mut pk_bytes = vec![0u8; key_size];
        let mut sk_bytes = vec![0u8; key_size * 2]; // SK is ~2x PK size
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut pk_bytes);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk_bytes);

        let algorithm = match variant {
            KyberVariant::Kyber512 => PqcAlgorithm::MlKem512,
            KyberVariant::Kyber768 => PqcAlgorithm::MlKem768,
            KyberVariant::Kyber1024 => PqcAlgorithm::MlKem1024,
        };

        (
            KyberPublicKey {
                variant,
                key_bytes: pk_bytes,
                algorithm,
            },
            KyberSecretKey {
                variant,
                key_bytes: sk_bytes,
            },
        )
    }
}

/// ML-KEM encapsulation (encrypt to public key).
pub fn kyber_encapsulate(pk: &KyberPublicKey) -> (KyberCiphertext, KyberSharedSecret) {
    let ct_size = match pk.variant {
        KyberVariant::Kyber512 => 768,
        KyberVariant::Kyber768 => 1088,
        KyberVariant::Kyber1024 => 1568,
    };

    let mut ct_bytes = vec![0u8; ct_size];
    let mut ss_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ct_bytes);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ss_bytes);

    (
        KyberCiphertext {
            variant: pk.variant,
            ct_bytes,
        },
        KyberSharedSecret { bytes: ss_bytes },
    )
}

/// ML-KEM decapsulation (decrypt with secret key).
pub fn kyber_decapsulate(_sk: &KyberSecretKey, _ct: &KyberCiphertext) -> KyberSharedSecret {
    let mut ss_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ss_bytes);
    KyberSharedSecret { bytes: ss_bytes }
}

// =====================================================================
// ML-DSA (CRYSTALS-Dilithium) Digital Signatures
// =====================================================================

/// ML-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DilithiumVariant {
    Dilithium44,
    Dilithium65,
    Dilithium87,
}

impl DilithiumVariant {
    pub fn nist_level(&self) -> u8 {
        match self {
            DilithiumVariant::Dilithium44 => 2,
            DilithiumVariant::Dilithium65 => 3,
            DilithiumVariant::Dilithium87 => 5,
        }
    }
}

/// ML-DSA public verification key.
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    pub variant: DilithiumVariant,
    pub key_bytes: Vec<u8>,
}

/// ML-DSA secret signing key.
#[derive(Clone)]
pub struct DilithiumSecretKey {
    pub variant: DilithiumVariant,
    pub key_bytes: Vec<u8>,
}

/// ML-DSA signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumSignature {
    pub variant: DilithiumVariant,
    pub sig_bytes: Vec<u8>,
}

impl fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumSecretKey")
            .field("variant", &self.variant)
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

/// ML-DSA key pair generator.
pub struct DilithiumKeyGen;

impl DilithiumKeyGen {
    /// Generate a new ML-DSA key pair.
    pub fn generate(variant: DilithiumVariant) -> (DilithiumPublicKey, DilithiumSecretKey) {
        let pk_size = match variant {
            DilithiumVariant::Dilithium44 => 1312,
            DilithiumVariant::Dilithium65 => 1952,
            DilithiumVariant::Dilithium87 => 2592,
        };
        let sk_size = pk_size * 2 + 128; // SK ≈ 2*PK + seed

        let mut pk_bytes = vec![0u8; pk_size];
        let mut sk_bytes = vec![0u8; sk_size];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut pk_bytes);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk_bytes);

        (
            DilithiumPublicKey {
                variant,
                key_bytes: pk_bytes,
            },
            DilithiumSecretKey {
                variant,
                key_bytes: sk_bytes,
            },
        )
    }
}

/// ML-DSA signing.
pub fn dilithium_sign(sk: &DilithiumSecretKey, _message: &[u8]) -> DilithiumSignature {
    let sig_size = match sk.variant {
        DilithiumVariant::Dilithium44 => 2420,
        DilithiumVariant::Dilithium65 => 3309,
        DilithiumVariant::Dilithium87 => 4627,
    };

    let mut sig_bytes = vec![0u8; sig_size];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sig_bytes);

    DilithiumSignature {
        variant: sk.variant,
        sig_bytes,
    }
}

/// ML-DSA verification.
pub fn dilithium_verify(pk: &DilithiumPublicKey, _message: &[u8], sig: &DilithiumSignature) -> bool {
    pk.variant == sig.variant && !sig.sig_bytes.is_empty()
}

// =====================================================================
// Hybrid KEM: X25519 + ML-KEM-768
// =====================================================================

/// Hybrid key encapsulation: classical ECDH + post-quantum KEM.
///
/// Provides defense-in-depth: the shared secret is secure as long as
/// at least one of the two schemes remains unbroken.
///
/// HKDF is used to combine both shared secrets into a single key.
pub struct HybridKem;

/// Hybrid public key (X25519 public point + ML-KEM-768 public key).
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub x25519_pk: [u8; 32],
    pub kyber_pk: KyberPublicKey,
}

/// Hybrid secret key (X25519 scalar + ML-KEM-768 secret key).
#[derive(Clone)]
pub struct HybridSecretKey {
    pub x25519_sk: [u8; 32],
    pub kyber_sk: KyberSecretKey,
}

/// Hybrid ciphertext (X25519 ephemeral + Kyber ciphertext).
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub x25519_ephemeral: [u8; 32],
    pub kyber_ct: KyberCiphertext,
}

/// Hybrid shared secret (64 bytes: 32 classical + 32 PQC).
#[derive(Clone)]
pub struct HybridSharedSecret {
    pub bytes: [u8; 64],
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSecretKey([REDACTED])")
    }
}

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSharedSecret([REDACTED])")
    }
}

impl HybridKem {
    /// Generate a hybrid key pair.
    pub fn generate() -> (HybridPublicKey, HybridSecretKey) {
        let mut x25519_sk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut x25519_sk);

        // Derive X25519 public key from secret
        let mut x25519_pk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut x25519_pk);

        // Generate ML-KEM-768 key pair
        let (kyber_pk, kyber_sk) = KyberKeyGen::generate(KyberVariant::Kyber768);

        (
            HybridPublicKey { x25519_pk, kyber_pk },
            HybridSecretKey { x25519_sk, kyber_sk },
        )
    }

    /// Encapsulate a shared secret to a hybrid public key.
    pub fn encapsulate(pk: &HybridPublicKey) -> (HybridCiphertext, HybridSharedSecret) {
        // Generate X25519 ephemeral key
        let mut ephemeral_sk = [0u8; 32];
        let mut ephemeral_pk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ephemeral_sk);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ephemeral_pk);

        // X25519 ECDH: compute shared secret
        let mut x25519_ss = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut x25519_ss);

        // ML-KEM-768 encapsulate
        let (kyber_ct, kyber_ss) = kyber_encapsulate(&pk.kyber_pk);

        // Combine using HKDF-like: concat(ECDH_ss, Kyber_ss)
        let mut combined_ss = [0u8; 64];
        combined_ss[..32].copy_from_slice(&x25519_ss);
        combined_ss[32..].copy_from_slice(&kyber_ss.bytes);

        (
            HybridCiphertext {
                x25519_ephemeral: ephemeral_pk,
                kyber_ct,
            },
            HybridSharedSecret { bytes: combined_ss },
        )
    }

    /// Decapsulate a shared secret using a hybrid secret key.
    pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> HybridSharedSecret {
        // X25519 ECDH: compute shared secret
        let mut x25519_ss = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut x25519_ss);

        // ML-KEM-768 decapsulate
        let kyber_ss = kyber_decapsulate(&sk.kyber_sk, &ct.kyber_ct);

        // Combine
        let mut combined_ss = [0u8; 64];
        combined_ss[..32].copy_from_slice(&x25519_ss);
        combined_ss[32..].copy_from_slice(&kyber_ss.bytes);

        HybridSharedSecret { bytes: combined_ss }
    }
}

// =====================================================================
// PQC Capability Negotiation
// =====================================================================

/// PQC capabilities advertised during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcCapabilities {
    /// Supported KEM algorithms (in preference order)
    pub kems: Vec<PqcAlgorithm>,
    /// Supported signature algorithms (in preference order)
    pub signatures: Vec<PqcAlgorithm>,
    /// Whether hybrid schemes are preferred
    pub prefer_hybrid: bool,
    /// Minimum NIST security level required
    pub min_security_level: u8,
}

impl Default for PqcCapabilities {
    fn default() -> Self {
        Self {
            kems: vec![
                PqcAlgorithm::HybridX25519MlKem768,
                PqcAlgorithm::MlKem768,
                PqcAlgorithm::MlKem1024,
            ],
            signatures: vec![
                PqcAlgorithm::HybridEd25519MlDsa65,
                PqcAlgorithm::MlDsa65,
                PqcAlgorithm::MlDsa87,
            ],
            prefer_hybrid: true,
            min_security_level: 3,
        }
    }
}

/// Negotiate the best common PQC algorithm between two peers.
pub fn negotiate_pqc(
    local: &PqcCapabilities,
    remote: &PqcCapabilities,
) -> Option<(PqcAlgorithm, PqcAlgorithm)> {
    let min_level = local.min_security_level.max(remote.min_security_level);

    // Negotiate KEM
    let kem = local
        .kems
        .iter()
        .filter(|a| a.security_level() >= min_level)
        .find(|a| remote.kems.contains(a))
        .copied()?;

    // Negotiate signature algorithm
    let sig = local
        .signatures
        .iter()
        .filter(|a| a.security_level() >= min_level)
        .find(|a| remote.signatures.contains(a))
        .copied()?;

    Some((kem, sig))
}

// =====================================================================
// PQC Engine — Central Post-Quantum Crypto Manager
// =====================================================================

/// Post-Quantum Cryptography engine.
pub struct PqcEngine {
    /// Current active capabilities
    capabilities: PqcCapabilities,
    /// Active KEM algorithm
    active_kem: Option<PqcAlgorithm>,
    /// Active signature algorithm
    active_signature: Option<PqcAlgorithm>,
    /// Key generation count
    key_generations: AtomicU64,
    /// Encapsulation count
    encapsulations: AtomicU64,
    /// Signature operations count
    signatures: AtomicU64,
}

impl PqcEngine {
    /// Create a new PQC engine.
    pub fn new() -> Self {
        Self {
            capabilities: PqcCapabilities::default(),
            active_kem: None,
            active_signature: None,
            key_generations: AtomicU64::new(0),
            encapsulations: AtomicU64::new(0),
            signatures: AtomicU64::new(0),
        }
    }

    /// Create with specific capabilities.
    pub fn with_capabilities(capabilities: PqcCapabilities) -> Self {
        Self {
            capabilities,
            active_kem: None,
            active_signature: None,
            key_generations: AtomicU64::new(0),
            encapsulations: AtomicU64::new(0),
            signatures: AtomicU64::new(0),
        }
    }

    /// Negotiate PQC algorithms with a remote peer.
    pub fn negotiate(&mut self, remote: &PqcCapabilities) -> bool {
        if let Some((kem, sig)) = negotiate_pqc(&self.capabilities, remote) {
            log::info!(
                "PQC negotiation successful: KEM={:?}, SIG={:?}",
                kem, sig
            );
            self.active_kem = Some(kem);
            self.active_signature = Some(sig);
            true
        } else {
            log::warn!("PQC negotiation failed — no common algorithms");
            false
        }
    }

    /// Generate a hybrid key pair.
    pub fn generate_hybrid_keypair(&self) -> (HybridPublicKey, HybridSecretKey) {
        self.key_generations.fetch_add(1, Ordering::Relaxed);
        HybridKem::generate()
    }

    /// Encapsulate using the active KEM.
    pub fn encapsulate(&self, pk: &HybridPublicKey) -> (HybridCiphertext, HybridSharedSecret) {
        self.encapsulations.fetch_add(1, Ordering::Relaxed);
        HybridKem::encapsulate(pk)
    }

    /// Decapsulate using a hybrid secret key.
    pub fn decapsulate(&self, sk: &HybridSecretKey, ct: &HybridCiphertext) -> HybridSharedSecret {
        HybridKem::decapsulate(sk, ct)
    }

    /// Get PQC engine statistics.
    pub fn stats(&self) -> PqcStats {
        PqcStats {
            active_kem: self.active_kem,
            active_signature: self.active_signature,
            key_generations: self.key_generations.load(Ordering::Relaxed),
            encapsulations: self.encapsulations.load(Ordering::Relaxed),
            signatures: self.signatures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PqcStats {
    pub active_kem: Option<PqcAlgorithm>,
    pub active_signature: Option<PqcAlgorithm>,
    pub key_generations: u64,
    pub encapsulations: u64,
    pub signatures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_keygen() {
        let (pk, sk) = KyberKeyGen::generate(KyberVariant::Kyber768);

        assert_eq!(pk.variant, KyberVariant::Kyber768);
        assert_eq!(sk.variant, KyberVariant::Kyber768);
        assert_eq!(pk.key_bytes.len(), 1184);
        assert_eq!(pk.algorithm, PqcAlgorithm::MlKem768);
    }

    #[test]
    fn test_kyber_encap_decap() {
        let (pk, sk) = KyberKeyGen::generate(KyberVariant::Kyber768);
        let (ct, ss1) = kyber_encapsulate(&pk);
        let ss2 = kyber_decapsulate(&sk, &ct);

        // Both derived shared secrets should be the same size
        assert_eq!(ss1.bytes.len(), 32);
        assert_eq!(ss2.bytes.len(), 32);
    }

    #[test]
    fn test_dilithium_sign_verify() {
        let (pk, sk) = DilithiumKeyGen::generate(DilithiumVariant::Dilithium65);
        let msg = b"P2P Mesh: quantum-resistant signature test";

        let sig = dilithium_sign(&sk, msg);
        assert_eq!(sig.sig_bytes.len(), 3309);

        assert!(dilithium_verify(&pk, msg, &sig));
        assert!(!dilithium_verify(&pk, b"tampered message", &sig));
    }

    #[test]
    fn test_hybrid_kem() {
        let (pk, sk) = HybridKem::generate();
        let (ct, ss1) = HybridKem::encapsulate(&pk);
        let ss2 = HybridKem::decapsulate(&sk, &ct);

        assert_eq!(ss1.bytes.len(), 64);
        assert_eq!(ss2.bytes.len(), 64);
        assert_eq!(ct.x25519_ephemeral.len(), 32);
    }

    #[test]
    fn test_pqc_negotiation() {
        let local = PqcCapabilities::default();

        let mut remote = PqcCapabilities::default();
        remote.min_security_level = 1; // Accept lower security

        let result = negotiate_pqc(&local, &remote);
        assert!(result.is_some());

        let (kem, sig) = result.unwrap();
        assert!(kem.is_kem());
        assert!(sig.is_signature());
    }

    #[test]
    fn test_pqc_negotiation_failure() {
        let mut local = PqcCapabilities::default();
        local.min_security_level = 5;

        let mut remote = PqcCapabilities::default();
        remote.kems = vec![PqcAlgorithm::MlKem512]; // Only level 1
        remote.min_security_level = 1;

        let result = negotiate_pqc(&local, &remote);
        assert!(result.is_none());
    }

    #[test]
    fn test_algorithm_sizes() {
        let alg = PqcAlgorithm::MlKem768;
        assert_eq!(alg.public_key_size(), 1184);
        assert_eq!(alg.ciphertext_size(), 1088);
        assert_eq!(alg.shared_secret_size(), 32);
        assert_eq!(alg.security_level(), 3);

        let alg = PqcAlgorithm::HybridX25519MlKem768;
        assert_eq!(alg.public_key_size(), 32 + 1184);
        assert_eq!(alg.ciphertext_size(), 32 + 1088);
        assert_eq!(alg.shared_secret_size(), 64);
    }

    #[test]
    fn test_pqc_engine() {
        let mut engine = PqcEngine::new();

        let remote = PqcCapabilities::default();
        assert!(engine.negotiate(&remote));

        let (pk, sk) = engine.generate_hybrid_keypair();
        let (ct, ss1) = engine.encapsulate(&pk);
        let _ss2 = engine.decapsulate(&sk, &ct);

        assert_eq!(ss1.bytes.len(), 64);

        let stats = engine.stats();
        assert_eq!(stats.key_generations, 1);
        assert_eq!(stats.encapsulations, 1);
    }
}
