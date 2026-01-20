//! TFHE LWE-based PRE backend (post-quantum, fast)
//!
//! This backend uses TFHE's key switching mechanism for proxy recryption.
//! Expected to be 10-100x faster than OpenFHE BFV backend.
//!
//! # v1 Limitations
//!
//! This v1 implementation uses symmetric key switching key (KSK) generation,
//! which requires both secrets for recrypt key generation. The `to_public`
//! parameter in `generate_recrypt_key` is interpreted as serialized secret key
//! bytes (a workaround for the v1 limitation).
//!
//! Phase 3 will implement asymmetric KSK generation using only Alice's
//! secret + Bob's public key.

use crate::error::{PreError, PreResult};
use crate::pre::{BackendId, Ciphertext, KeyPair, PreBackend, PublicKey, RecryptKey, SecretKey};
use zeroize::Zeroizing;

/// TFHE LWE-based PRE backend
pub struct TfheBackend {
    #[cfg(feature = "tfhe")]
    params: recrypt_tfhe::TfheParams,
    #[cfg(not(feature = "tfhe"))]
    _marker: std::marker::PhantomData<()>,
}

impl TfheBackend {
    /// Create a new TFHE backend with default 128-bit security parameters
    #[cfg(feature = "tfhe")]
    pub fn new() -> PreResult<Self> {
        Ok(Self {
            params: recrypt_tfhe::TfheParams::default_128bit(),
        })
    }

    /// Create a new TFHE backend (feature not enabled)
    #[cfg(not(feature = "tfhe"))]
    pub fn new() -> PreResult<Self> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled. Build with --features tfhe".into(),
        ))
    }

    /// Check if TFHE backend is available
    pub fn is_available() -> bool {
        cfg!(feature = "tfhe")
    }
}

#[cfg(feature = "tfhe")]
impl PreBackend for TfheBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Tfhe
    }

    fn name(&self) -> &'static str {
        "TFHE LWE PRE (Post-Quantum, Fast)"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let tfhe_sk = recrypt_tfhe::TfheSecretKey::generate(&self.params);
        let sk_bytes = tfhe_sk.to_bytes();

        // v1: no separate public key, use empty bytes
        // In v1, encryption requires secret key (symmetric encryption)
        Ok(KeyPair {
            public: PublicKey::new(BackendId::Tfhe, vec![]),
            secret: SecretKey::new(BackendId::Tfhe, sk_bytes),
        })
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        // v1: no public key derivation, return empty
        Ok(PublicKey::new(BackendId::Tfhe, vec![]))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        // v1 workaround: `to_public` actually contains Bob's secret key bytes
        // This is a limitation of v1 symmetric KSK generation
        //
        // In production (Phase 3), this will use actual public key bytes

        let from_tfhe_sk = recrypt_tfhe::TfheSecretKey::from_bytes(from_secret.as_bytes())
            .map_err(|e| PreError::InvalidKey(format!("Invalid from_secret: {}", e)))?;

        // For v1: if to_public is empty, we can't generate a recrypt key
        // The caller must pass the recipient's secret key bytes in to_public
        if to_public.as_bytes().is_empty() {
            return Err(PreError::RecryptKeyGeneration(
                "TFHE v1 requires recipient's secret key bytes in to_public field".into(),
            ));
        }

        let to_tfhe_sk = recrypt_tfhe::TfheSecretKey::from_bytes(to_public.as_bytes())
            .map_err(|e| PreError::InvalidKey(format!("Invalid to_public (v1: secret key): {}", e)))?;

        let rk = recrypt_tfhe::TfheRecryptKey::generate_symmetric(
            &from_tfhe_sk,
            &to_tfhe_sk,
            &self.params,
        );

        let rk_bytes = rk.to_bytes();

        Ok(RecryptKey::new(
            BackendId::Tfhe,
            PublicKey::new(BackendId::Tfhe, vec![]),
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        if plaintext.len() != 32 {
            return Err(PreError::Encryption(format!(
                "TFHE backend only supports 32-byte encryption, got {}",
                plaintext.len()
            )));
        }

        // v1: recipient must actually be the secret key bytes
        // This is a limitation of v1 symmetric encryption
        if recipient.as_bytes().is_empty() {
            return Err(PreError::Encryption(
                "TFHE v1 requires recipient's secret key bytes for encryption".into(),
            ));
        }

        let tfhe_sk = recrypt_tfhe::TfheSecretKey::from_bytes(recipient.as_bytes())
            .map_err(|e| PreError::InvalidKey(format!("Invalid recipient key: {}", e)))?;

        let plaintext_array: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| PreError::Encryption("Plaintext must be exactly 32 bytes".into()))?;

        let multi_lwe = recrypt_tfhe::encrypt_symmetric_key(&tfhe_sk, &plaintext_array, &self.params)
            .map_err(|e| PreError::Encryption(e.to_string()))?;

        Ok(Ciphertext::new(BackendId::Tfhe, 0, multi_lwe.to_bytes()))
    }

    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>> {
        let tfhe_sk = recrypt_tfhe::TfheSecretKey::from_bytes(secret.as_bytes())
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;

        let multi_lwe = recrypt_tfhe::MultiLweCiphertext::from_bytes(ciphertext.as_bytes())
            .map_err(|e| PreError::Decryption(e.to_string()))?;

        recrypt_tfhe::decrypt_symmetric_key(&tfhe_sk, &multi_lwe, &self.params)
            .map_err(|e| PreError::Decryption(e.to_string()))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        let multi_lwe = recrypt_tfhe::MultiLweCiphertext::from_bytes(ciphertext.as_bytes())
            .map_err(|e| PreError::Recryption(e.to_string()))?;

        // Deserialize recrypt key
        let rk = recrypt_tfhe::TfheRecryptKey::from_bytes(recrypt_key.as_bytes(), &self.params)
            .map_err(|e| PreError::RecryptKeyGeneration(e.to_string()))?;

        let recrypted = recrypt_tfhe::recrypt(&rk, &multi_lwe, &self.params)
            .map_err(|e| PreError::Recryption(e.to_string()))?;

        Ok(Ciphertext::new(
            BackendId::Tfhe,
            ciphertext.level() + 1,
            recrypted.to_bytes(),
        ))
    }

    fn max_plaintext_size(&self) -> usize {
        32 // Only symmetric key, not full KeyMaterial
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        // v1: Full ciphertexts stored
        // 128 chunks × (4 bytes length + (742+1) × 8 bytes data) = ~762 KB
        // This is larger than seeded version, but simpler for v1
        let chunk_size = 4 + (self.params.lwe_dimension.0 + 1) * 8;
        4 + 128 * chunk_size
    }
}

// Stub implementation when TFHE feature is not enabled
#[cfg(not(feature = "tfhe"))]
impl PreBackend for TfheBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Tfhe
    }

    fn name(&self) -> &'static str {
        "TFHE LWE PRE (Post-Quantum, Fast) [UNAVAILABLE]"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled".into(),
        ))
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled".into(),
        ))
    }

    fn generate_recrypt_key(
        &self,
        _from_secret: &SecretKey,
        _to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled".into(),
        ))
    }

    fn encrypt(&self, _recipient: &PublicKey, _plaintext: &[u8]) -> PreResult<Ciphertext> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled".into(),
        ))
    }

    fn decrypt(&self, _secret: &SecretKey, _ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled".into(),
        ))
    }

    fn recrypt(&self, _recrypt_key: &RecryptKey, _ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled".into(),
        ))
    }

    fn max_plaintext_size(&self) -> usize {
        32
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        // Estimate for default params: 128 chunks × ~5.95 KB
        762_000
    }
}

#[cfg(all(test, feature = "tfhe"))]
mod tests {
    use super::*;

    #[test]
    fn tfhe_backend_creation() {
        let backend = TfheBackend::new().expect("Failed to create TFHE backend");
        assert_eq!(backend.backend_id(), BackendId::Tfhe);
        assert!(backend.is_post_quantum());
        assert_eq!(backend.name(), "TFHE LWE PRE (Post-Quantum, Fast)");
    }

    #[test]
    fn tfhe_keypair_generation() {
        let backend = TfheBackend::new().unwrap();
        let keypair = backend.generate_keypair().expect("Failed to generate keypair");

        assert_eq!(keypair.secret.backend(), BackendId::Tfhe);
        assert!(!keypair.secret.as_bytes().is_empty());

        // v1: public key is empty
        assert!(keypair.public.as_bytes().is_empty());
    }

    #[test]
    fn tfhe_encrypt_decrypt_roundtrip() {
        let backend = TfheBackend::new().unwrap();
        let keypair = backend.generate_keypair().unwrap();

        let plaintext = [0x42u8; 32];

        // v1: use secret key bytes as "public key" for encryption
        let recipient_as_pk = PublicKey::new(BackendId::Tfhe, keypair.secret.as_bytes().to_vec());

        let ciphertext = backend.encrypt(&recipient_as_pk, &plaintext).unwrap();
        assert_eq!(ciphertext.backend(), BackendId::Tfhe);
        assert_eq!(ciphertext.level(), 0);

        let decrypted = backend.decrypt(&keypair.secret, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn tfhe_recryption() {
        let backend = TfheBackend::new().unwrap();

        // Generate Alice's and Bob's keypairs
        let alice_keypair = backend.generate_keypair().unwrap();
        let bob_keypair = backend.generate_keypair().unwrap();

        let plaintext = [0xAB; 32];

        // Encrypt under Alice's key (v1: use secret as "public")
        let alice_pk = PublicKey::new(BackendId::Tfhe, alice_keypair.secret.as_bytes().to_vec());
        let ciphertext = backend.encrypt(&alice_pk, &plaintext).unwrap();

        // Generate recrypt key Alice → Bob (v1: pass Bob's secret as "public")
        let bob_as_pk = PublicKey::new(BackendId::Tfhe, bob_keypair.secret.as_bytes().to_vec());
        let recrypt_key = backend.generate_recrypt_key(&alice_keypair.secret, &bob_as_pk).unwrap();

        // Recrypt for Bob
        let recrypted = backend.recrypt(&recrypt_key, &ciphertext).unwrap();
        assert_eq!(recrypted.level(), 1);

        // Bob decrypts
        let decrypted = backend.decrypt(&bob_keypair.secret, &recrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }
}
