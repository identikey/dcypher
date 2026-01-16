//! OpenFHE Proxy Recryption bindings
//!
//! Provides lattice-based PRE via the BFV scheme with INDCPA security.

mod pre;

pub use pre::{bytes_to_coefficients, coefficients_to_bytes};

use crate::error::FfiError;

#[cfg(feature = "openfhe")]
use recrypt_openfhe_sys::ffi as openfhe;

/// A public key for encryption
pub struct PublicKey {
    #[cfg(feature = "openfhe")]
    inner: cxx::UniquePtr<openfhe::PublicKey>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

/// A secret key for decryption
pub struct SecretKey {
    #[cfg(feature = "openfhe")]
    inner: cxx::UniquePtr<openfhe::PrivateKey>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

/// A keypair containing both public and secret keys
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// A ciphertext encrypted under a public key
pub struct Ciphertext {
    #[cfg(feature = "openfhe")]
    inner: cxx::UniquePtr<openfhe::Ciphertext>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

/// A recryption key for transforming ciphertexts
pub struct RecryptKey {
    #[cfg(feature = "openfhe")]
    inner: cxx::UniquePtr<openfhe::RecryptKey>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

/// PRE-enabled crypto context using BFV scheme
pub struct PreContext {
    #[cfg(feature = "openfhe")]
    inner: cxx::UniquePtr<openfhe::CryptoContext>,
    #[cfg(feature = "openfhe")]
    ring_dimension: u32,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

#[cfg(feature = "openfhe")]
impl PreContext {
    /// Create a new PRE context with default parameters
    ///
    /// Uses BFVrns with plaintext_modulus = 65537
    pub fn new() -> Result<Self, FfiError> {
        let ctx = openfhe::create_bfv_context(65537, 60);
        if ctx.is_null() {
            return Err(FfiError::OpenFhe("Failed to create BFV context".into()));
        }

        openfhe::enable_pke(&ctx);
        openfhe::enable_keyswitch(&ctx);
        openfhe::enable_leveledshe(&ctx);
        openfhe::enable_pre(&ctx);

        let ring_dimension = openfhe::get_ring_dimension(&ctx);

        Ok(Self {
            inner: ctx,
            ring_dimension,
        })
    }

    /// Get the number of slots available for packing data
    pub fn slot_count(&self) -> u32 {
        self.ring_dimension
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> Result<KeyPair, FfiError> {
        let kp = openfhe::keygen(&self.inner);
        if kp.is_null() {
            return Err(FfiError::OpenFhe("Failed to generate keypair".into()));
        }

        let pk = openfhe::get_public_key(&kp);
        let sk = openfhe::get_private_key(&kp);

        Ok(KeyPair {
            public: PublicKey { inner: pk },
            secret: SecretKey { inner: sk },
        })
    }

    /// Encrypt raw bytes for a recipient
    ///
    /// Data is converted to coefficients and may be split across multiple ciphertexts
    /// if it exceeds the slot capacity.
    pub fn encrypt(&self, pk: &PublicKey, data: &[u8]) -> Result<Vec<Ciphertext>, FfiError> {
        let coeffs = bytes_to_coefficients(data);
        let slot_count = self.slot_count() as usize;

        let mut ciphertexts = Vec::new();
        for chunk in coeffs.chunks(slot_count) {
            // Pad to full slot count
            let mut padded = chunk.to_vec();
            padded.resize(slot_count, 0);

            let pt = openfhe::make_packed_plaintext(&self.inner, &padded);
            let ct = openfhe::encrypt(&self.inner, &pk.inner, &pt);

            if ct.is_null() {
                return Err(FfiError::OpenFhe("Encryption failed".into()));
            }

            ciphertexts.push(Ciphertext { inner: ct });
        }

        Ok(ciphertexts)
    }

    /// Decrypt ciphertexts and return raw bytes
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        ciphertexts: &[Ciphertext],
        original_len: usize,
    ) -> Result<Vec<u8>, FfiError> {
        let mut all_coeffs = Vec::new();

        for ct in ciphertexts {
            let pt = openfhe::decrypt(&self.inner, &sk.inner, &ct.inner);
            if pt.is_null() {
                return Err(FfiError::OpenFhe("Decryption failed".into()));
            }

            let coeffs = openfhe::get_packed_value(&pt);
            all_coeffs.extend(coeffs);
        }

        // Convert back to bytes
        let coeff_count = original_len.div_ceil(2);
        let bytes = coefficients_to_bytes(
            &all_coeffs[..coeff_count.min(all_coeffs.len())],
            original_len,
        );

        Ok(bytes)
    }

    /// Generate a recryption key from one user to another
    pub fn generate_recrypt_key(
        &self,
        from_sk: &SecretKey,
        to_pk: &PublicKey,
    ) -> Result<RecryptKey, FfiError> {
        let rk = openfhe::generate_recrypt_key(&self.inner, &from_sk.inner, &to_pk.inner);
        if rk.is_null() {
            return Err(FfiError::OpenFhe(
                "Failed to generate recryption key".into(),
            ));
        }

        Ok(RecryptKey { inner: rk })
    }

    /// Transform ciphertexts from one recipient to another
    pub fn recrypt(
        &self,
        rk: &RecryptKey,
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<Ciphertext>, FfiError> {
        let mut result = Vec::with_capacity(ciphertexts.len());

        for ct in ciphertexts {
            let new_ct = openfhe::recrypt(&self.inner, &rk.inner, &ct.inner);
            if new_ct.is_null() {
                return Err(FfiError::OpenFhe("Recryption failed".into()));
            }
            result.push(Ciphertext { inner: new_ct });
        }

        Ok(result)
    }
}

// Stub implementation when openfhe feature is disabled
#[cfg(not(feature = "openfhe"))]
impl PreContext {
    pub fn new() -> Result<Self, FfiError> {
        Err(FfiError::OpenFhe(
            "OpenFHE feature not enabled. Build with --features openfhe".into(),
        ))
    }

    pub fn slot_count(&self) -> u32 {
        0
    }

    pub fn generate_keypair(&self) -> Result<KeyPair, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn encrypt(&self, _pk: &PublicKey, _data: &[u8]) -> Result<Vec<Ciphertext>, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn decrypt(
        &self,
        _sk: &SecretKey,
        _ciphertexts: &[Ciphertext],
        _original_len: usize,
    ) -> Result<Vec<u8>, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn generate_recrypt_key(
        &self,
        _from_sk: &SecretKey,
        _to_pk: &PublicKey,
    ) -> Result<RecryptKey, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn recrypt(
        &self,
        _rk: &RecryptKey,
        _ciphertexts: &[Ciphertext],
    ) -> Result<Vec<Ciphertext>, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }
}

#[cfg(all(test, feature = "openfhe"))]
mod tests {
    use super::*;

    #[test]
    fn test_pre_context_creation() {
        let ctx = PreContext::new().unwrap();
        assert!(ctx.slot_count() > 0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx = PreContext::new().unwrap();
        let kp = ctx.generate_keypair().unwrap();

        let data = b"Hello, PRE!";
        let ciphertexts = ctx.encrypt(&kp.public, data).unwrap();
        let decrypted = ctx.decrypt(&kp.secret, &ciphertexts, data.len()).unwrap();

        assert_eq!(&decrypted[..], data);
    }

    #[test]
    fn test_pre_recryption_flow() {
        let ctx = PreContext::new().unwrap();

        // Alice and Bob
        let alice = ctx.generate_keypair().unwrap();
        let bob = ctx.generate_keypair().unwrap();

        // Alice encrypts
        let data = b"Secret message for recryption";
        let ct_alice = ctx.encrypt(&alice.public, data).unwrap();

        // Generate recryption key Alice → Bob
        let rk = ctx
            .generate_recrypt_key(&alice.secret, &bob.public)
            .unwrap();

        // Proxy transforms
        let ct_bob = ctx.recrypt(&rk, &ct_alice).unwrap();

        // Bob decrypts
        let decrypted = ctx.decrypt(&bob.secret, &ct_bob, data.len()).unwrap();

        assert_eq!(&decrypted[..], data);
    }
}
