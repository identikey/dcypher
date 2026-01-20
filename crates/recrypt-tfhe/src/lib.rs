//! TFHE-based Proxy Recryption Library
//!
//! This crate provides TFHE LWE-based proxy recryption, enabling fast post-quantum
//! secure key transformation without revealing plaintext.
//!
//! # Overview
//!
//! TFHE (Torus Fully Homomorphic Encryption) uses LWE (Learning With Errors) ciphertexts
//! and key switching to implement proxy recryption:
//!
//! 1. **Encryption**: A 32-byte symmetric key is encrypted as 128 × 2-bit LWE ciphertexts
//! 2. **Recryption**: Key switching transforms ciphertexts from Alice's key to Bob's key
//! 3. **Decryption**: Bob decrypts using his secret key
//!
//! # Performance
//!
//! Expected performance improvements over OpenFHE BFV:
//! - Recryption: ~1-3s → ~10-50ms (10-100x faster)
//! - Pure Rust (no C++ FFI)
//! - Thread-safe (no global state)
//!
//! # v1 Limitations
//!
//! This v1 implementation uses symmetric key switching key (KSK) generation,
//! which requires both Alice's and Bob's secret keys. Phase 3 will implement
//! asymmetric KSK generation using only Alice's secret + Bob's public key.
//!
//! # Example
//!
//! ```ignore
//! use recrypt_tfhe::{TfheParams, TfheSecretKey, TfheRecryptKey};
//! use recrypt_tfhe::{encrypt_symmetric_key, decrypt_symmetric_key, recrypt};
//!
//! let params = TfheParams::default_128bit();
//!
//! // Generate keys
//! let alice_sk = TfheSecretKey::generate(&params);
//! let bob_sk = TfheSecretKey::generate(&params);
//!
//! // Encrypt a 32-byte key
//! let plaintext = [0x42u8; 32];
//! let ciphertext = encrypt_symmetric_key(&alice_sk, &plaintext, &params).unwrap();
//!
//! // Generate recryption key (v1: requires both secrets)
//! let rk = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);
//!
//! // Recrypt for Bob
//! let recrypted = recrypt(&rk, &ciphertext, &params).unwrap();
//!
//! // Bob decrypts
//! let decrypted = decrypt_symmetric_key(&bob_sk, &recrypted, &params).unwrap();
//! assert_eq!(&decrypted[..], &plaintext[..]);
//! ```

pub mod ciphertext;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod keys;
pub mod params;
pub mod recrypt;

// Re-exports for convenience
pub use ciphertext::{LweCiphertextChunk, MultiLweCiphertext, SeededLweCiphertext};
pub use decrypt::decrypt_symmetric_key;
pub use encrypt::{encrypt_symmetric_key, encrypt_with_public_key};
pub use error::{TfheError, TfheResult};
pub use keys::{TfhePublicKey, TfheRecryptKey, TfheSecretKey};
pub use params::TfheParams;
pub use recrypt::recrypt;
