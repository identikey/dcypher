//! Post-quantum signature operations via liboqs
//!
//! Provides ML-DSA (Dilithium) signatures for post-quantum security.

mod sig;

pub use sig::{PqAlgorithm, PqKeyPair, pq_keygen, pq_sign, pq_verify};
