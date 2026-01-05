//! Post-quantum signature operations

use crate::error::FfiError;

/// Supported post-quantum signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAlgorithm {
    /// ML-DSA-87 (formerly Dilithium5) - highest security level
    MlDsa87,
    /// ML-DSA-65 (formerly Dilithium3)
    MlDsa65,
    /// ML-DSA-44 (formerly Dilithium2)
    MlDsa44,
}

impl PqAlgorithm {
    /// Get the OQS algorithm name string
    pub fn to_oqs_name(&self) -> &'static str {
        match self {
            Self::MlDsa87 => "ML-DSA-87",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa44 => "ML-DSA-44",
        }
    }
}

/// A post-quantum keypair
pub struct PqKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: PqAlgorithm,
}

/// Generate a new post-quantum keypair
pub fn pq_keygen(_alg: PqAlgorithm) -> Result<PqKeyPair, FfiError> {
    // TODO: Implement via liboqs FFI in Phase 1c
    Err(FfiError::LibOqs(
        "liboqs bindings not yet implemented".into(),
    ))
}

/// Sign a message with a post-quantum secret key
pub fn pq_sign(_sk: &[u8], _alg: PqAlgorithm, _message: &[u8]) -> Result<Vec<u8>, FfiError> {
    // TODO: Implement via liboqs FFI in Phase 1c
    Err(FfiError::LibOqs(
        "liboqs bindings not yet implemented".into(),
    ))
}

/// Verify a post-quantum signature
pub fn pq_verify(
    _pk: &[u8],
    _alg: PqAlgorithm,
    _message: &[u8],
    _signature: &[u8],
) -> Result<bool, FfiError> {
    // TODO: Implement via liboqs FFI in Phase 1c
    Err(FfiError::LibOqs(
        "liboqs bindings not yet implemented".into(),
    ))
}
