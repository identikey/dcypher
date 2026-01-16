//! Post-quantum signature operations via liboqs

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

#[cfg(feature = "liboqs")]
impl From<PqAlgorithm> for oqs::sig::Algorithm {
    fn from(alg: PqAlgorithm) -> Self {
        match alg {
            PqAlgorithm::MlDsa87 => oqs::sig::Algorithm::MlDsa87,
            PqAlgorithm::MlDsa65 => oqs::sig::Algorithm::MlDsa65,
            PqAlgorithm::MlDsa44 => oqs::sig::Algorithm::MlDsa44,
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
#[cfg(feature = "liboqs")]
pub fn pq_keygen(alg: PqAlgorithm) -> Result<PqKeyPair, FfiError> {
    let sig = oqs::sig::Sig::new(alg.into())
        .map_err(|e| FfiError::LibOqs(format!("Failed to init algorithm: {e}")))?;

    let (pk, sk) = sig
        .keypair()
        .map_err(|e| FfiError::LibOqs(format!("Keygen failed: {e}")))?;

    Ok(PqKeyPair {
        public_key: pk.into_vec(),
        secret_key: sk.into_vec(),
        algorithm: alg,
    })
}

/// Sign a message with a post-quantum secret key
#[cfg(feature = "liboqs")]
pub fn pq_sign(sk: &[u8], alg: PqAlgorithm, message: &[u8]) -> Result<Vec<u8>, FfiError> {
    let sig_scheme = oqs::sig::Sig::new(alg.into())
        .map_err(|e| FfiError::LibOqs(format!("Failed to init algorithm: {e}")))?;

    let secret_key = sig_scheme
        .secret_key_from_bytes(sk)
        .ok_or_else(|| FfiError::LibOqs("Invalid secret key length".into()))?;

    let signature = sig_scheme
        .sign(message, secret_key)
        .map_err(|e| FfiError::LibOqs(format!("Signing failed: {e}")))?;

    Ok(signature.into_vec())
}

/// Verify a post-quantum signature
#[cfg(feature = "liboqs")]
pub fn pq_verify(
    pk: &[u8],
    alg: PqAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, FfiError> {
    let sig_scheme = oqs::sig::Sig::new(alg.into())
        .map_err(|e| FfiError::LibOqs(format!("Failed to init algorithm: {e}")))?;

    let public_key = sig_scheme
        .public_key_from_bytes(pk)
        .ok_or_else(|| FfiError::LibOqs("Invalid public key length".into()))?;

    let sig_ref = sig_scheme
        .signature_from_bytes(signature)
        .ok_or_else(|| FfiError::LibOqs("Invalid signature length".into()))?;

    match sig_scheme.verify(message, sig_ref, public_key) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// Stub implementations when liboqs feature is disabled
#[cfg(not(feature = "liboqs"))]
pub fn pq_keygen(_alg: PqAlgorithm) -> Result<PqKeyPair, FfiError> {
    Err(FfiError::LibOqs(
        "liboqs feature not enabled. Build with --features liboqs".into(),
    ))
}

#[cfg(not(feature = "liboqs"))]
pub fn pq_sign(_sk: &[u8], _alg: PqAlgorithm, _message: &[u8]) -> Result<Vec<u8>, FfiError> {
    Err(FfiError::LibOqs(
        "liboqs feature not enabled. Build with --features liboqs".into(),
    ))
}

#[cfg(not(feature = "liboqs"))]
pub fn pq_verify(
    _pk: &[u8],
    _alg: PqAlgorithm,
    _message: &[u8],
    _signature: &[u8],
) -> Result<bool, FfiError> {
    Err(FfiError::LibOqs(
        "liboqs feature not enabled. Build with --features liboqs".into(),
    ))
}

#[cfg(all(test, feature = "liboqs"))]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        let kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let message = b"Test message for ML-DSA-87";

        let signature = pq_sign(&kp.secret_key, PqAlgorithm::MlDsa87, message).unwrap();
        let valid = pq_verify(&kp.public_key, PqAlgorithm::MlDsa87, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let kp = pq_keygen(PqAlgorithm::MlDsa65).unwrap();
        let message = b"Test message for ML-DSA-65";

        let signature = pq_sign(&kp.secret_key, PqAlgorithm::MlDsa65, message).unwrap();
        let valid = pq_verify(&kp.public_key, PqAlgorithm::MlDsa65, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_ml_dsa_44_roundtrip() {
        let kp = pq_keygen(PqAlgorithm::MlDsa44).unwrap();
        let message = b"Test message for ML-DSA-44";

        let signature = pq_sign(&kp.secret_key, PqAlgorithm::MlDsa44, message).unwrap();
        let valid = pq_verify(&kp.public_key, PqAlgorithm::MlDsa44, message, &signature).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_tampered_message_fails() {
        let kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let message = b"Original message";
        let tampered = b"Tampered message";

        let signature = pq_sign(&kp.secret_key, PqAlgorithm::MlDsa87, message).unwrap();
        let valid = pq_verify(&kp.public_key, PqAlgorithm::MlDsa87, tampered, &signature).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let kp2 = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let message = b"Test message";

        let signature = pq_sign(&kp1.secret_key, PqAlgorithm::MlDsa87, message).unwrap();
        let valid = pq_verify(&kp2.public_key, PqAlgorithm::MlDsa87, message, &signature).unwrap();

        assert!(!valid);
    }
}
