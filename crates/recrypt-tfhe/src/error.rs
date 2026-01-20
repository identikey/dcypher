//! Error types for TFHE operations

#[derive(Debug, thiserror::Error)]
pub enum TfheError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Recryption failed: {0}")]
    Recryption(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),
}

pub type TfheResult<T> = Result<T, TfheError>;
