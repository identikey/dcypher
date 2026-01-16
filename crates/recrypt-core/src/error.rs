use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("PRE backend error: {0}")]
    PreBackend(#[from] PreError),

    #[error("Signature error: {0}")]
    Signature(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("FFI error: {0}")]
    Ffi(#[from] recrypt_ffi::error::FfiError),
}

pub type CoreResult<T> = Result<T, CoreError>;

/// Errors from PRE operations
#[derive(Error, Debug)]
pub enum PreError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Recryption failed: {0}")]
    Recryption(String),

    #[error("Recrypt key generation failed: {0}")]
    RecryptKeyGeneration(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    #[error("Backend not available: {0}")]
    BackendUnavailable(String),
}

pub type PreResult<T> = Result<T, PreError>;
