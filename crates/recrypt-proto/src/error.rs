use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("Protobuf encode error: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),

    #[error("Protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),

    #[error("Armor parse error: {0}")]
    ArmorParse(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Bao verification failed: {0}")]
    BaoVerification(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Core error: {0}")]
    Core(#[from] recrypt_core::error::CoreError),
}

pub type ProtoResult<T> = Result<T, ProtoError>;
