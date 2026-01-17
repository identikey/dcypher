//! Multi-format serialization support

use crate::armor::ArmorType;
use crate::error::{ProtoError, ProtoResult};

/// Detected serialization format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Protobuf,
    Json,
    Armor,
}

/// Detect format from raw bytes
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(b"----- BEGIN RECRYPT") {
        Format::Armor
    } else if data.first() == Some(&b'{') {
        Format::Json
    } else {
        Format::Protobuf
    }
}

/// Trait for types that can be serialized to multiple formats
pub trait MultiFormat: Sized {
    /// Protobuf message type name (for debugging)
    fn proto_name() -> &'static str;

    /// Serialize to Protobuf bytes
    fn to_protobuf(&self) -> ProtoResult<Vec<u8>>;

    /// Deserialize from Protobuf bytes
    fn from_protobuf(bytes: &[u8]) -> ProtoResult<Self>;

    /// Serialize to JSON string
    fn to_json(&self) -> ProtoResult<String>;

    /// Deserialize from JSON string
    fn from_json(s: &str) -> ProtoResult<Self>;

    /// Serialize to ASCII armor (if applicable)
    fn to_armor(&self, armor_type: ArmorType) -> ProtoResult<String>;

    /// Deserialize from ASCII armor
    fn from_armor(s: &str) -> ProtoResult<Self>;

    /// Deserialize from any format (auto-detect)
    fn from_any(data: &[u8]) -> ProtoResult<Self> {
        match detect_format(data) {
            Format::Protobuf => Self::from_protobuf(data),
            Format::Json => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| ProtoError::InvalidFormat(e.to_string()))?;
                Self::from_json(s)
            }
            Format::Armor => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| ProtoError::InvalidFormat(e.to_string()))?;
                Self::from_armor(s)
            }
        }
    }
}
