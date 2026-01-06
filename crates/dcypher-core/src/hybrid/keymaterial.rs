//! Key material bundle (implementation in Phase 2.4)

use crate::error::PreError;

/// Key material bundle (96 bytes plaintext before PRE encryption)
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// XChaCha20 symmetric key (256-bit)
    pub symmetric_key: [u8; 32],
    /// XChaCha20 extended nonce (192-bit for birthday-safe random generation)
    pub nonce: [u8; 24],
    /// Blake3 hash of original plaintext (encrypted for confidentiality!)
    pub plaintext_hash: [u8; 32],
    /// Original plaintext size in bytes
    pub plaintext_size: u64,
}

impl KeyMaterial {
    pub const SERIALIZED_SIZE: usize = 32 + 24 + 32 + 8; // 96 bytes

    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut out = [0u8; Self::SERIALIZED_SIZE];
        out[0..32].copy_from_slice(&self.symmetric_key);
        out[32..56].copy_from_slice(&self.nonce);
        out[56..88].copy_from_slice(&self.plaintext_hash);
        out[88..96].copy_from_slice(&self.plaintext_size.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PreError> {
        if bytes.len() != Self::SERIALIZED_SIZE {
            return Err(PreError::Deserialization(format!(
                "Invalid key material size: {} != {}",
                bytes.len(),
                Self::SERIALIZED_SIZE
            )));
        }
        Ok(Self {
            symmetric_key: bytes[0..32].try_into().unwrap(),
            nonce: bytes[32..56].try_into().unwrap(),
            plaintext_hash: bytes[56..88].try_into().unwrap(),
            plaintext_size: u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        })
    }
}
