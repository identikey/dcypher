//! LWE ciphertext types for TFHE operations

use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use tfhe::core_crypto::prelude::*;

use crate::error::{TfheError, TfheResult};

/// Single LWE ciphertext chunk
///
/// For v1, we store the full ciphertext (a vector + b).
/// Future optimization: use seeded ciphertexts for fresh encryptions.
#[derive(Clone, Debug)]
pub struct LweCiphertextChunk {
    /// Full ciphertext data: [a_0, ..., a_{n-1}, b]
    data: Vec<u64>,
}

impl LweCiphertextChunk {
    /// Create from a full LWE ciphertext
    pub fn from_lwe(ct: &LweCiphertextOwned<u64>) -> Self {
        Self {
            data: ct.as_ref().to_vec(),
        }
    }

    /// Convert to full LWE ciphertext
    pub fn to_lwe(&self, modulus: CiphertextModulus<u64>) -> LweCiphertextOwned<u64> {
        LweCiphertext::from_container(self.data.clone(), modulus)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.data.len() * 8);
        bytes.extend((self.data.len() as u32).to_le_bytes());
        for val in &self.data {
            bytes.extend(val.to_le_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        if bytes.len() < 4 {
            return Err(TfheError::Deserialization(
                "Ciphertext chunk too short".to_string(),
            ));
        }

        let len = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid length bytes".to_string()))?,
        ) as usize;

        let expected_len = 4 + len * 8;
        if bytes.len() != expected_len {
            return Err(TfheError::Deserialization(format!(
                "Invalid chunk length: {} != {}",
                bytes.len(),
                expected_len
            )));
        }

        let mut data = Vec::with_capacity(len);
        for i in 0..len {
            let offset = 4 + i * 8;
            let val = u64::from_le_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| TfheError::Deserialization("Invalid u64 bytes".to_string()))?,
            );
            data.push(val);
        }

        Ok(Self { data })
    }

    /// Get serialized size in bytes
    pub fn serialized_size(&self) -> usize {
        4 + self.data.len() * 8
    }
}

/// Seeded LWE ciphertext: stores seed + b value only (for fresh encryptions)
/// Receiver regenerates `a` vector from seed for ~700x size reduction
#[derive(Clone, Debug)]
pub struct SeededLweCiphertext {
    /// Seed for regenerating the `a` vector
    pub seed: [u8; 32],
    /// The `b` component of the ciphertext: b = <a, s> + m + e
    pub b: u64,
}

impl SeededLweCiphertext {
    /// Create from full LWE ciphertext by extracting the b component
    /// The seed should have been used to generate the `a` vector during encryption
    pub fn from_full(ct: &LweCiphertextOwned<u64>, seed: [u8; 32]) -> Self {
        let b = *ct.get_body().data;
        Self { seed, b }
    }

    /// Reconstruct full ciphertext by regenerating `a` from seed
    pub fn to_full(
        &self,
        dimension: LweDimension,
        modulus: CiphertextModulus<u64>,
    ) -> LweCiphertextOwned<u64> {
        let mut rng = ChaCha8Rng::from_seed(self.seed);
        let mut data = vec![0u64; dimension.0 + 1];

        // Generate `a` values from seed
        for val in data[..dimension.0].iter_mut() {
            *val = rng.next_u64();
        }

        // Set `b` at the end
        data[dimension.0] = self.b;

        LweCiphertext::from_container(data, modulus)
    }

    /// Serialize to bytes: [seed (32 bytes)][b (8 bytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&self.seed);
        bytes.extend_from_slice(&self.b.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        if bytes.len() != 40 {
            return Err(TfheError::Deserialization(format!(
                "Invalid seeded ciphertext length: {} != 40",
                bytes.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let b = u64::from_le_bytes(
            bytes[32..40]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid b bytes".to_string()))?,
        );

        Ok(Self { seed, b })
    }
}

/// Multi-LWE ciphertext: 128 LWE ciphertexts for 32-byte message
/// Each ciphertext encrypts a 2-bit chunk (256 bits total = 128 chunks)
#[derive(Clone, Debug)]
pub struct MultiLweCiphertext {
    /// Individual ciphertexts, one per 2-bit chunk
    pub chunks: Vec<LweCiphertextChunk>,
}

impl MultiLweCiphertext {
    /// Number of 2-bit chunks for a 32-byte (256-bit) message
    pub const CHUNK_COUNT: usize = 128;

    /// Create a new empty multi-LWE ciphertext with reserved capacity
    pub fn new() -> Self {
        Self {
            chunks: Vec::with_capacity(Self::CHUNK_COUNT),
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend((self.chunks.len() as u32).to_le_bytes());

        for chunk in &self.chunks {
            let chunk_bytes = chunk.to_bytes();
            bytes.extend(chunk_bytes);
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        if bytes.len() < 4 {
            return Err(TfheError::Deserialization(
                "Multi-LWE ciphertext too short".to_string(),
            ));
        }

        let count = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid count bytes".to_string()))?,
        ) as usize;

        let mut chunks = Vec::with_capacity(count);
        let mut offset = 4;

        for _ in 0..count {
            if offset + 4 > bytes.len() {
                return Err(TfheError::Deserialization(
                    "Truncated multi-LWE ciphertext".to_string(),
                ));
            }

            // Read the length prefix to determine chunk size
            let chunk_len = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| TfheError::Deserialization("Invalid chunk length".to_string()))?,
            ) as usize;

            let chunk_total_size = 4 + chunk_len * 8;
            if offset + chunk_total_size > bytes.len() {
                return Err(TfheError::Deserialization(
                    "Truncated chunk in multi-LWE".to_string(),
                ));
            }

            chunks.push(LweCiphertextChunk::from_bytes(
                &bytes[offset..offset + chunk_total_size],
            )?);
            offset += chunk_total_size;
        }

        Ok(Self { chunks })
    }
}

impl Default for MultiLweCiphertext {
    fn default() -> Self {
        Self::new()
    }
}
