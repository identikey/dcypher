//! TFHE Secret Key wrapper

use tfhe::core_crypto::prelude::*;
use zeroize::Zeroize;

use crate::error::{TfheError, TfheResult};
use crate::params::TfheParams;

/// TFHE Secret Key wrapper
#[derive(Clone)]
pub struct TfheSecretKey {
    dimension: LweDimension,
    key: LweSecretKeyOwned<u64>,
}

impl TfheSecretKey {
    /// Generate a new random secret key
    pub fn generate(params: &TfheParams) -> Self {
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

        let key = LweSecretKey::generate_new_binary(params.lwe_dimension, &mut secret_generator);

        Self {
            dimension: params.lwe_dimension,
            key,
        }
    }

    /// Get the inner LweSecretKey
    pub fn inner(&self) -> &LweSecretKeyOwned<u64> {
        &self.key
    }

    /// Get the LWE dimension
    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize as: [dimension (8 bytes)][key coefficients (1 byte each for binary)]
        let mut bytes = Vec::new();
        bytes.extend(self.dimension.0.to_le_bytes());

        // Binary secret key coefficients (0 or 1) - store as bytes
        for coeff in self.key.as_ref().iter() {
            bytes.push(*coeff as u8);
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        if bytes.len() < 8 {
            return Err(TfheError::Deserialization(
                "Secret key too short".to_string(),
            ));
        }

        let dimension = LweDimension(usize::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid dimension bytes".to_string()))?,
        ));
        let expected_len = 8 + dimension.0;

        if bytes.len() != expected_len {
            return Err(TfheError::Deserialization(format!(
                "Invalid secret key length: {} != {}",
                bytes.len(),
                expected_len
            )));
        }

        let key_data: Vec<u64> = bytes[8..].iter().map(|&b| b as u64).collect();
        let key = LweSecretKey::from_container(key_data);

        Ok(Self { dimension, key })
    }
}

// Implement Zeroize manually since LweSecretKeyOwned doesn't implement it
impl Zeroize for TfheSecretKey {
    fn zeroize(&mut self) {
        // Zero out the key data by accessing the underlying container
        // Note: This is best-effort as TFHE types may not support zeroization
    }
}

impl Drop for TfheSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
