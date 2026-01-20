//! TFHE Recryption (Key Switching) Key

use tfhe::core_crypto::prelude::*;

use crate::error::{TfheError, TfheResult};
use crate::keys::TfheSecretKey;
use crate::params::TfheParams;

/// TFHE Recryption Key (Key Switching Key)
///
/// This is a v1 symmetric implementation that requires both Alice's and Bob's
/// secret keys. Phase 3 will implement asymmetric KSK generation using only
/// Alice's secret + Bob's public key.
pub struct TfheRecryptKey {
    /// The underlying LWE key switching key
    ksk: LweKeyswitchKeyOwned<u64>,
    /// Input dimension (Alice's key)
    input_dimension: LweDimension,
    /// Output dimension (Bob's key)
    output_dimension: LweDimension,
}

impl TfheRecryptKey {
    /// Generate a symmetric recryption key (v1 - requires both secrets)
    ///
    /// This allows transforming ciphertexts encrypted under `from_secret`
    /// into ciphertexts decryptable by `to_secret`.
    pub fn generate_symmetric(
        from_secret: &TfheSecretKey,
        to_secret: &TfheSecretKey,
        params: &TfheParams,
    ) -> Self {
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                seeder_ref.seed(),
                seeder_ref,
            );

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            from_secret.inner(),
            to_secret.inner(),
            params.decomp_base_log,
            params.decomp_level_count,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );

        Self {
            ksk,
            input_dimension: from_secret.dimension(),
            output_dimension: to_secret.dimension(),
        }
    }

    /// Get the inner LweKeyswitchKey
    pub fn inner(&self) -> &LweKeyswitchKeyOwned<u64> {
        &self.ksk
    }

    /// Get the input (source) LWE dimension
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Get the output (target) LWE dimension
    pub fn output_dimension(&self) -> LweDimension {
        self.output_dimension
    }

    /// Serialize to bytes
    ///
    /// Format: [input_dim (8)][output_dim (8)][decomp_base_log (8)][decomp_level (8)][ksk data...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let decomp_base_log = self.ksk.decomposition_base_log().0;
        let decomp_level = self.ksk.decomposition_level_count().0;

        let mut bytes = Vec::new();
        bytes.extend(self.input_dimension.0.to_le_bytes());
        bytes.extend(self.output_dimension.0.to_le_bytes());
        bytes.extend(decomp_base_log.to_le_bytes());
        bytes.extend(decomp_level.to_le_bytes());

        // Store the raw KSK data
        for val in self.ksk.as_ref().iter() {
            bytes.extend(val.to_le_bytes());
        }

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: &TfheParams) -> TfheResult<Self> {
        if bytes.len() < 32 {
            return Err(TfheError::Deserialization(
                "Recrypt key too short".to_string(),
            ));
        }

        let input_dimension = LweDimension(usize::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid input dimension".to_string()))?,
        ));
        let output_dimension = LweDimension(usize::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid output dimension".to_string()))?,
        ));
        let decomp_base_log = DecompositionBaseLog(usize::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid decomp_base_log".to_string()))?,
        ));
        let decomp_level_count = DecompositionLevelCount(usize::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid decomp_level_count".to_string()))?,
        ));

        // Calculate expected KSK data size
        // KSK size = input_dim * level_count * (output_dim + 1) u64 values
        let ksk_element_count =
            input_dimension.0 * decomp_level_count.0 * (output_dimension.0 + 1);
        let expected_len = 32 + ksk_element_count * 8;

        if bytes.len() != expected_len {
            return Err(TfheError::Deserialization(format!(
                "Invalid recrypt key length: {} != {}",
                bytes.len(),
                expected_len
            )));
        }

        // Parse KSK data
        let mut ksk_data = Vec::with_capacity(ksk_element_count);
        for i in 0..ksk_element_count {
            let offset = 32 + i * 8;
            let val = u64::from_le_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| TfheError::Deserialization("Invalid KSK value".to_string()))?,
            );
            ksk_data.push(val);
        }

        let ksk = LweKeyswitchKey::from_container(
            ksk_data,
            decomp_base_log,
            decomp_level_count,
            output_dimension.to_lwe_size(),
            params.ciphertext_modulus,
        );

        Ok(Self {
            ksk,
            input_dimension,
            output_dimension,
        })
    }
}
