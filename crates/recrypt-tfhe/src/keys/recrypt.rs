//! TFHE Recryption (Key Switching) Key
//!
//! A recryption key (also called a key switching key or KSK) allows transforming
//! ciphertexts encrypted under one secret key into ciphertexts decryptable by
//! another secret key, without revealing the plaintext.
//!
//! This module provides both symmetric (requires both secrets) and asymmetric
//! (requires only source secret + target public key) KSK generation.

use tfhe::core_crypto::prelude::*;

use crate::error::{TfheError, TfheResult};
use crate::keys::{TfhePublicKey, TfheSecretKey};
use crate::params::TfheParams;

/// TFHE Recryption Key (Key Switching Key)
///
/// Allows transforming ciphertexts from one key to another.
/// Can be generated using either:
/// - `generate_symmetric`: requires both secret keys (testing/internal use)
/// - `generate_asymmetric`: requires source secret + target public (production use)
pub struct TfheRecryptKey {
    /// The underlying LWE key switching key
    ksk: LweKeyswitchKeyOwned<u64>,
    /// Input dimension (source key)
    input_dimension: LweDimension,
    /// Output dimension (target key)
    output_dimension: LweDimension,
}

impl TfheRecryptKey {
    /// Generate a symmetric recryption key (requires both secrets)
    ///
    /// This allows transforming ciphertexts encrypted under `from_secret`
    /// into ciphertexts decryptable by `to_secret`.
    ///
    /// Use this for testing or internal operations where both secrets are available.
    /// For production use, prefer `generate_asymmetric`.
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

    /// Generate an asymmetric recryption key (EXPERIMENTAL - HIGH NOISE)
    ///
    /// **WARNING**: This method has noise accumulation issues with current parameters.
    /// Public key encryption introduces ~52 bits of noise per KSK element. With n=742
    /// dimensions and 3 decomposition levels, the accumulated noise during key switching
    /// exceeds the ~62-bit message space, causing decryption failures.
    ///
    /// For production use, prefer `generate_symmetric` or the hybrid approach where
    /// the target sends their secret key over a secure channel (e.g., encrypted with
    /// the source's public key using a traditional PKE scheme).
    ///
    /// This method is kept for research/experimentation with different parameters.
    ///
    /// # How it works
    ///
    /// A key switching key is a collection of encryptions where for each
    /// input secret key coefficient s_i and decomposition level l, we encrypt:
    ///   `-s_i * q / B^l` under the target key (negated for subtraction in keyswitch)
    ///
    /// where q is the ciphertext modulus (2^64 for native) and B = 2^base_log.
    ///
    /// With the symmetric version, we use TFHE's standard key generation (~47 bit noise).
    /// With the asymmetric version, we use public-key encryption (~52 bit noise).
    pub fn generate_asymmetric(
        from_secret: &TfheSecretKey,
        to_public: &TfhePublicKey,
        params: &TfheParams,
    ) -> Self {
        let input_dim = from_secret.dimension();
        let output_dim = to_public.dimension();
        let decomp_base_log = params.decomp_base_log;
        let decomp_level_count = params.decomp_level_count;

        // Build KSK data manually
        // The output ciphertext has size (output_dim + 1)
        let output_lwe_size = output_dim.to_lwe_size().0; // dimension + 1
        let total_elements = input_dim.0 * decomp_level_count.0 * output_lwe_size;
        let mut ksk_data = vec![0u64; total_elements];

        // Get the secret key coefficients (binary: 0 or 1)
        let secret_coeffs = from_secret.inner().as_ref();

        // For each coefficient of the input secret key
        for i in 0..input_dim.0 {
            let s_i = secret_coeffs[i]; // 0 or 1 (binary secret)

            // For each decomposition level (1 to level_count)
            // Level 1 is the most significant, level_count is the least significant
            for level in 1..=decomp_level_count.0 {
                // Compute the gadget factor: 2^(64 - level * base_log)
                // This is the scaling factor for this decomposition level
                // The formula is: q / B^l where q = 2^64, B = 2^base_log
                // So: 2^64 / 2^(l * base_log) = 2^(64 - l * base_log)
                let shift = 64usize.saturating_sub(level * decomp_base_log.0);
                let gadget_factor = 1u64 << shift;

                // The plaintext to encrypt: -s_i * gadget_factor (negated!)
                // Key switching subtracts, so we encrypt the negation.
                // Note: s_i is 0 or 1, so this is either 0 or -gadget_factor
                // In modular arithmetic, -x = (2^64 - x) mod 2^64 = wrapping_neg(x)
                let plaintext_value = if s_i != 0 {
                    gadget_factor.wrapping_neg()
                } else {
                    0
                };

                // Encrypt under the target public key
                let ct = to_public.encrypt_lwe(Plaintext(plaintext_value));

                // Copy the ciphertext data into the KSK
                let ksk_offset =
                    i * decomp_level_count.0 * output_lwe_size + (level - 1) * output_lwe_size;
                ksk_data[ksk_offset..ksk_offset + output_lwe_size]
                    .copy_from_slice(ct.as_ref());
            }
        }

        // Construct the KSK from our manually built data
        let ksk = LweKeyswitchKey::from_container(
            ksk_data,
            decomp_base_log,
            decomp_level_count,
            output_dim.to_lwe_size(),
            params.ciphertext_modulus,
        );

        Self {
            ksk,
            input_dimension: input_dim,
            output_dimension: output_dim,
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
