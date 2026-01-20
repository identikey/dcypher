//! TFHE Public Key
//!
//! Uses TFHE-rs built-in LwePublicKey for proper noise management and
//! IND-CPA secure public-key encryption.

use tfhe::core_crypto::prelude::*;

use crate::error::{TfheError, TfheResult};
use crate::keys::TfheSecretKey;
use crate::params::TfheParams;

/// TFHE Public Key
///
/// Wraps the TFHE-rs LwePublicKey type for proper public-key encryption.
/// Uses the recommended zero encryption count for security.
pub struct TfhePublicKey {
    /// The underlying TFHE public key
    inner: LwePublicKeyOwned<u64>,
    /// LWE dimension
    dimension: LweDimension,
    /// Ciphertext modulus
    modulus: CiphertextModulus<u64>,
    /// Noise distribution (needed for encryption)
    noise_distribution: DynamicDistribution<u64>,
}

impl TfhePublicKey {
    /// Generate public key from secret key
    ///
    /// Uses TFHE-rs recommended zero encryption count for security.
    pub fn from_secret(secret: &TfheSecretKey, params: &TfheParams) -> Self {
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

        // Use the recommended zero encryption count: (n+1)*64+128
        // This provides optimal security guarantees.
        // Timing: ~6 seconds in release mode for n=742.
        let n = secret.dimension().0;
        let zero_encryption_count = LwePublicKeyZeroEncryptionCount((n + 1) * 64 + 128);

        let pk = allocate_and_generate_new_lwe_public_key(
            secret.inner(),
            zero_encryption_count,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );

        Self {
            inner: pk,
            dimension: secret.dimension(),
            modulus: params.ciphertext_modulus,
            noise_distribution: params.lwe_noise_distribution,
        }
    }

    /// Encrypt a plaintext using this public key
    ///
    /// Uses TFHE-rs built-in public key encryption for proper noise management.
    pub fn encrypt_lwe(&self, plaintext: Plaintext<u64>) -> LweCiphertextOwned<u64> {
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

        let mut ct = LweCiphertext::new(0u64, self.dimension.to_lwe_size(), self.modulus);

        encrypt_lwe_ciphertext_with_public_key(
            &self.inner,
            &mut ct,
            plaintext,
            &mut secret_generator,
        );

        ct
    }

    /// Get the inner LwePublicKey
    pub fn inner(&self) -> &LwePublicKeyOwned<u64> {
        &self.inner
    }

    /// Get the LWE dimension
    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    /// Get the ciphertext modulus
    pub fn modulus(&self) -> CiphertextModulus<u64> {
        self.modulus
    }

    /// Get the noise distribution
    pub fn noise_distribution(&self) -> DynamicDistribution<u64> {
        self.noise_distribution
    }

    /// Number of zero encryptions in the public key
    pub fn encryption_count(&self) -> usize {
        self.inner.zero_encryption_count().0
    }

    /// Serialize to bytes
    ///
    /// Format: [dimension (8)][modulus flag (1)][noise_std (8)][count (4)][ciphertext data...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_size = self.dimension.0 + 1; // a vector + b
        let count = self.encryption_count();
        let total_ct_bytes = count * ct_size * 8;

        let mut bytes = Vec::with_capacity(8 + 1 + 8 + 4 + total_ct_bytes);

        // Header
        bytes.extend(self.dimension.0.to_le_bytes());
        bytes.push(if self.modulus.is_native_modulus() { 1 } else { 0 });

        // Store noise standard deviation
        let noise_std = match self.noise_distribution {
            DynamicDistribution::Gaussian(g) => g.standard_dev().0,
            _ => 0.0,
        };
        bytes.extend(noise_std.to_le_bytes());

        bytes.extend((count as u32).to_le_bytes());

        // Ciphertext data (flat array of u64 values)
        for val in self.inner.as_ref().iter() {
            bytes.extend(val.to_le_bytes());
        }

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        if bytes.len() < 21 {
            return Err(TfheError::Deserialization(
                "Public key too short".to_string(),
            ));
        }

        // Parse header
        let dimension = LweDimension(usize::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid dimension".to_string()))?,
        ));

        let modulus = if bytes[8] == 1 {
            CiphertextModulus::new_native()
        } else {
            return Err(TfheError::Deserialization(
                "Only native modulus supported".to_string(),
            ));
        };

        let noise_std = f64::from_le_bytes(
            bytes[9..17]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid noise std".to_string()))?,
        );
        let noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev(noise_std));

        let count = u32::from_le_bytes(
            bytes[17..21]
                .try_into()
                .map_err(|_| TfheError::Deserialization("Invalid count".to_string()))?,
        ) as usize;

        // Validate expected length
        let ct_size = dimension.0 + 1;
        let expected_len = 21 + count * ct_size * 8;
        if bytes.len() != expected_len {
            return Err(TfheError::Deserialization(format!(
                "Invalid public key length: {} != {}",
                bytes.len(),
                expected_len
            )));
        }

        // Parse ciphertexts into a flat vector
        let total_elements = count * ct_size;
        let mut pk_data = Vec::with_capacity(total_elements);
        let mut offset = 21;

        for _ in 0..total_elements {
            let val = u64::from_le_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| TfheError::Deserialization("Invalid u64".to_string()))?,
            );
            pk_data.push(val);
            offset += 8;
        }

        let inner = LwePublicKey::from_container(
            pk_data,
            dimension.to_lwe_size(),
            modulus,
        );

        Ok(Self {
            inner,
            dimension,
            modulus,
            noise_distribution,
        })
    }
}

impl Clone for TfhePublicKey {
    fn clone(&self) -> Self {
        Self {
            inner: LwePublicKey::from_container(
                self.inner.as_ref().to_vec(),
                self.dimension.to_lwe_size(),
                self.modulus,
            ),
            dimension: self.dimension,
            modulus: self.modulus,
            noise_distribution: self.noise_distribution,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_generation() {
        let params = TfheParams::default_128bit();
        let sk = TfheSecretKey::generate(&params);
        let pk = TfhePublicKey::from_secret(&sk, &params);

        assert_eq!(pk.dimension(), sk.dimension());
        // Recommended count: (n+1) * 64 + 128 = 47680 for n=742
        let n = sk.dimension().0;
        let expected_count = (n + 1) * 64 + 128;
        assert_eq!(pk.encryption_count(), expected_count);
    }

    #[test]
    fn public_key_serialization_roundtrip() {
        let params = TfheParams::default_128bit();
        let sk = TfheSecretKey::generate(&params);
        let pk = TfhePublicKey::from_secret(&sk, &params);

        let bytes = pk.to_bytes();
        let pk2 = TfhePublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pk.dimension(), pk2.dimension());
        assert_eq!(pk.encryption_count(), pk2.encryption_count());
    }

    #[test]
    fn public_key_encryption_decryption() {
        let params = TfheParams::default_128bit();
        let sk = TfheSecretKey::generate(&params);
        let pk = TfhePublicKey::from_secret(&sk, &params);

        // Encrypt a 2-bit value (0-3)
        let delta = TfheParams::delta();
        for message in 0..4u64 {
            let plaintext = Plaintext(message * delta);
            let ct = pk.encrypt_lwe(plaintext);

            // Decrypt
            let decrypted = decrypt_lwe_ciphertext(sk.inner(), &ct);

            // Round to nearest message
            let rounded = decrypted.0.wrapping_add(delta / 2) / delta;
            let recovered = rounded & 0b11;

            assert_eq!(
                recovered, message,
                "Failed for message {}: got {}",
                message, recovered
            );
        }
    }
}
