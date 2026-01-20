//! TFHE security parameters targeting 128-bit security

use tfhe::core_crypto::prelude::*;

/// TFHE parameters targeting 128-bit security
/// Based on standard LWE estimator recommendations
#[derive(Clone, Debug)]
pub struct TfheParams {
    /// LWE dimension (n)
    pub lwe_dimension: LweDimension,
    /// Gaussian noise distribution
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    /// Decomposition base log for key switching
    pub decomp_base_log: DecompositionBaseLog,
    /// Number of decomposition levels for key switching
    pub decomp_level_count: DecompositionLevelCount,
    /// Ciphertext modulus (native u64)
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

impl TfheParams {
    /// Default params: 128-bit security, 1-2 hop support
    pub fn default_128bit() -> Self {
        Self {
            lwe_dimension: LweDimension(742),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                0.000007069849454709433,
            )),
            decomp_base_log: DecompositionBaseLog(4),
            decomp_level_count: DecompositionLevelCount(9),
            ciphertext_modulus: CiphertextModulus::new_native(),
        }
    }

    /// 2-bit message space (0-3)
    pub fn message_modulus() -> u64 {
        4
    }

    /// Delta for 2-bit encoding in u64 torus
    /// Places the 2-bit message in the top 2 bits of u64
    pub fn delta() -> u64 {
        1u64 << 62 // Top 2 bits: u64::MAX / 4 + 1
    }
}

impl Default for TfheParams {
    fn default() -> Self {
        Self::default_128bit()
    }
}
