//! TFHE encryption operations

use tfhe::core_crypto::prelude::*;

use crate::ciphertext::{LweCiphertextChunk, MultiLweCiphertext};
use crate::error::TfheResult;
use crate::keys::TfheSecretKey;
use crate::params::TfheParams;

/// Encrypt a 32-byte symmetric key as 128 × 2-bit LWE ciphertexts
///
/// This is the v1 symmetric encryption that requires the recipient's secret key.
/// Used for establishing correctness before implementing asymmetric encryption.
pub fn encrypt_symmetric_key(
    recipient_secret: &TfheSecretKey,
    plaintext: &[u8; 32],
    params: &TfheParams,
) -> TfheResult<MultiLweCiphertext> {
    let mut seeder = new_seeder();
    let seeder_ref = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

    let delta = TfheParams::delta();
    let mut chunks = Vec::with_capacity(MultiLweCiphertext::CHUNK_COUNT);

    // Encrypt each 2-bit chunk
    for byte_idx in 0..32 {
        let byte = plaintext[byte_idx];

        // 4 chunks per byte (2 bits each)
        for chunk_idx in 0..4 {
            let shift = chunk_idx * 2;
            let two_bits = ((byte >> shift) & 0b11) as u64;

            // Scale plaintext by delta to place it in the upper bits
            let plaintext_val = Plaintext(two_bits * delta);

            // Allocate and encrypt using TFHE's standard encryption
            let lwe_ct: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
                recipient_secret.inner(),
                plaintext_val,
                params.lwe_noise_distribution,
                params.ciphertext_modulus,
                &mut encryption_generator,
            );

            chunks.push(LweCiphertextChunk::from_lwe(&lwe_ct));
        }
    }

    Ok(MultiLweCiphertext { chunks })
}
