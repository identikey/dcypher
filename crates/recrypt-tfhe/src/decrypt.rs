//! TFHE decryption operations

use tfhe::core_crypto::prelude::*;
use zeroize::Zeroizing;

use crate::ciphertext::MultiLweCiphertext;
use crate::error::{TfheError, TfheResult};
use crate::keys::TfheSecretKey;
use crate::params::TfheParams;

/// Decrypt a multi-LWE ciphertext back to a 32-byte symmetric key
pub fn decrypt_symmetric_key(
    secret: &TfheSecretKey,
    ciphertext: &MultiLweCiphertext,
    params: &TfheParams,
) -> TfheResult<Zeroizing<Vec<u8>>> {
    if ciphertext.chunks.len() != MultiLweCiphertext::CHUNK_COUNT {
        return Err(TfheError::Decryption(format!(
            "Expected {} chunks, got {}",
            MultiLweCiphertext::CHUNK_COUNT,
            ciphertext.chunks.len()
        )));
    }

    let delta = TfheParams::delta();
    let mut plaintext_bytes = Zeroizing::new(vec![0u8; 32]);

    for byte_idx in 0..32 {
        let mut byte_val = 0u8;

        for chunk_idx in 0..4 {
            let chunk_global_idx = byte_idx * 4 + chunk_idx;
            let chunk = &ciphertext.chunks[chunk_global_idx];

            // Convert to full LWE ciphertext
            let full_ct = chunk.to_lwe(params.ciphertext_modulus);

            // Decrypt: compute b - <a, s>
            let decrypted = decrypt_lwe_ciphertext(secret.inner(), &full_ct);

            // Round to nearest 2-bit value
            let two_bits = decode_2bit(decrypted.0, delta);

            byte_val |= (two_bits & 0b11) << (chunk_idx * 2);
        }

        plaintext_bytes[byte_idx] = byte_val;
    }

    Ok(plaintext_bytes)
}

/// Decode a 2-bit value from a noisy decryption result
///
/// The plaintext was encoded as `m * delta` where delta = 2^62.
/// After decryption, we have `m * delta + noise`.
/// We round to the nearest multiple of delta to recover m.
fn decode_2bit(noisy_value: u64, delta: u64) -> u8 {
    // Add delta/2 for rounding, then divide by delta
    let rounded = noisy_value.wrapping_add(delta / 2) / delta;
    // Mask to 2 bits (0-3)
    (rounded & 0b11) as u8
}
