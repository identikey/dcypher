//! TFHE recryption (key switching) operation

use tfhe::core_crypto::prelude::*;

use crate::ciphertext::{LweCiphertextChunk, MultiLweCiphertext};
use crate::error::TfheResult;
use crate::keys::TfheRecryptKey;
use crate::params::TfheParams;

/// Recrypt (key switch) a multi-LWE ciphertext from one key to another
///
/// This transforms ciphertexts encrypted under Alice's key into ciphertexts
/// decryptable by Bob, without decrypting or revealing the plaintext.
pub fn recrypt(
    recrypt_key: &TfheRecryptKey,
    ciphertext: &MultiLweCiphertext,
    params: &TfheParams,
) -> TfheResult<MultiLweCiphertext> {
    let mut recrypted_chunks = Vec::with_capacity(ciphertext.chunks.len());

    for chunk in &ciphertext.chunks {
        // Convert to full input ciphertext
        let full_ct = chunk.to_lwe(params.ciphertext_modulus);

        // Allocate output ciphertext
        let mut output_ct = LweCiphertext::new(
            0u64,
            recrypt_key.output_dimension().to_lwe_size(),
            params.ciphertext_modulus,
        );

        // Perform key switching
        keyswitch_lwe_ciphertext(recrypt_key.inner(), &full_ct, &mut output_ct);

        // Store the full recrypted ciphertext
        recrypted_chunks.push(LweCiphertextChunk::from_lwe(&output_ct));
    }

    Ok(MultiLweCiphertext {
        chunks: recrypted_chunks,
    })
}
