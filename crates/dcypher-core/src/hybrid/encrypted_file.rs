//! Encrypted file structure (implementation in Phase 2.4)

use crate::pre::Ciphertext;

/// An encrypted file with streaming-verifiable integrity
#[derive(Clone, Debug)]
pub struct EncryptedFile {
    /// PRE-encrypted key bundle (contains: key, nonce, plaintext_hash, size)
    pub wrapped_key: Ciphertext,

    /// Bao root hash of ciphertext (for streaming verification)
    pub bao_hash: [u8; 32],

    /// Bao outboard data (verification tree, ~1% of ciphertext size)
    pub bao_outboard: Vec<u8>,

    /// XChaCha20-encrypted data (no auth tag—Bao provides integrity)
    pub ciphertext: Vec<u8>,
}

impl EncryptedFile {
    /// Serialize to bytes (simplified—full wire format in Phase 3)
    pub fn to_bytes(&self) -> Vec<u8> {
        let wrapped = self.wrapped_key.to_bytes();
        let mut out = Vec::new();

        // Version
        out.push(2u8);

        // Wrapped key
        out.extend((wrapped.len() as u32).to_le_bytes());
        out.extend(&wrapped);

        // Bao hash
        out.extend(&self.bao_hash);
        out.extend((self.bao_outboard.len() as u64).to_le_bytes());
        out.extend(&self.bao_outboard);

        // Ciphertext
        out.extend((self.ciphertext.len() as u64).to_le_bytes());
        out.extend(&self.ciphertext);

        out
    }
}
