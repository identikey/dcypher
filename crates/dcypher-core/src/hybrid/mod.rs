//! Hybrid encryption using XChaCha20 + Blake3/Bao

mod encrypted_file;
mod keymaterial;

pub use encrypted_file::EncryptedFile;
pub use keymaterial::KeyMaterial;

use crate::error::{CoreError, CoreResult};
use crate::pre::{PreBackend, PublicKey, RecryptKey, SecretKey};
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Hybrid encryption using PRE for key wrapping + XChaCha20 + Bao
pub struct HybridEncryptor<B: PreBackend> {
    backend: B,
}

impl<B: PreBackend> HybridEncryptor<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Encrypt data for a recipient with streaming-verifiable integrity
    pub fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> CoreResult<EncryptedFile> {
        // Generate random symmetric key and nonce
        let mut sym_key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(sym_key.as_mut());
        OsRng.fill_bytes(&mut nonce);

        // Hash plaintext for post-decryption verification
        let plaintext_hash = blake3::hash(plaintext);
        let plaintext_size = plaintext.len() as u64;

        // Encrypt with XChaCha20
        let mut ciphertext = plaintext.to_vec();
        let mut cipher = XChaCha20::new((&*sym_key).into(), (&nonce).into());
        cipher.apply_keystream(&mut ciphertext);

        // Compute Bao tree for streaming verification
        let (bao_outboard, bao_hash) = bao::encode::outboard(&ciphertext);

        // Bundle key material (plaintext_hash encrypted inside!)
        let key_material = KeyMaterial {
            symmetric_key: *sym_key,
            nonce,
            plaintext_hash: *plaintext_hash.as_bytes(),
            plaintext_size,
        };

        // Wrap entire bundle with PRE
        let wrapped_key = self.backend.encrypt(recipient, &key_material.to_bytes())?;

        Ok(EncryptedFile {
            wrapped_key,
            bao_hash: *bao_hash.as_bytes(),
            bao_outboard,
            ciphertext,
        })
    }

    /// Decrypt and verify integrity
    pub fn decrypt(&self, secret: &SecretKey, file: &EncryptedFile) -> CoreResult<Vec<u8>> {
        // Verify ciphertext integrity via Bao
        let computed_bao = blake3::hash(&file.ciphertext);
        if computed_bao.as_bytes() != &file.bao_hash {
            return Err(CoreError::Decryption(
                "Bao hash mismatch—ciphertext corrupted".into(),
            ));
        }

        // Unwrap key material bundle
        let key_material_bytes = self.backend.decrypt(secret, &file.wrapped_key)?;
        let key_material = KeyMaterial::from_bytes(&key_material_bytes)
            .map_err(|e| CoreError::Decryption(e.to_string()))?;

        // Decrypt with XChaCha20
        let mut plaintext = file.ciphertext.clone();
        let mut cipher = XChaCha20::new(
            (&key_material.symmetric_key).into(),
            (&key_material.nonce).into(),
        );
        cipher.apply_keystream(&mut plaintext);

        // Verify plaintext size
        if plaintext.len() as u64 != key_material.plaintext_size {
            return Err(CoreError::Decryption(format!(
                "Plaintext size mismatch: {} != {}",
                plaintext.len(),
                key_material.plaintext_size
            )));
        }

        // Verify plaintext hash (now decrypted from bundle!)
        let computed_hash = blake3::hash(&plaintext);
        if computed_hash.as_bytes() != &key_material.plaintext_hash {
            return Err(CoreError::Decryption(
                "Plaintext hash mismatch—decryption produced wrong data".into(),
            ));
        }

        Ok(plaintext)
    }

    /// Recrypt for a new recipient
    ///
    /// Only transforms wrapped_key—ciphertext and Bao tree unchanged.
    pub fn recrypt(
        &self,
        recrypt_key: &RecryptKey,
        file: &EncryptedFile,
    ) -> CoreResult<EncryptedFile> {
        let new_wrapped = self.backend.recrypt(recrypt_key, &file.wrapped_key)?;

        Ok(EncryptedFile {
            wrapped_key: new_wrapped,
            bao_hash: file.bao_hash,
            bao_outboard: file.bao_outboard.clone(),
            ciphertext: file.ciphertext.clone(),
        })
    }

    /// Access the underlying PRE backend
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pre::backends::MockBackend;

    #[test]
    fn test_hybrid_encrypt_decrypt() {
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);

        let kp = encryptor.backend().generate_keypair().unwrap();
        let plaintext = b"Hello, hybrid encryption!";

        let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();
        let decrypted = encryptor.decrypt(&kp.secret, &encrypted).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_hybrid_recryption_flow() {
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);

        let alice = encryptor.backend().generate_keypair().unwrap();
        let bob = encryptor.backend().generate_keypair().unwrap();

        let plaintext = b"Secret message for Bob";
        let encrypted_alice = encryptor.encrypt(&alice.public, plaintext).unwrap();

        // Generate recrypt key Alice → Bob
        let rk = encryptor
            .backend()
            .generate_recrypt_key(&alice.secret, &bob.public)
            .unwrap();

        // Proxy transforms
        let encrypted_bob = encryptor.recrypt(&rk, &encrypted_alice).unwrap();

        // Bob decrypts
        let decrypted = encryptor.decrypt(&bob.secret, &encrypted_bob).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_detected() {
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);

        let kp = encryptor.backend().generate_keypair().unwrap();
        let plaintext = b"Integrity test";

        let mut encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Should fail Bao verification
        let result = encryptor.decrypt(&kp.secret, &encrypted);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Bao"));
    }
}
