//! Mock PRE backend for testing
//!
//! NOT SECURE - uses symmetric encryption where "public key" is shared secret.
//! Enables fast iteration without FFI overhead.

use crate::error::{PreError, PreResult};
use crate::pre::*;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

pub struct MockBackend;

impl PreBackend for MockBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Mock
    }

    fn name(&self) -> &'static str {
        "Mock (TESTING ONLY)"
    }

    fn is_post_quantum(&self) -> bool {
        false
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let mut secret_bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let public_bytes = secret_bytes.clone(); // Mock: pk = sk

        Ok(KeyPair {
            public: PublicKey::new(BackendId::Mock, public_bytes),
            secret: SecretKey::new(BackendId::Mock, secret_bytes),
        })
    }

    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey> {
        Ok(PublicKey::new(BackendId::Mock, secret.bytes.clone()))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        // Mock: rk = from_sk XOR to_pk
        let mut rk_bytes = vec![0u8; 32];
        for (i, byte) in rk_bytes.iter_mut().enumerate() {
            *byte = from_secret.bytes[i] ^ to_public.bytes[i];
        }

        Ok(RecryptKey::new(
            BackendId::Mock,
            self.public_key_from_secret(from_secret)?,
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let mut ct = plaintext.to_vec();
        let key: &[u8; 32] = &recipient.bytes[..32]
            .try_into()
            .map_err(|_| PreError::InvalidKey("Mock key must be 32 bytes".into()))?;

        let mut cipher = XChaCha20::new(key.into(), &nonce.into());
        cipher.apply_keystream(&mut ct);

        let mut bytes = nonce.to_vec();
        bytes.extend(ct);

        Ok(Ciphertext::new(BackendId::Mock, 0, bytes))
    }

    fn decrypt(
        &self,
        secret: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> PreResult<Zeroizing<Vec<u8>>> {
        if ciphertext.bytes.len() < 24 {
            return Err(PreError::Decryption("Ciphertext too short".into()));
        }

        let nonce: &[u8; 24] = ciphertext.bytes[..24].try_into().unwrap();
        let mut pt = ciphertext.bytes[24..].to_vec();

        let key: &[u8; 32] = &secret.bytes[..32]
            .try_into()
            .map_err(|_| PreError::InvalidKey("Mock key must be 32 bytes".into()))?;

        let mut cipher = XChaCha20::new(key.into(), nonce.into());
        cipher.apply_keystream(&mut pt);

        Ok(Zeroizing::new(pt))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        // Mock: decrypt with from_sk, re-encrypt with to_pk
        let from_secret_approx: Vec<u8> = recrypt_key
            .bytes
            .iter()
            .zip(recrypt_key.to_public.bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let temp_secret = SecretKey::new(BackendId::Mock, from_secret_approx);
        let plaintext = self.decrypt(&temp_secret, ciphertext)?;

        let mut new_ct = self.encrypt(&recrypt_key.to_public, &plaintext)?;
        new_ct.level = ciphertext.level + 1;

        Ok(new_ct)
    }

    fn max_plaintext_size(&self) -> usize {
        1024 * 1024 // 1 MB
    }

    fn ciphertext_size_estimate(&self, plaintext_size: usize) -> usize {
        plaintext_size + 24 // Just nonce overhead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_encrypt_decrypt() {
        let backend = MockBackend;
        let kp = backend.generate_keypair().unwrap();
        let plaintext = b"Hello, Mock PRE!";

        let ct = backend.encrypt(&kp.public, plaintext).unwrap();
        let pt = backend.decrypt(&kp.secret, &ct).unwrap();

        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn test_mock_recryption() {
        let backend = MockBackend;
        let alice = backend.generate_keypair().unwrap();
        let bob = backend.generate_keypair().unwrap();

        let plaintext = b"Secret for Bob";
        let ct_alice = backend.encrypt(&alice.public, plaintext).unwrap();

        let rk = backend
            .generate_recrypt_key(&alice.secret, &bob.public)
            .unwrap();
        let ct_bob = backend.recrypt(&rk, &ct_alice).unwrap();

        let pt_bob = backend.decrypt(&bob.secret, &ct_bob).unwrap();
        assert_eq!(&pt_bob[..], plaintext);
        assert_eq!(ct_bob.level(), 1);
    }
}
