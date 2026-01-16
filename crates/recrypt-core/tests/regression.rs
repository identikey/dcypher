//! Known-answer tests for regression detection
//!
//! These use deterministic tests to detect implementation changes.

use recrypt_core::pre::backends::MockBackend;
use recrypt_core::*;

#[test]
fn test_fixed_key_encrypt_decrypt() {
    // Use mock backend with deterministic keys
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);

    // Fixed keypair (mock backend: pk = sk)
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Known plaintext for regression test";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();
    let decrypted = encryptor.decrypt(&kp.secret, &encrypted).unwrap();

    assert_eq!(&decrypted[..], plaintext);

    // Note: We don't check ciphertext bytes (non-deterministic)
    // Only verify semantic correctness
}

#[test]
fn test_recryption_level_tracking() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);

    let alice = encryptor.backend().generate_keypair().unwrap();
    let bob = encryptor.backend().generate_keypair().unwrap();
    let carol = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Multi-hop recryption test";

    // Alice encrypts
    let ct0 = encryptor.encrypt(&alice.public, plaintext).unwrap();
    assert_eq!(ct0.wrapped_key.level(), 0);

    // Recrypt Alice → Bob
    let rk_ab = encryptor
        .backend()
        .generate_recrypt_key(&alice.secret, &bob.public)
        .unwrap();
    let ct1 = encryptor.recrypt(&rk_ab, &ct0).unwrap();
    assert_eq!(ct1.wrapped_key.level(), 1);

    // Recrypt Bob → Carol
    let rk_bc = encryptor
        .backend()
        .generate_recrypt_key(&bob.secret, &carol.public)
        .unwrap();
    let ct2 = encryptor.recrypt(&rk_bc, &ct1).unwrap();
    assert_eq!(ct2.wrapped_key.level(), 2);

    // Carol decrypts
    let decrypted = encryptor.decrypt(&carol.secret, &ct2).unwrap();
    assert_eq!(&decrypted[..], plaintext);
}
