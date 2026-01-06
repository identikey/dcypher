//! Signature integration tests

use dcypher_core::PreBackend;
use dcypher_core::hybrid::HybridEncryptor;
use dcypher_core::pre::backends::mock::MockBackend;
use dcypher_core::sign::{SigningKeys, VerifyingKeys};
use dcypher_ffi::ed25519::ed25519_keygen;
use dcypher_ffi::liboqs::{PqAlgorithm, pq_keygen};

#[test]
fn test_sign_and_verify() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    // Generate signing keys
    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    let signing_keys = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key.clone(),
    };

    let verifying_keys = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: pq_kp.public_key.clone(),
    };

    // Encrypt and sign
    let plaintext = b"Signed message test";
    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Verify signature is present
    assert!(encrypted.signature.is_some());

    // Decrypt with verification
    let decrypted = encryptor
        .decrypt_and_verify(&kp.secret, &encrypted, &verifying_keys)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_tampered_wrapped_key_detected() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    let signing_keys = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key.clone(),
    };

    let verifying_keys = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: pq_kp.public_key.clone(),
    };

    let plaintext = b"Integrity test";
    let mut encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Tamper with wrapped_key (part of signature payload)
    let tampered_bytes = vec![0u8; encrypted.wrapped_key.as_bytes().len()];
    encrypted.wrapped_key = dcypher_core::pre::Ciphertext::new(
        encrypted.wrapped_key.backend(),
        encrypted.wrapped_key.level(),
        tampered_bytes,
    );

    // Signature verification should fail
    let result = encryptor.decrypt_and_verify(&kp.secret, &encrypted, &verifying_keys);
    assert!(result.is_err());
}

#[test]
fn test_tampered_bao_hash_detected() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    let signing_keys = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key.clone(),
    };

    let verifying_keys = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: pq_kp.public_key.clone(),
    };

    let plaintext = b"Hash tampering test";
    let mut encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Tamper with bao_hash (part of signature payload)
    encrypted.bao_hash = [0u8; 32];

    // Signature verification should fail
    let result = encryptor.decrypt_and_verify(&kp.secret, &encrypted, &verifying_keys);
    assert!(result.is_err());
}

#[test]
fn test_wrong_verifying_key() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let ed_kp1 = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    let signing_keys = SigningKeys {
        ed25519: ed_kp1.signing_key,
        ml_dsa: pq_kp.secret_key.clone(),
    };

    // Different verifying key
    let ed_kp2 = ed25519_keygen();
    let wrong_verifying_keys = VerifyingKeys {
        ed25519: ed_kp2.verifying_key,
        ml_dsa: pq_kp.public_key.clone(),
    };

    let plaintext = b"Wrong key test";
    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Verification should fail with wrong key
    let result = encryptor.decrypt_and_verify(&kp.secret, &encrypted, &wrong_verifying_keys);
    assert!(result.is_err());
}
