//! Signature serialization tests

use recrypt_core::PreBackend;
use recrypt_core::hybrid::HybridEncryptor;
use recrypt_core::pre::backends::mock::MockBackend;
use recrypt_core::sign::{SigningKeys, VerifyingKeys};
use recrypt_ffi::ed25519::ed25519_keygen;
use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};
use recrypt_proto::format::MultiFormat;

#[test]
fn test_signed_file_protobuf_roundtrip() {
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

    let plaintext = b"Signed serialization test";
    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Serialize to protobuf
    let proto_bytes = encrypted.to_protobuf().unwrap();

    // Deserialize
    let restored = recrypt_core::hybrid::EncryptedFile::from_protobuf(&proto_bytes).unwrap();

    // Signature should be present
    assert!(restored.signature.is_some());

    // Verify and decrypt
    let decrypted = encryptor
        .decrypt_and_verify(&kp.secret, &restored, &verifying_keys)
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_unsigned_file_protobuf_roundtrip() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Unsigned file";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

    // Serialize
    let proto_bytes = encrypted.to_protobuf().unwrap();
    let restored = recrypt_core::hybrid::EncryptedFile::from_protobuf(&proto_bytes).unwrap();

    // Signature should be absent
    assert!(restored.signature.is_none());

    // Can still decrypt
    let decrypted = encryptor.decrypt(&kp.secret, &restored).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_signed_file_size_overhead() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    let signing_keys = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key.clone(),
    };

    let plaintext = b"Size test";
    let unsigned = encryptor.encrypt(&kp.public, plaintext).unwrap();
    let signed = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    let unsigned_bytes = unsigned.to_protobuf().unwrap();
    let signed_bytes = signed.to_protobuf().unwrap();

    let overhead = signed_bytes.len() - unsigned_bytes.len();

    // ML-DSA-87 signature is ~4595 bytes, ED25519 is 64 bytes
    // Total overhead should be around 4.7 KB
    println!(
        "Signature overhead: {} bytes (~{:.1} KB)",
        overhead,
        overhead as f64 / 1024.0
    );
    assert!(
        overhead > 4000 && overhead < 5000,
        "Expected ~4.7KB overhead, got {overhead} bytes"
    );
}
