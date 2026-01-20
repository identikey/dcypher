//! Roundtrip encryption tests for TFHE

use recrypt_tfhe::{decrypt_symmetric_key, encrypt_symmetric_key, TfheParams, TfheSecretKey};

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let params = TfheParams::default_128bit();
    let secret_key = TfheSecretKey::generate(&params);

    // Test with a known plaintext
    let plaintext: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    // Encrypt
    let ciphertext = encrypt_symmetric_key(&secret_key, &plaintext, &params)
        .expect("Encryption should succeed");

    // Decrypt
    let decrypted = decrypt_symmetric_key(&secret_key, &ciphertext, &params)
        .expect("Decryption should succeed");

    // Verify
    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Decrypted plaintext should match original"
    );
}

#[test]
fn test_encrypt_decrypt_all_zeros() {
    let params = TfheParams::default_128bit();
    let secret_key = TfheSecretKey::generate(&params);

    let plaintext = [0u8; 32];

    let ciphertext = encrypt_symmetric_key(&secret_key, &plaintext, &params)
        .expect("Encryption should succeed");

    let decrypted = decrypt_symmetric_key(&secret_key, &ciphertext, &params)
        .expect("Decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Decrypted plaintext should match original"
    );
}

#[test]
fn test_encrypt_decrypt_all_ones() {
    let params = TfheParams::default_128bit();
    let secret_key = TfheSecretKey::generate(&params);

    let plaintext = [0xffu8; 32];

    let ciphertext = encrypt_symmetric_key(&secret_key, &plaintext, &params)
        .expect("Encryption should succeed");

    let decrypted = decrypt_symmetric_key(&secret_key, &ciphertext, &params)
        .expect("Decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Decrypted plaintext should match original"
    );
}

#[test]
fn test_encrypt_decrypt_random() {
    use rand::RngCore;

    let params = TfheParams::default_128bit();
    let secret_key = TfheSecretKey::generate(&params);

    // Test with random plaintext
    let mut plaintext = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut plaintext);

    let ciphertext = encrypt_symmetric_key(&secret_key, &plaintext, &params)
        .expect("Encryption should succeed");

    let decrypted = decrypt_symmetric_key(&secret_key, &ciphertext, &params)
        .expect("Decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Decrypted plaintext should match original"
    );
}

#[test]
fn test_secret_key_serialization() {
    let params = TfheParams::default_128bit();
    let secret_key = TfheSecretKey::generate(&params);

    // Serialize
    let bytes = secret_key.to_bytes();

    // Deserialize
    let restored = TfheSecretKey::from_bytes(&bytes).expect("Deserialization should succeed");

    // Verify by encrypting/decrypting with restored key
    let plaintext = [0x42u8; 32];
    let ciphertext =
        encrypt_symmetric_key(&secret_key, &plaintext, &params).expect("Encryption should succeed");

    let decrypted = decrypt_symmetric_key(&restored, &ciphertext, &params)
        .expect("Decryption with restored key should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Key serialization should preserve functionality"
    );
}

#[test]
fn test_ciphertext_serialization() {
    use recrypt_tfhe::MultiLweCiphertext;

    let params = TfheParams::default_128bit();
    let secret_key = TfheSecretKey::generate(&params);
    let plaintext = [0x42u8; 32];

    let ciphertext = encrypt_symmetric_key(&secret_key, &plaintext, &params)
        .expect("Encryption should succeed");

    // Serialize
    let bytes = ciphertext.to_bytes();

    // Deserialize
    let restored = MultiLweCiphertext::from_bytes(&bytes).expect("Deserialization should succeed");

    // Verify decryption still works
    let decrypted = decrypt_symmetric_key(&secret_key, &restored, &params)
        .expect("Decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Ciphertext serialization should preserve decryptability"
    );
}
