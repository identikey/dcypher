//! Recryption (key switching) tests for TFHE

use recrypt_tfhe::{
    decrypt_symmetric_key, encrypt_symmetric_key, recrypt, TfheParams, TfheRecryptKey,
    TfheSecretKey,
};

#[test]
fn test_alice_to_bob_recryption() {
    let params = TfheParams::default_128bit();

    // Generate keys for Alice and Bob
    let alice_sk = TfheSecretKey::generate(&params);
    let bob_sk = TfheSecretKey::generate(&params);

    let plaintext = [0x42u8; 32];

    // Alice encrypts
    let ct_alice =
        encrypt_symmetric_key(&alice_sk, &plaintext, &params).expect("Encryption should succeed");

    // Generate recryption key (v1: requires both secrets)
    let rk = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);

    // Proxy recrypts
    let ct_bob = recrypt(&rk, &ct_alice, &params).expect("Recryption should succeed");

    // Bob decrypts
    let decrypted =
        decrypt_symmetric_key(&bob_sk, &ct_bob, &params).expect("Decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Bob should be able to decrypt recrypted ciphertext"
    );
}

#[test]
fn test_recryption_different_messages() {
    use rand::RngCore;

    let params = TfheParams::default_128bit();
    let alice_sk = TfheSecretKey::generate(&params);
    let bob_sk = TfheSecretKey::generate(&params);

    // Test several different messages
    for _ in 0..3 {
        let mut plaintext = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext);

        let ct_alice = encrypt_symmetric_key(&alice_sk, &plaintext, &params)
            .expect("Encryption should succeed");

        let rk = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);

        let ct_bob = recrypt(&rk, &ct_alice, &params).expect("Recryption should succeed");

        let decrypted =
            decrypt_symmetric_key(&bob_sk, &ct_bob, &params).expect("Decryption should succeed");

        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "Recryption should preserve message"
        );
    }
}

#[test]
fn test_two_hop_recryption() {
    let params = TfheParams::default_128bit();

    // Generate keys for Alice, Bob, and Carol
    let alice_sk = TfheSecretKey::generate(&params);
    let bob_sk = TfheSecretKey::generate(&params);
    let carol_sk = TfheSecretKey::generate(&params);

    let plaintext = [0x42u8; 32];

    // Alice encrypts
    let ct_alice =
        encrypt_symmetric_key(&alice_sk, &plaintext, &params).expect("Encryption should succeed");

    // Recrypt Alice -> Bob
    let rk_ab = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);
    let ct_bob = recrypt(&rk_ab, &ct_alice, &params).expect("Recryption A->B should succeed");

    // Recrypt Bob -> Carol
    let rk_bc = TfheRecryptKey::generate_symmetric(&bob_sk, &carol_sk, &params);
    let ct_carol = recrypt(&rk_bc, &ct_bob, &params).expect("Recryption B->C should succeed");

    // Carol decrypts
    let decrypted = decrypt_symmetric_key(&carol_sk, &ct_carol, &params)
        .expect("Carol's decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Carol should be able to decrypt after 2 hops"
    );
}

#[test]
fn test_recrypt_key_serialization() {
    let params = TfheParams::default_128bit();
    let alice_sk = TfheSecretKey::generate(&params);
    let bob_sk = TfheSecretKey::generate(&params);

    let rk = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);

    // Serialize
    let bytes = rk.to_bytes();

    // Deserialize
    let restored =
        TfheRecryptKey::from_bytes(&bytes, &params).expect("Deserialization should succeed");

    // Verify by using restored key
    let plaintext = [0x42u8; 32];
    let ct_alice =
        encrypt_symmetric_key(&alice_sk, &plaintext, &params).expect("Encryption should succeed");

    let ct_bob =
        recrypt(&restored, &ct_alice, &params).expect("Recryption with restored key should succeed");

    let decrypted =
        decrypt_symmetric_key(&bob_sk, &ct_bob, &params).expect("Decryption should succeed");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Recrypt key serialization should preserve functionality"
    );
}

#[test]
fn test_wrong_key_cannot_decrypt() {
    let params = TfheParams::default_128bit();

    let alice_sk = TfheSecretKey::generate(&params);
    let bob_sk = TfheSecretKey::generate(&params);
    let eve_sk = TfheSecretKey::generate(&params);

    let plaintext = [0x42u8; 32];

    // Alice encrypts
    let ct_alice =
        encrypt_symmetric_key(&alice_sk, &plaintext, &params).expect("Encryption should succeed");

    // Recrypt to Bob
    let rk = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);
    let ct_bob = recrypt(&rk, &ct_alice, &params).expect("Recryption should succeed");

    // Eve tries to decrypt (should fail - decryption will return wrong data)
    let eve_decrypted = decrypt_symmetric_key(&eve_sk, &ct_bob, &params)
        .expect("Decryption operation should succeed");

    // Eve's decryption should NOT match the plaintext
    assert_ne!(
        &eve_decrypted[..],
        &plaintext[..],
        "Eve should not be able to decrypt Bob's ciphertext"
    );
}
