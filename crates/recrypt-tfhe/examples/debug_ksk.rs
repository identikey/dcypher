//! Debug KSK generation by comparing symmetric vs asymmetric
//!
//! Run with: cargo run --example debug_ksk --release -p recrypt-tfhe

use std::time::Instant;
use recrypt_tfhe::{TfheParams, TfheSecretKey, TfhePublicKey, TfheRecryptKey};
use recrypt_tfhe::{encrypt_with_public_key, decrypt_symmetric_key, recrypt};

fn main() {
    println!("Debug KSK Generation");
    println!("====================\n");

    let params = TfheParams::default_128bit();

    // Generate keys
    println!("Generating keys (this will take a while)...");
    let start = Instant::now();
    let alice_sk = TfheSecretKey::generate(&params);
    let alice_pk = TfhePublicKey::from_secret(&alice_sk, &params);
    let bob_sk = TfheSecretKey::generate(&params);
    let bob_pk = TfhePublicKey::from_secret(&bob_sk, &params);
    println!("Keys generated in {:.2?}\n", start.elapsed());

    // Test symmetric KSK (should work)
    println!("Testing SYMMETRIC KSK...");
    let start = Instant::now();
    let rk_sym = TfheRecryptKey::generate_symmetric(&alice_sk, &bob_sk, &params);
    println!("Symmetric KSK generated in {:.2?}", start.elapsed());

    let plaintext = [0xABu8; 32];
    let ct = encrypt_with_public_key(&alice_pk, &plaintext, &params).unwrap();

    // Direct decrypt (should work)
    let dec = decrypt_symmetric_key(&alice_sk, &ct, &params).unwrap();
    println!("Direct decrypt: {}", if &dec[..] == &plaintext[..] { "OK" } else { "FAIL" });

    // Recrypt with symmetric KSK
    let ct_bob_sym = recrypt(&rk_sym, &ct, &params).unwrap();
    let dec_bob_sym = decrypt_symmetric_key(&bob_sk, &ct_bob_sym, &params).unwrap();
    println!("Symmetric recrypt: {}", if &dec_bob_sym[..] == &plaintext[..] { "OK" } else { "FAIL" });

    // Test asymmetric KSK
    println!("\nTesting ASYMMETRIC KSK...");
    let start = Instant::now();
    let rk_asym = TfheRecryptKey::generate_asymmetric(&alice_sk, &bob_pk, &params);
    println!("Asymmetric KSK generated in {:.2?}", start.elapsed());

    // Recrypt with asymmetric KSK
    let ct_bob_asym = recrypt(&rk_asym, &ct, &params).unwrap();
    let dec_bob_asym = decrypt_symmetric_key(&bob_sk, &ct_bob_asym, &params).unwrap();

    if &dec_bob_asym[..] == &plaintext[..] {
        println!("Asymmetric recrypt: OK");
    } else {
        println!("Asymmetric recrypt: FAIL");
        println!("  Expected: {:?}", &plaintext[..8]);
        println!("  Got:      {:?}", &dec_bob_asym[..8]);

        // Count matching bytes
        let matching = plaintext.iter().zip(dec_bob_asym.iter())
            .filter(|(a, b)| a == b)
            .count();
        println!("  Matching bytes: {}/32", matching);
    }

    // Let's try testing with a simple single-chunk encrypt and keyswitch
    println!("\nTesting single-bit keyswitch...");

    // Encrypt a single 2-bit value (just message 0)
    let single_plaintext = [0u8; 32];
    let ct_single = encrypt_with_public_key(&alice_pk, &single_plaintext, &params).unwrap();

    // Direct decrypt should give zeros
    let dec_single = decrypt_symmetric_key(&alice_sk, &ct_single, &params).unwrap();
    let zeros_match = dec_single.iter().all(|&b| b == 0);
    println!("Direct decrypt zeros: {}", if zeros_match { "OK" } else { "FAIL" });

    // Symmetric recrypt of zeros
    let ct_single_sym = recrypt(&rk_sym, &ct_single, &params).unwrap();
    let dec_single_sym = decrypt_symmetric_key(&bob_sk, &ct_single_sym, &params).unwrap();
    let zeros_sym_match = dec_single_sym.iter().all(|&b| b == 0);
    println!("Symmetric recrypt zeros: {}", if zeros_sym_match { "OK" } else { "FAIL" });

    // Asymmetric recrypt of zeros
    let ct_single_asym = recrypt(&rk_asym, &ct_single, &params).unwrap();
    let dec_single_asym = decrypt_symmetric_key(&bob_sk, &ct_single_asym, &params).unwrap();
    let zeros_asym_match = dec_single_asym.iter().all(|&b| b == 0);
    if zeros_asym_match {
        println!("Asymmetric recrypt zeros: OK");
    } else {
        println!("Asymmetric recrypt zeros: FAIL");
        println!("  Got: {:?}", &dec_single_asym[..8]);
    }
}
