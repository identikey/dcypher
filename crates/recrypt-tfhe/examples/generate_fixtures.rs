//! Generate pre-computed key fixtures for testing
//!
//! Run with: cargo run --example generate_fixtures --release -p recrypt-tfhe
//!
//! This generates:
//! - Alice's keypair (secret + public)
//! - Bob's keypair (secret + public)
//! - Alice->Bob recrypt key (asymmetric)
//!
//! Keys are saved to crates/recrypt-tfhe/fixtures/

use std::fs;
use std::path::Path;
use std::time::Instant;

fn main() {
    println!("Generating TFHE Key Fixtures");
    println!("============================\n");

    let params = recrypt_tfhe::TfheParams::default_128bit();
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");

    // Ensure fixtures directory exists
    fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures directory");

    // Generate Alice's keypair
    println!("Generating Alice's secret key...");
    let start = Instant::now();
    let alice_sk = recrypt_tfhe::TfheSecretKey::generate(&params);
    println!("  Secret key generated in {:.2?}", start.elapsed());

    println!("Generating Alice's public key (this takes ~6 seconds)...");
    let start = Instant::now();
    let alice_pk = recrypt_tfhe::TfhePublicKey::from_secret(&alice_sk, &params);
    println!("  Public key generated in {:.2?}", start.elapsed());
    println!("  Zero encryption count: {}", alice_pk.encryption_count());

    // Generate Bob's keypair
    println!("\nGenerating Bob's secret key...");
    let start = Instant::now();
    let bob_sk = recrypt_tfhe::TfheSecretKey::generate(&params);
    println!("  Secret key generated in {:.2?}", start.elapsed());

    println!("Generating Bob's public key (this takes ~6 seconds)...");
    let start = Instant::now();
    let bob_pk = recrypt_tfhe::TfhePublicKey::from_secret(&bob_sk, &params);
    println!("  Public key generated in {:.2?}", start.elapsed());
    println!("  Zero encryption count: {}", bob_pk.encryption_count());

    // Generate Alice->Bob recrypt key
    println!("\nGenerating Alice->Bob recrypt key...");
    let start = Instant::now();
    let rk_alice_bob =
        recrypt_tfhe::TfheRecryptKey::generate_asymmetric(&alice_sk, &bob_pk, &params);
    println!("  Recrypt key generated in {:.2?}", start.elapsed());

    // Save all keys
    println!("\nSaving keys to {:?}...", fixtures_dir);

    fs::write(fixtures_dir.join("alice_sk.bin"), alice_sk.to_bytes())
        .expect("Failed to write alice_sk");
    fs::write(fixtures_dir.join("alice_pk.bin"), alice_pk.to_bytes())
        .expect("Failed to write alice_pk");
    fs::write(fixtures_dir.join("bob_sk.bin"), bob_sk.to_bytes())
        .expect("Failed to write bob_sk");
    fs::write(fixtures_dir.join("bob_pk.bin"), bob_pk.to_bytes())
        .expect("Failed to write bob_pk");
    fs::write(fixtures_dir.join("rk_alice_bob.bin"), rk_alice_bob.to_bytes())
        .expect("Failed to write rk_alice_bob");

    // Print sizes
    println!("\nFixture sizes:");
    println!(
        "  alice_sk.bin: {} bytes ({:.2} KB)",
        alice_sk.to_bytes().len(),
        alice_sk.to_bytes().len() as f64 / 1024.0
    );
    println!(
        "  alice_pk.bin: {} bytes ({:.2} MB)",
        alice_pk.to_bytes().len(),
        alice_pk.to_bytes().len() as f64 / 1024.0 / 1024.0
    );
    println!(
        "  bob_sk.bin: {} bytes ({:.2} KB)",
        bob_sk.to_bytes().len(),
        bob_sk.to_bytes().len() as f64 / 1024.0
    );
    println!(
        "  bob_pk.bin: {} bytes ({:.2} MB)",
        bob_pk.to_bytes().len(),
        bob_pk.to_bytes().len() as f64 / 1024.0 / 1024.0
    );
    println!(
        "  rk_alice_bob.bin: {} bytes ({:.2} MB)",
        rk_alice_bob.to_bytes().len(),
        rk_alice_bob.to_bytes().len() as f64 / 1024.0 / 1024.0
    );

    // Verify the fixtures work
    println!("\nVerifying fixtures...");

    let plaintext = [0xABu8; 32];

    // Encrypt with Alice's public key
    let ct = recrypt_tfhe::encrypt_with_public_key(&alice_pk, &plaintext, &params)
        .expect("Encryption failed");

    // Decrypt with Alice's secret key (should work)
    let decrypted = recrypt_tfhe::decrypt_symmetric_key(&alice_sk, &ct, &params)
        .expect("Decryption failed");
    assert_eq!(&decrypted[..], &plaintext[..], "Direct decrypt failed!");
    println!("  Direct encryption/decryption: OK");

    // Recrypt for Bob
    let ct_bob = recrypt_tfhe::recrypt(&rk_alice_bob, &ct, &params).expect("Recryption failed");

    // Bob decrypts
    let decrypted_bob = recrypt_tfhe::decrypt_symmetric_key(&bob_sk, &ct_bob, &params)
        .expect("Bob's decryption failed");
    assert_eq!(
        &decrypted_bob[..],
        &plaintext[..],
        "Recryption/decrypt failed!"
    );
    println!("  Recryption and decryption: OK");

    println!("\nAll fixtures generated and verified successfully!");
}
