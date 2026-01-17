// Alice→Bob→Carol recryption flow demonstration

use recrypt_core::{HybridEncryptor, pre::PreBackend, pre::backends::MockBackend};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Recrypt: Alice → Bob → Carol Recryption Demo");
    println!("   (MockBackend - production will use LatticeBackend)\n");

    // Initialize with MockBackend (LatticeBackend needs serialization from Phase 3)
    let encryptor = HybridEncryptor::new(MockBackend);

    // 1. Generate keypairs for Alice, Bob, and Carol
    println!("1️⃣  Generating keypairs...");
    let alice_kp = encryptor.backend().generate_keypair()?;
    let bob_kp = encryptor.backend().generate_keypair()?;
    let carol_kp = encryptor.backend().generate_keypair()?;
    println!("   ✓ Alice, Bob, and Carol have keypairs\n");

    // 2. Alice encrypts data
    let plaintext = b"The secret is: Recrypt rules!";
    println!(
        "2️⃣  Alice encrypts: {:?}",
        std::str::from_utf8(plaintext).unwrap()
    );
    let encrypted_for_alice = encryptor.encrypt(&alice_kp.public, plaintext)?;
    println!(
        "   ✓ Encrypted ({} bytes)\n",
        encrypted_for_alice.ciphertext.len()
    );

    // 3. Alice can decrypt her own data
    println!("3️⃣  Alice decrypts her own data...");
    let decrypted_by_alice = encryptor.decrypt(&alice_kp.secret, &encrypted_for_alice)?;
    println!(
        "   ✓ Alice sees: {:?}\n",
        std::str::from_utf8(&decrypted_by_alice).unwrap()
    );

    // 4. Alice generates recryption key: Alice → Bob
    println!("4️⃣  Alice generates recryption key for Bob...");
    let alice_to_bob_rk = encryptor
        .backend()
        .generate_recrypt_key(&alice_kp.secret, &bob_kp.public)?;
    println!("   ✓ Recryption key created\n");

    // 5. Proxy recrypts: Alice's ciphertext → Bob's ciphertext
    println!("5️⃣  Proxy recrypts Alice's ciphertext for Bob...");
    let encrypted_for_bob = encryptor.recrypt(&alice_to_bob_rk, &encrypted_for_alice)?;
    println!("   ✓ Recrypted for Bob\n");

    // 6. Bob decrypts
    println!("6️⃣  Bob decrypts...");
    let decrypted_by_bob = encryptor.decrypt(&bob_kp.secret, &encrypted_for_bob)?;
    println!(
        "   ✓ Bob sees: {:?}\n",
        std::str::from_utf8(&decrypted_by_bob).unwrap()
    );

    // 7. Bob generates recryption key: Bob → Carol
    println!("7️⃣  Bob generates recryption key for Carol...");
    let bob_to_carol_rk = encryptor
        .backend()
        .generate_recrypt_key(&bob_kp.secret, &carol_kp.public)?;
    println!("   ✓ Recryption key created\n");

    // 8. Proxy recrypts again: Bob's ciphertext → Carol's ciphertext
    println!("8️⃣  Proxy recrypts Bob's ciphertext for Carol...");
    let encrypted_for_carol = encryptor.recrypt(&bob_to_carol_rk, &encrypted_for_bob)?;
    println!("   ✓ Recrypted for Carol\n");

    // 9. Carol decrypts
    println!("9️⃣  Carol decrypts...");
    let decrypted_by_carol = encryptor.decrypt(&carol_kp.secret, &encrypted_for_carol)?;
    println!(
        "   ✓ Carol sees: {:?}\n",
        std::str::from_utf8(&decrypted_by_carol).unwrap()
    );

    // Verification
    println!("✅ Verification:");
    assert_eq!(&decrypted_by_alice[..], plaintext);
    assert_eq!(&decrypted_by_bob[..], plaintext);
    assert_eq!(&decrypted_by_carol[..], plaintext);
    println!("   All three parties see the same plaintext!");
    println!("   Alice → Bob → Carol recryption: SUCCESS 🎉");

    Ok(())
}
