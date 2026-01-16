// Basic hybrid encryption/decryption

use recrypt_core::{HybridEncryptor, pre::PreBackend, pre::backends::MockBackend};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 dCypher: Basic Encryption Demo");
    println!("   (MockBackend - production will use LatticeBackend)\n");

    let encryptor = HybridEncryptor::new(MockBackend);

    // Generate keypair
    println!("1️⃣  Generating keypair...");
    let keypair = encryptor.backend().generate_keypair()?;
    println!("   ✓ Keypair ready\n");

    // Encrypt some data
    let messages = vec![
        b"Hello, dCypher!" as &[u8],
        b"Short msg",
        b"This is a longer message with more bytes to test the hybrid encryption system.",
    ];

    for (i, msg) in messages.iter().enumerate() {
        println!(
            "{}️⃣  Encrypting: {:?}",
            i + 2,
            std::str::from_utf8(msg).unwrap()
        );

        let encrypted = encryptor.encrypt(&keypair.public, msg)?;
        println!(
            "   ✓ Encrypted: {} bytes plaintext → {} bytes ciphertext + {} bytes Bao outboard",
            msg.len(),
            encrypted.ciphertext.len(),
            encrypted.bao_outboard.len()
        );

        let decrypted = encryptor.decrypt(&keypair.secret, &encrypted)?;
        println!(
            "   ✓ Decrypted: {:?}",
            std::str::from_utf8(&decrypted).unwrap()
        );

        assert_eq!(&decrypted[..], *msg);
        println!("   ✓ Verified!\n");
    }

    println!("✅ All encryption/decryption cycles successful!");

    Ok(())
}
