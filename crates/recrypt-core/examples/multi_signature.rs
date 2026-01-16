// Multi-signature (ED25519 + ML-DSA-87) demonstration

use recrypt_core::sign::{SigningKeys, VerifyingKeys, sign_message, verify_message};
use recrypt_ffi::ed25519::ed25519_keygen;
use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 dCypher: Multi-Signature Demo");
    println!("   (ED25519 Classical + ML-DSA-87 Post-Quantum)\n");

    // Generate signing keys
    println!("1️⃣  Generating signing keys...");
    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87)?;
    let signing_keys = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key.clone(),
    };
    let verifying_keys = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: pq_kp.public_key.clone(),
    };
    println!(
        "   ✓ Keys ready (ED25519: 32 bytes, ML-DSA-87: {} bytes)\n",
        verifying_keys.ml_dsa.len()
    );

    // Sign various messages
    let messages = vec![
        b"Transfer $100 to Bob" as &[u8],
        b"Approve document #42",
        b"Revoke access for user@example.com",
    ];

    for (i, msg) in messages.iter().enumerate() {
        println!(
            "{}️⃣  Signing: {:?}",
            i + 2,
            std::str::from_utf8(msg).unwrap()
        );

        let multi_sig = sign_message(msg, &signing_keys)?;
        println!(
            "   ✓ Signed (ED25519: {} bytes, ML-DSA-87: {} bytes)",
            multi_sig.ed25519_sig.to_bytes().len(),
            multi_sig.ml_dsa_sig.len()
        );

        // Verify signature
        verify_message(msg, &multi_sig, &verifying_keys)?;
        println!("   ✓ Verified!\n");
    }

    // Demonstrate failure on tampered message
    println!(
        "{}️⃣  Testing tampered message detection...",
        messages.len() + 2
    );
    let msg = b"Original message";
    let sig = sign_message(msg, &signing_keys)?;

    let tampered = b"Tampered message";
    match verify_message(tampered, &sig, &verifying_keys) {
        Ok(_) => println!("   ✗ ERROR: Tampered message passed verification!"),
        Err(e) => println!("   ✓ Correctly rejected: {}\n", e),
    }

    println!("✅ Multi-signature system working correctly!");
    println!("   Both classical and post-quantum signatures must verify");

    Ok(())
}
