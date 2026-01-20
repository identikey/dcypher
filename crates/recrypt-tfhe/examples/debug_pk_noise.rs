//! Debug public key encryption noise levels
//!
//! Run with: cargo run --example debug_pk_noise --release -p recrypt-tfhe

use tfhe::core_crypto::prelude::*;

fn main() {
    println!("Debug Public Key Encryption Noise");
    println!("==================================\n");

    let lwe_dimension = LweDimension(742);
    let noise_std = StandardDev(0.000007069849454709433);
    let noise_distribution: DynamicDistribution<u64> =
        DynamicDistribution::new_gaussian_from_std_dev(noise_std);
    let ciphertext_modulus: CiphertextModulus<u64> = CiphertextModulus::new_native();

    // Generate secret key
    let mut seeder = new_seeder();
    let seeder_ref = seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

    let sk: LweSecretKeyOwned<u64> = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );

    // Generate public key with practical count for speed
    let mut seeder = new_seeder();
    let seeder_ref = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

    let pk = allocate_and_generate_new_lwe_public_key(
        &sk,
        LwePublicKeyZeroEncryptionCount(2 * lwe_dimension.0),
        noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    println!("Secret key dimension: {}", lwe_dimension.0);
    println!("Public key zero encryption count: {}", pk.zero_encryption_count().0);

    // Test encrypting various values with public key
    let delta: u64 = 1u64 << 62; // For 2-bit messages

    println!("\nTesting 2-bit message encryption/decryption with PUBLIC key:");
    for msg in 0..4u64 {
        let plaintext = Plaintext(msg * delta);

        // Encrypt with public key
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut secret_gen =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

        let mut ct = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
        encrypt_lwe_ciphertext_with_public_key(&pk, &mut ct, plaintext, &mut secret_gen);

        // Decrypt
        let decrypted = decrypt_lwe_ciphertext(&sk, &ct);
        let rounded = decrypted.0.wrapping_add(delta / 2) / delta;
        let recovered = rounded & 0b11;

        let noise = if msg * delta > decrypted.0 {
            msg * delta - decrypted.0
        } else {
            decrypted.0 - msg * delta
        };
        let noise_bits = 64 - noise.leading_zeros();

        println!(
            "  msg={}: encrypted={:016x}, decrypted={:016x}, recovered={}, noise_bits={}, {}",
            msg,
            plaintext.0,
            decrypted.0,
            recovered,
            noise_bits,
            if recovered == msg { "OK" } else { "FAIL" }
        );
    }

    // Now test encrypting gadget values (what KSK needs)
    let decomp_base_log = 4usize;
    let decomp_level_count = 3usize;

    println!("\nTesting gadget value encryption (what KSK needs):");
    for level in 1..=decomp_level_count {
        let shift = 64usize.saturating_sub(level * decomp_base_log);
        let gadget_factor = 1u64 << shift;
        let neg_gadget = gadget_factor.wrapping_neg();

        println!("\n  Level {}: gadget=2^{} = {:016x}", level, shift, gadget_factor);
        println!("           -gadget = {:016x}", neg_gadget);

        // Encrypt -gadget (what KSK does)
        let plaintext = Plaintext(neg_gadget);

        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut secret_gen =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

        let mut ct = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
        encrypt_lwe_ciphertext_with_public_key(&pk, &mut ct, plaintext, &mut secret_gen);

        // Decrypt
        let decrypted = decrypt_lwe_ciphertext(&sk, &ct);
        let error = decrypted.0.wrapping_sub(neg_gadget);
        let error_bits = if error < (1u64 << 63) {
            64 - error.leading_zeros()
        } else {
            64 - error.wrapping_neg().leading_zeros()
        };

        println!("           decrypted = {:016x}", decrypted.0);
        println!("           error bits = {}", error_bits);
    }

    // Test symmetric encryption for comparison
    println!("\nTesting same with SYMMETRIC encryption:");
    for level in 1..=decomp_level_count {
        let shift = 64usize.saturating_sub(level * decomp_base_log);
        let gadget_factor = 1u64 << shift;
        let neg_gadget = gadget_factor.wrapping_neg();

        let plaintext = Plaintext(neg_gadget);

        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut enc_gen =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

        let ct: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &sk,
            plaintext,
            noise_distribution,
            ciphertext_modulus,
            &mut enc_gen,
        );

        let decrypted = decrypt_lwe_ciphertext(&sk, &ct);
        let error = decrypted.0.wrapping_sub(neg_gadget);
        let error_bits = if error < (1u64 << 63) {
            64 - error.leading_zeros()
        } else {
            64 - error.wrapping_neg().leading_zeros()
        };

        println!("  Level {}: error bits = {} (symmetric)", level, error_bits);
    }
}
