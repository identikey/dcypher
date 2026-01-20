//! Test how zero encryption count affects public key noise
//!
//! Run with: cargo run --example debug_pk_noise_counts --release -p recrypt-tfhe

use tfhe::core_crypto::prelude::*;

fn measure_pk_noise(zero_count: usize) -> (u32, u32, u32) {
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

    // Generate public key with specified count
    let mut seeder = new_seeder();
    let seeder_ref = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

    let pk = allocate_and_generate_new_lwe_public_key(
        &sk,
        LwePublicKeyZeroEncryptionCount(zero_count),
        noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Measure noise over several encryptions
    let mut min_bits = 64u32;
    let mut max_bits = 0u32;
    let mut sum_bits = 0u64;
    let trials = 100;

    for _ in 0..trials {
        let msg = 0u64;
        let delta: u64 = 1u64 << 62;
        let plaintext = Plaintext(msg * delta);

        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut secret_gen =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

        let mut ct = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
        encrypt_lwe_ciphertext_with_public_key(&pk, &mut ct, plaintext, &mut secret_gen);

        let decrypted = decrypt_lwe_ciphertext(&sk, &ct);
        let noise = decrypted.0;
        let noise_bits = if noise < (1u64 << 63) {
            64 - noise.leading_zeros()
        } else {
            64 - noise.wrapping_neg().leading_zeros()
        };

        min_bits = min_bits.min(noise_bits);
        max_bits = max_bits.max(noise_bits);
        sum_bits += noise_bits as u64;
    }

    let avg_bits = (sum_bits / trials as u64) as u32;
    (min_bits, avg_bits, max_bits)
}

fn main() {
    println!("Public Key Noise vs Zero Encryption Count");
    println!("==========================================\n");

    // Test with different zero encryption counts
    let counts = [
        742 * 2,      // 2n (practical minimum)
        742 * 4,      // 4n
        742 * 8,      // 8n
        742 * 16,     // 16n
        (742 + 1) * 64 + 128, // Recommended
    ];

    println!("n = 742 (LWE dimension)");
    println!("Message space: 62 bits\n");
    println!("{:>10} | {:>8} | {:>8} | {:>8}", "Count", "Min", "Avg", "Max");
    println!("{:-<10}-+-{:-<8}-+-{:-<8}-+-{:-<8}", "", "", "", "");

    for count in counts {
        let (min_bits, avg_bits, max_bits) = measure_pk_noise(count);
        let ratio = count as f64 / 742.0;
        println!(
            "{:>10} | {:>8} | {:>8} | {:>8}  ({:.1}n)",
            count, min_bits, avg_bits, max_bits, ratio
        );
    }

    println!("\nFor key switching to work, we need noise + accumulated noise < 62 bits");
    println!("With n=742 terms being summed, and base_log=4, level=3:");
    println!("  Accumulated noise ≈ sqrt(n × levels) × individual_noise");
    println!("  ≈ sqrt(742 × 3) × individual_noise");
    println!("  ≈ 47 × individual_noise (in bits: +5.5 bits)");
    println!("\nSo individual noise must be < 62 - 5.5 = ~56 bits");
}
