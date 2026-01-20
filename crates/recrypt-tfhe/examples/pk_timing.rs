//! Timing test for public key generation with different zero encryption counts
//!
//! Run with: cargo run --example pk_timing --release -p recrypt-tfhe

use std::time::Instant;
use tfhe::core_crypto::prelude::*;

fn main() {
    println!("TFHE Public Key Generation Timing Test");
    println!("=======================================\n");

    // Default parameters (128-bit security)
    let lwe_dimension = LweDimension(742);
    let noise_std = StandardDev(0.000007069849454709433);
    let noise_distribution: DynamicDistribution<u64> =
        DynamicDistribution::new_gaussian_from_std_dev(noise_std);
    let ciphertext_modulus: CiphertextModulus<u64> = CiphertextModulus::new_native();

    let n = lwe_dimension.0;
    let recommended_count = (n + 1) * 64 + 128;
    let practical_count = 2 * n;

    println!("LWE dimension: {}", n);
    println!("Recommended zero encryption count: {} (security-optimal)", recommended_count);
    println!("Practical zero encryption count: {} (performance tradeoff)", practical_count);
    println!("Ratio: {:.1}x\n", recommended_count as f64 / practical_count as f64);

    // Generate secret key first
    println!("Generating secret key...");
    let mut seeder = new_seeder();
    let seeder_ref = seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed());

    let sk: LweSecretKeyOwned<u64> = allocate_and_generate_new_binary_lwe_secret_key(
        lwe_dimension,
        &mut secret_generator,
    );
    println!("Secret key generated.\n");

    // Test practical count
    println!("Testing PRACTICAL count ({})...", practical_count);
    let start = Instant::now();
    {
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

        let _pk = allocate_and_generate_new_lwe_public_key(
            &sk,
            LwePublicKeyZeroEncryptionCount(practical_count),
            noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );
    }
    let practical_duration = start.elapsed();
    println!("Practical count took: {:.2?}\n", practical_duration);

    // Test recommended count
    println!("Testing RECOMMENDED count ({})...", recommended_count);
    println!("(This may take several minutes...)");
    let start = Instant::now();
    {
        let mut seeder = new_seeder();
        let seeder_ref = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder_ref.seed(), seeder_ref);

        let _pk = allocate_and_generate_new_lwe_public_key(
            &sk,
            LwePublicKeyZeroEncryptionCount(recommended_count),
            noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );
    }
    let recommended_duration = start.elapsed();
    println!("Recommended count took: {:.2?}\n", recommended_duration);

    // Summary
    println!("Summary");
    println!("-------");
    println!("Practical ({} encryptions): {:.2?}", practical_count, practical_duration);
    println!("Recommended ({} encryptions): {:.2?}", recommended_count, recommended_duration);
    println!("Slowdown factor: {:.1}x", recommended_duration.as_secs_f64() / practical_duration.as_secs_f64());
}
