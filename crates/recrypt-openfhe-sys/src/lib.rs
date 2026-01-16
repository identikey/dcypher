//! Minimal OpenFHE bindings for Proxy Recryption (PRE)
//!
//! This crate provides the raw FFI layer to OpenFHE, exposing only the
//! ~15 functions needed for PRE operations with the BFV scheme.
//!
//! Higher-level safe Rust wrappers are provided by `recrypt-ffi`.

#[cxx::bridge(namespace = "recrypt_openfhe")]
pub mod ffi {
    unsafe extern "C++" {
        include!("recrypt-openfhe-sys/src/wrapper.h");

        // Opaque types (defined in C++ with complete definitions)
        type CryptoContext;
        type KeyPair;
        type PublicKey;
        type PrivateKey;
        type Plaintext;
        type Ciphertext;
        type RecryptKey;

        // Context creation and properties
        fn create_bfv_context(
            plaintext_modulus: u64,
            scaling_mod_size: u32,
        ) -> UniquePtr<CryptoContext>;
        fn enable_pke(ctx: &CryptoContext);
        fn enable_keyswitch(ctx: &CryptoContext);
        fn enable_leveledshe(ctx: &CryptoContext);
        fn enable_pre(ctx: &CryptoContext);
        fn get_ring_dimension(ctx: &CryptoContext) -> u32;

        // Key generation
        fn keygen(ctx: &CryptoContext) -> UniquePtr<KeyPair>;
        fn get_public_key(kp: &KeyPair) -> UniquePtr<PublicKey>;
        fn get_private_key(kp: &KeyPair) -> UniquePtr<PrivateKey>;

        // Plaintext operations
        fn make_packed_plaintext(ctx: &CryptoContext, values: &[i64]) -> UniquePtr<Plaintext>;
        fn get_packed_value(pt: &Plaintext) -> Vec<i64>;

        // Encryption/Decryption
        fn encrypt(ctx: &CryptoContext, pk: &PublicKey, pt: &Plaintext) -> UniquePtr<Ciphertext>;
        fn decrypt(ctx: &CryptoContext, sk: &PrivateKey, ct: &Ciphertext) -> UniquePtr<Plaintext>;

        // PRE (recryption) operations
        fn generate_recrypt_key(
            ctx: &CryptoContext,
            from_sk: &PrivateKey,
            to_pk: &PublicKey,
        ) -> UniquePtr<RecryptKey>;
        fn recrypt(ctx: &CryptoContext, rk: &RecryptKey, ct: &Ciphertext) -> UniquePtr<Ciphertext>;

        // Serialization (byte-based)
        fn serialize_ciphertext(ct: &Ciphertext) -> Vec<u8>;
        fn deserialize_ciphertext(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<Ciphertext>;
        fn serialize_public_key(pk: &PublicKey) -> Vec<u8>;
        fn deserialize_public_key(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<PublicKey>;
        fn serialize_private_key(sk: &PrivateKey) -> Vec<u8>;
        fn deserialize_private_key(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<PrivateKey>;
        fn serialize_recrypt_key(rk: &RecryptKey) -> Vec<u8>;
        fn deserialize_recrypt_key(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<RecryptKey>;
    }
}

// Re-export for convenience
pub use ffi::*;

#[cfg(test)]
mod tests {
    use super::ffi;

    #[test]
    fn test_create_context() {
        let ctx = ffi::create_bfv_context(65537, 60);
        assert!(!ctx.is_null());

        ffi::enable_pke(&ctx);
        ffi::enable_keyswitch(&ctx);
        ffi::enable_leveledshe(&ctx);
        ffi::enable_pre(&ctx);

        let ring_dim = ffi::get_ring_dimension(&ctx);
        assert!(ring_dim > 0);
        println!("Ring dimension: {}", ring_dim);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx = ffi::create_bfv_context(65537, 60);
        ffi::enable_pke(&ctx);
        ffi::enable_keyswitch(&ctx);
        ffi::enable_leveledshe(&ctx);
        ffi::enable_pre(&ctx);

        let kp = ffi::keygen(&ctx);
        let pk = ffi::get_public_key(&kp);
        let sk = ffi::get_private_key(&kp);

        let values: Vec<i64> = vec![1, 2, 3, 4, 5];
        let pt = ffi::make_packed_plaintext(&ctx, &values);

        let ct = ffi::encrypt(&ctx, &pk, &pt);
        let pt_dec = ffi::decrypt(&ctx, &sk, &ct);

        let recovered = ffi::get_packed_value(&pt_dec);
        assert_eq!(&recovered[..5], &values[..]);
        println!("Roundtrip successful: {:?}", &recovered[..5]);
    }

    #[test]
    fn test_pre_recryption() {
        let ctx = ffi::create_bfv_context(65537, 60);
        ffi::enable_pke(&ctx);
        ffi::enable_keyswitch(&ctx);
        ffi::enable_leveledshe(&ctx);
        ffi::enable_pre(&ctx);

        // Alice and Bob generate their keypairs
        let alice_kp = ffi::keygen(&ctx);
        let alice_pk = ffi::get_public_key(&alice_kp);
        let alice_sk = ffi::get_private_key(&alice_kp);

        let bob_kp = ffi::keygen(&ctx);
        let bob_pk = ffi::get_public_key(&bob_kp);
        let bob_sk = ffi::get_private_key(&bob_kp);

        // Alice encrypts data to herself
        let values: Vec<i64> = vec![42, 123, 456];
        let pt = ffi::make_packed_plaintext(&ctx, &values);
        let ct_alice = ffi::encrypt(&ctx, &alice_pk, &pt);

        // Alice generates a recryption key to Bob
        let rk = ffi::generate_recrypt_key(&ctx, &alice_sk, &bob_pk);

        // Proxy transforms the ciphertext (without seeing plaintext)
        let ct_bob = ffi::recrypt(&ctx, &rk, &ct_alice);

        // Bob decrypts with his own secret key
        let pt_bob = ffi::decrypt(&ctx, &bob_sk, &ct_bob);
        let recovered = ffi::get_packed_value(&pt_bob);

        assert_eq!(&recovered[..3], &values[..]);
        println!("PRE recryption successful: {:?}", &recovered[..3]);
    }
}
