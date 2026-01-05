# Non-Determinism in Cryptographic Operations

**Status:** ✅ DECIDED  
**Decision:** Test semantic correctness, not byte equality

---

## Summary

Several cryptographic operations in dCypher produce non-deterministic output. This is **expected and secure**, but requires careful handling in testing and content addressing.

---

## Sources of Non-Determinism

### 1. OpenFHE Ciphertext Encryption

**What happens:** Encrypting the same plaintext twice produces different ciphertexts.

**Why:** BFV/PRE encryption includes randomness for IND-CPA security. Without randomness, an attacker could detect if two ciphertexts encrypt the same message.

**Impact:**

- ❌ Cannot compare ciphertexts byte-for-byte
- ❌ Cannot use ciphertext as content hash
- ✅ Decryption always produces same plaintext

**Testing Strategy:**

```rust
#[test]
fn test_encryption_roundtrip() {
    let msg = b"test message";
    let (pk, sk) = generate_keypair();

    let ct1 = encrypt(&pk, msg);
    let ct2 = encrypt(&pk, msg);

    // Ciphertexts differ
    assert_ne!(ct1.as_bytes(), ct2.as_bytes());

    // But both decrypt to same plaintext
    assert_eq!(decrypt(&sk, &ct1), msg);
    assert_eq!(decrypt(&sk, &ct2), msg);
}
```

### 2. OpenFHE Serialization

**What happens:** Serializing the same object twice may produce different bytes.

**Why:** OpenFHE's internal representation doesn't guarantee canonical ordering of elements.

**Impact:**

- ❌ Cannot use serialized form for equality testing
- ❌ Cannot hash serialized ciphertext for content addressing
- ✅ Deserialized objects are functionally identical

**Testing Strategy:**

```rust
#[test]
fn test_serialization_semantic_equality() {
    let ctx = create_context();
    let (pk, sk) = generate_keypair();
    let msg = b"test";

    let ct = encrypt(&pk, msg);

    // Serialize and deserialize
    let bytes = serialize(&ct);
    let ct_restored = deserialize(&bytes);

    // May have different serialization
    // (don't test: serialize(&ct_restored) == bytes)

    // But must decrypt identically
    assert_eq!(decrypt(&sk, &ct_restored), msg);
}
```

### 3. Post-Quantum Signatures

**What happens:** Signing the same message twice produces different signatures.

**Why:** Many PQ signature schemes (ML-DSA, SLH-DSA, etc.) include randomness for security properties.

**Impact:**

- ❌ Cannot compare signatures byte-for-byte
- ❌ Cannot use signature as deterministic identifier
- ✅ Both signatures verify correctly

**Testing Strategy:**

```rust
#[test]
fn test_signature_verification() {
    let (signing_key, verifying_key) = generate_signing_keypair();
    let msg = b"test message";

    let sig1 = sign(&signing_key, msg);
    let sig2 = sign(&signing_key, msg);

    // Signatures differ
    assert_ne!(sig1.as_bytes(), sig2.as_bytes());

    // But both verify
    assert!(verify(&verifying_key, msg, &sig1));
    assert!(verify(&verifying_key, msg, &sig2));
}
```

---

## Content Addressing Strategy

Since ciphertext is non-deterministic, content addressing must use **plaintext hashes**:

```rust
/// File identity is the Blake3 hash of the PLAINTEXT
fn compute_file_identity(plaintext: &[u8]) -> blake3::Hash {
    blake3::hash(plaintext)
}

/// Storage key derived from plaintext, not ciphertext
fn storage_key(plaintext: &[u8]) -> String {
    let hash = compute_file_identity(plaintext);
    format!("files/{}", hash.to_hex())
}
```

### Metadata Storage

File metadata must include the plaintext hash:

```rust
struct FileMetadata {
    /// Blake3 hash of original plaintext (file identity)
    plaintext_hash: [u8; 32],

    /// Wrapped symmetric key (PRE-encrypted)
    wrapped_key: Vec<u8>,

    /// Bao root hash of encrypted chunks (for integrity)
    encrypted_bao_root: [u8; 32],

    /// ... other fields
}
```

---

## Testing Patterns

### Pattern 1: Roundtrip Semantic Equality

```rust
fn test_roundtrip<T: Encrypt + Decrypt>(value: T) {
    let encrypted = value.encrypt();
    let decrypted = encrypted.decrypt();
    assert_eq!(decrypted, value);  // Semantic equality
}
```

### Pattern 2: Property-Based Testing

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encryption_preserves_content(data: Vec<u8>) {
        let (pk, sk) = generate_keypair();
        let ct = encrypt(&pk, &data);
        let pt = decrypt(&sk, &ct);
        prop_assert_eq!(pt, data);
    }

    #[test]
    fn recryption_preserves_content(data: Vec<u8>) {
        let (alice_pk, alice_sk) = generate_keypair();
        let (bob_pk, bob_sk) = generate_keypair();

        let ct_alice = encrypt(&alice_pk, &data);
        let rk = generate_recrypt_key(&alice_sk, &bob_pk);
        let ct_bob = recrypt(&rk, &ct_alice);
        let pt = decrypt(&bob_sk, &ct_bob);

        prop_assert_eq!(pt, data);
    }
}
```

### Pattern 3: Known-Answer Tests (for deterministic components)

HDprint fingerprints ARE deterministic (same key → same fingerprint):

```rust
#[test]
fn test_hdprint_deterministic() {
    let pubkey = hex::decode("0123456789abcdef...").unwrap();

    let fp1 = generate_fingerprint(&pubkey, "medium");
    let fp2 = generate_fingerprint(&pubkey, "medium");

    // HDprint IS deterministic
    assert_eq!(fp1, fp2);

    // Can use known-answer test
    assert_eq!(fp1, "Ab3DeF_Xy9ZmP7q_R2sK1M4V");
}
```

---

## Crypto Context Management

OpenFHE requires the same context instance for related operations:

```rust
// WRONG: Creating new contexts
fn bad_encrypt_decrypt(data: &[u8]) {
    let ctx1 = create_context();  // Context 1
    let (pk, _) = ctx1.generate_keys();
    let ct = ctx1.encrypt(&pk, data);

    let ctx2 = create_context();  // Context 2 - INCOMPATIBLE!
    let (_, sk) = ctx2.generate_keys();
    ctx2.decrypt(&sk, &ct);  // FAILS or produces garbage
}

// RIGHT: Reusing context
fn good_encrypt_decrypt(data: &[u8]) {
    let ctx = create_context();  // Single context
    let (pk, sk) = ctx.generate_keys();
    let ct = ctx.encrypt(&pk, data);
    let pt = ctx.decrypt(&sk, &ct);  // Works correctly
    assert_eq!(pt, data);
}
```

---

## Summary Table

| Operation   | Deterministic? | Test Strategy                             |
| ----------- | -------------- | ----------------------------------------- |
| Encrypt     | ❌             | Roundtrip: decrypt(encrypt(x)) == x       |
| Serialize   | ❌             | Roundtrip: deserialize(serialize(x)) ≡ x  |
| PQ Sign     | ❌             | Verify: verify(sign(m)) == true           |
| Blake3 hash | ✅             | Direct comparison                         |
| HDprint     | ✅             | Known-answer tests                        |
| Bao encode  | ✅             | Direct comparison (same data → same root) |

---

## Dependencies

```toml
[dev-dependencies]
proptest = "1"
```

---

## References

- [IND-CPA Security](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability)
- [proptest crate](https://docs.rs/proptest)
