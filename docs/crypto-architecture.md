# Crypto Architecture: Encryption Approach

**Status:** ⏳ PENDING DISCUSSION  
**Decision:** Hybrid encryption recommended, awaiting final confirmation

---

## Summary

This document analyzes the choice between:

1. **Pure Asymmetric:** Encrypt entire files with OpenFHE PRE
2. **Hybrid (KEM-DEM):** Symmetric file encryption + asymmetric key wrapping

**Preliminary recommendation:** Hybrid approach due to FHE ciphertext expansion.

---

## The Problem: FHE Ciphertext Expansion

BFV/PRE encryption has significant ciphertext expansion:

| Security Level | Ring Dimension | Expansion Factor |
| -------------- | -------------- | ---------------- |
| 128-bit        | ~4096          | ~50-100x         |
| 192-bit        | ~8192          | ~100-200x        |
| 256-bit        | ~16384         | ~200-400x        |

**Example at 128-bit security:**

- 1 MB plaintext → 50-100 MB ciphertext
- 100 MB plaintext → 5-10 GB ciphertext

This is impractical for file storage.

---

## Option 1: Pure Asymmetric

```
┌─────────────────────────────────────────────────────────────┐
│  ENCRYPTION                                                  │
│                                                              │
│  plaintext → [PRE Encrypt] → ciphertext (50-100x larger)    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  RECRYPTION                                                  │
│                                                              │
│  ciphertext_alice → [PRE Transform] → ciphertext_bob        │
│  (transforms entire file)                                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  DECRYPTION                                                  │
│                                                              │
│  ciphertext_bob → [PRE Decrypt] → plaintext                 │
└─────────────────────────────────────────────────────────────┘
```

**Pros:**

- ✅ Simple conceptual model
- ✅ Direct PRE transformation
- ✅ No key management for symmetric keys

**Cons:**

- ❌ 50-100x storage overhead
- ❌ 50-100x bandwidth for transfers
- ❌ Slow encryption/decryption (FHE is expensive)
- ❌ Recryption transforms entire file (slow for large files)

---

## Option 2: Hybrid (Recommended)

```
┌─────────────────────────────────────────────────────────────┐
│  ENCRYPTION                                                  │
│                                                              │
│  1. Generate random symmetric key K (256-bit)               │
│  2. Encrypt file: ciphertext = ChaCha20-Poly1305(K, file)   │
│  3. Wrap key: wrapped_K = PRE_Encrypt(pubkey, K)            │
│  4. Store: {ciphertext, wrapped_K}                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  RECRYPTION                                                  │
│                                                              │
│  1. Transform ONLY the wrapped key:                         │
│     wrapped_K_bob = PRE_Transform(rk, wrapped_K_alice)      │
│  2. File ciphertext stays IDENTICAL                         │
│  3. Super fast: only 256 bits transformed                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  DECRYPTION                                                  │
│                                                              │
│  1. Unwrap key: K = PRE_Decrypt(privkey, wrapped_K)         │
│  2. Decrypt file: plaintext = ChaCha20-Poly1305(K, ct)      │
└─────────────────────────────────────────────────────────────┘
```

**Pros:**

- ✅ ~0% storage overhead (symmetric encryption is 1:1)
- ✅ Fast encryption/decryption (ChaCha20 is ~GB/s)
- ✅ Fast recryption (only 256 bits transformed)
- ✅ Standard construction (KEM-DEM paradigm)
- ✅ Streaming-friendly

**Cons:**

- ❌ Two-stage encryption (slightly more complex)
- ❌ Must manage symmetric key lifecycle
- ❌ Wrapped key is still ~KB due to FHE expansion

---

## Security Analysis: Hybrid Construction

The hybrid approach follows the KEM-DEM (Key Encapsulation Mechanism - Data Encapsulation Mechanism) paradigm:

### KEM (Key Encapsulation)

- PRE encrypts the symmetric key
- Security relies on PRE/BFV hardness (lattice problems)

### DEM (Data Encapsulation)

- ChaCha20-Poly1305 encrypts the data
- Security relies on symmetric key secrecy

### Composition Security

If KEM is IND-CCA secure and DEM is AE (authenticated encryption), the composition is IND-CCA secure.

- **BFV/PRE:** Provides IND-CPA security (sufficient for our use)
- **ChaCha20-Poly1305:** Provides AE (AEAD)

**Note:** PRE is IND-CPA, not IND-CCA, but this is acceptable because:

1. Ciphertexts are content-addressed (tampered = different hash)
2. Signatures authenticate all messages
3. We don't need chosen-ciphertext security

---

## Wrapped Key Format

The wrapped symmetric key fits in a single PRE ciphertext slot:

```rust
struct WrappedKey {
    // ChaCha20-Poly1305 needs: key (32) + nonce (12) = 44 bytes
    // Fits comfortably in one BFV slot (typically 16-bit coefficients)
    ciphertext: Vec<u8>,  // ~1-10 KB after PRE encryption
}
```

### Encoding Strategy

```rust
fn wrap_symmetric_key(
    ctx: &CryptoContext,
    recipient_pk: &PublicKey,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> WrappedKey {
    // Pack 44 bytes into coefficients
    // Each coefficient holds 16 bits (2 bytes)
    // Need 22 coefficients minimum
    let coeffs = bytes_to_coefficients(&[key, nonce].concat());

    // Encrypt (single ciphertext, but still ~KB sized)
    let ct = ctx.encrypt(recipient_pk, &coeffs);

    WrappedKey { ciphertext: serialize(ct) }
}
```

---

## Comparison Table

| Aspect           | Pure Asymmetric    | Hybrid            |
| ---------------- | ------------------ | ----------------- |
| Storage overhead | 50-100x            | ~1% (wrapped key) |
| Encryption speed | Slow (FHE)         | Fast (ChaCha20)   |
| Decryption speed | Slow (FHE)         | Fast (ChaCha20)   |
| Recryption speed | Slow (entire file) | Fast (256 bits)   |
| Complexity       | Simple             | Moderate          |
| Security         | FHE only           | FHE + symmetric   |
| Streaming        | Difficult          | Natural           |

---

## Implementation Sketch

```rust
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead};
use rand::RngCore;

/// Encrypt a file for a recipient
pub fn encrypt_file(
    ctx: &CryptoContext,
    recipient_pk: &PublicKey,
    plaintext: &[u8],
) -> (Vec<u8>, WrappedKey) {
    // Generate random symmetric key
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Encrypt file with symmetric key
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("encryption failure");

    // Wrap symmetric key with PRE
    let wrapped = wrap_symmetric_key(ctx, recipient_pk, &key, &nonce);

    (ciphertext, wrapped)
}

/// Decrypt a file
pub fn decrypt_file(
    ctx: &CryptoContext,
    secret_key: &SecretKey,
    ciphertext: &[u8],
    wrapped_key: &WrappedKey,
) -> Vec<u8> {
    // Unwrap symmetric key
    let (key, nonce) = unwrap_symmetric_key(ctx, secret_key, wrapped_key);

    // Decrypt file
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher.decrypt(Nonce::from_slice(&nonce), ciphertext)
        .expect("decryption failure")
}

/// Recrypt for a new recipient (fast!)
pub fn recrypt_wrapped_key(
    ctx: &CryptoContext,
    recrypt_key: &RecryptKey,
    wrapped_key: &WrappedKey,
) -> WrappedKey {
    // Only transforms the small wrapped key, not the file
    let ct = deserialize(&wrapped_key.ciphertext);
    let recrypted = ctx.recrypt(recrypt_key, &ct);
    WrappedKey { ciphertext: serialize(&recrypted) }
}
```

---

## Open Questions for Discussion

1. **Nonce handling:** Store with wrapped key or derive from file hash?
2. **Key rotation:** How to handle re-encryption with new symmetric key?
3. **Partial file access:** Can we support range requests with hybrid?
4. **Multi-recipient:** Encrypt key once per recipient, or shared scheme?

---

## Dependencies

```toml
[dependencies]
chacha20poly1305 = "0.10"
rand = "0.8"
```

---

## References

- [KEM-DEM Paradigm](https://en.wikipedia.org/wiki/Hybrid_cryptosystem)
- [ChaCha20-Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
- [BFV Encryption Scheme](https://eprint.iacr.org/2012/144)
