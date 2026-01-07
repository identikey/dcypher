# HMAC Analysis: HDprint Only

**Status:** ✅ DECIDED  
**Decision:** Retain HMAC-SHA3-512 for HDprint fingerprint generation; use plain Blake3 elsewhere

---

## Summary

HMAC (Hash-based Message Authentication Code) is used **only** in HDprint's fingerprint chain. All other hashing uses plain Blake3.

---

## Current HDprint Algorithm

From Python prototype (`algorithms.py`):

```python
def hmac_sha3_512(key: bytes, data: bytes) -> bytes:
    """Generate HMAC-SHA3-512 hash with blake3 preprocessing."""
    blake3_key = blake3.blake3(key).digest()
    blake3_data = blake3.blake3(data).digest()
    return hmac.new(blake3_key, blake3_data, hashlib.sha3_512).digest()
```

This is used iteratively to generate each character of the fingerprint:

```python
for char_index in range(total_chars):
    char_hash = hmac_sha3_512(public_key, current_data)
    char_b58 = based58.b58encode(char_hash).decode("ascii")
    character = char_b58[-1]  # Take last character
    current_data = char_hash   # Chain for next iteration
```

---

## Why HMAC in HDprint?

### 1. Key Binding

The fingerprint is **bound** to the public key. Without knowing the key, an attacker cannot:

- Forge a fingerprint for a chosen public key
- Find a public key that produces a target fingerprint
- Predict fingerprint from partial key knowledge

```
HMAC(key, data) ≠ Hash(key || data)
```

HMAC provides stronger security properties than simple concatenation.

### 2. PRF Property

HMAC is a Pseudorandom Function (PRF), meaning its output is computationally indistinguishable from random. This ensures:

- Uniform distribution in Base58 character selection
- No bias in fingerprint characters
- Cryptographic independence between characters

### 3. Chain Security

Each character depends on the HMAC of the previous:

```
char[0] = HMAC(pubkey, pubkey)[-1]
char[1] = HMAC(pubkey, HMAC(pubkey, pubkey))[-1]
char[n] = HMAC(pubkey, char[n-1])[-1]
```

This chaining provides:

- Avalanche effect (changing any input changes all subsequent characters)
- No shortcuts to compute later characters without earlier ones

---

## Alternative Considered: Blake3 Keyed Mode

Blake3 supports keyed hashing:

```rust
let mac = blake3::keyed_hash(&key, data);
```

**Why not use this for HDprint?**

1. **Compatibility:** HDprint was designed with HMAC-SHA3-512; changing would break fingerprint verification against Python-generated values (though we don't need cross-version compatibility)

2. **Security margin:** HMAC-SHA3-512 provides 512-bit output, giving more bits per iteration than Blake3's 256-bit output. Since we take only the last Base58 character (~5.86 bits) per iteration, this is overkill but harmless.

3. **Conservative choice:** HMAC construction is extremely well-studied. Blake3 keyed mode is newer (though also well-designed).

**Verdict:** Keep HMAC-SHA3-512 for HDprint. The "Blake3 preprocessing" step before HMAC is retained as it provides additional mixing.

---

## Where NOT to Use HMAC

Plain Blake3 is sufficient for:

| Use Case                | Why HMAC Not Needed                           |
| ----------------------- | --------------------------------------------- |
| Content hashing         | No secret key; just need collision resistance |
| Chunk hashes            | Same as above                                 |
| Bao tree nodes          | Internal to Bao; no keyed requirement         |
| Wire protocol integrity | Signatures provide authentication             |
| File identity           | Content addressing doesn't need keying        |

---

## Rust Implementation

```rust
use hmac::{Hmac, Mac};
use sha3::Sha3_512;

type HmacSha3_512 = Hmac<Sha3_512>;

/// HMAC-SHA3-512 with Blake3 preprocessing (matching Python)
fn hmac_sha3_512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let blake3_key = blake3::hash(key);
    let blake3_data = blake3::hash(data);

    let mut mac = HmacSha3_512::new_from_slice(blake3_key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(blake3_data.as_bytes());

    let result = mac.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result.into_bytes());
    output
}
```

---

## Dependencies

```toml
[dependencies]
hmac = "0.12"
sha3 = "0.10"
blake3 = "1"
```

---

## Security Considerations

1. **Key length:** Public keys are typically 32+ bytes, which is adequate for HMAC
2. **Timing attacks:** Use constant-time comparison for fingerprint verification
3. **Side channels:** HMAC implementations in `hmac` crate are designed to be constant-time

---

## References

- [HMAC RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)
- [SHA-3 FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final)
- [hmac crate](https://docs.rs/hmac)
- [sha3 crate](https://docs.rs/sha3)
