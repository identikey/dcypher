# HDprint Specification

**Status:** ✅ Reference Document  
**Source:** Python prototype at `python-prototype/src/dcypher/hdprint/`

---

## Overview

HDprint is a self-correcting hierarchical identifier system combining:

1. **Paiready checksum:** BCH error-correcting, Base58L lowercase
2. **HDprint fingerprint:** HMAC-SHA3-512 chain, hierarchical scaling

### Format

```
{paiready}_{hdprint}
myzgemb_5ubrZa_T9w1LJRx_hEGmdyaM
└──┬───┘ └────────────┬───────────┘
   │                  │
   │                  └── Hierarchical fingerprint (mixed case Base58)
   └── Error-correcting checksum (lowercase Base58L)
```

---

## Key Properties

### 1. Error Correction

Single character typos in the checksum are automatically corrected:

```
User types:  1pk2bdr_...  (2 errors in checksum)
Corrected:   4pkabdr_...
```

**Implementation:** 5× BCH(t=1, m=7) interleaved codes

### 2. Case Insensitivity

Users can type everything lowercase; proper case is restored:

```
Input:   myzgemb_5ubrza_t9w1ljrx_hegmdyam
Output:  myzgemb_5ubrZa_T9w1LJRx_hEGmdyaM
```

**Implementation:** Case bit field encoded in checksum

### 3. Hierarchical Scaling

| Size   | Segments | Pattern           | Security (bits) |
| ------ | -------- | ----------------- | --------------- |
| TINY   | 1        | [6]               | ~17.6           |
| SMALL  | 2        | [6,8]             | ~64.4           |
| MEDIUM | 3        | [6,8,8]           | ~111.3          |
| RACK   | 4        | [6,8,8,8]         | ~158.2          |
| 2 RACK | 8        | [6,8,8,8,6,8,8,8] | ~316.4          |

### 4. Human Friendly

- Base58 encoding (no confusing chars: 0/O, 1/l, I)
- Underscore separators for visual parsing
- Meaningful structure: checksum first, then hierarchical segments

---

## Algorithm

### HDprint Fingerprint Generation

```
Input: public_key (bytes)
Output: fingerprint (string)

1. Determine pattern from size (e.g., MEDIUM = [6,8,8])
2. total_chars = sum(pattern)
3. current_data = public_key
4. characters = []

5. For i in 0..total_chars:
   a. hash = HMAC-SHA3-512(blake3(public_key), blake3(current_data))
   b. char = Base58(hash)[-1]  // Last character
   c. characters.append(char)
   d. current_data = hash

6. Group characters by pattern into segments
7. Return segments.join("_")
```

### HMAC-SHA3-512 with Blake3 Preprocessing

```python
def hmac_sha3_512(key: bytes, data: bytes) -> bytes:
    blake3_key = blake3.blake3(key).digest()
    blake3_data = blake3.blake3(data).digest()
    return hmac.new(blake3_key, blake3_data, hashlib.sha3_512).digest()
```

### Paiready Checksum Generation

```
Input: hdprint_string
Output: checksum (7 lowercase chars)

1. Encode HDprint as bit sequence
2. Include case bits for mixed-case chars
3. Apply 5 interleaved BCH(t=1, m=7) codes
4. Encode result as Base58L (lowercase)
5. Return 7-character checksum
```

---

## Rust Implementation Sketch

```rust
use hmac::{Hmac, Mac};
use sha3::Sha3_512;

type HmacSha3_512 = Hmac<Sha3_512>;

const SIZE_PATTERNS: &[(&str, &[usize])] = &[
    ("tiny", &[6]),
    ("small", &[6, 8]),
    ("medium", &[6, 8, 8]),
    ("rack", &[6, 8, 8, 8]),
];

pub fn generate_fingerprint(public_key: &[u8], size: &str) -> String {
    let pattern = get_pattern(size);
    let total_chars: usize = pattern.iter().sum();

    let mut characters = Vec::with_capacity(total_chars);
    let mut current_data = public_key.to_vec();

    for _ in 0..total_chars {
        let hash = hmac_sha3_512(public_key, &current_data);
        let b58 = bs58::encode(&hash).into_string();
        let ch = b58.chars().last().unwrap();
        characters.push(ch);
        current_data = hash.to_vec();
    }

    // Group into segments
    let mut segments = Vec::new();
    let mut idx = 0;
    for &len in pattern {
        let segment: String = characters[idx..idx+len].iter().collect();
        segments.push(segment);
        idx += len;
    }

    segments.join("_")
}

fn hmac_sha3_512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let blake3_key = blake3::hash(key);
    let blake3_data = blake3::hash(data);

    let mut mac = HmacSha3_512::new_from_slice(blake3_key.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(blake3_data.as_bytes());

    let result = mac.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result.into_bytes());
    output
}

fn get_pattern(size: &str) -> &'static [usize] {
    SIZE_PATTERNS
        .iter()
        .find(|(name, _)| *name == size)
        .map(|(_, pattern)| *pattern)
        .unwrap_or(&[6, 8, 8, 8])
}
```

---

## Verification

To verify a fingerprint:

```rust
pub fn verify_fingerprint(
    public_key: &[u8],
    fingerprint: &str,
    size: &str,
) -> bool {
    let expected = generate_fingerprint(public_key, size);
    expected == fingerprint
}
```

---

## Self-Correcting Identifier

Complete identifier with Paiready checksum:

```rust
pub struct SelfCorrectingId {
    pub checksum: String,      // 7 chars, lowercase
    pub fingerprint: String,   // HDprint, mixed case
}

impl SelfCorrectingId {
    pub fn generate(public_key: &[u8], size: &str) -> Self {
        let fingerprint = generate_fingerprint(public_key, size);
        let checksum = generate_paiready_checksum(&fingerprint);
        Self { checksum, fingerprint }
    }

    pub fn to_string(&self) -> String {
        format!("{}_{}", self.checksum, self.fingerprint)
    }

    pub fn parse(input: &str) -> Result<Self, Error> {
        let (checksum, fingerprint) = input.split_once('_')
            .ok_or(Error::InvalidFormat)?;
        // Validate and potentially correct...
        Ok(Self {
            checksum: checksum.to_string(),
            fingerprint: fingerprint.to_string(),
        })
    }

    pub fn verify_and_correct(&self) -> Result<Self, Error> {
        // Apply BCH error correction to checksum
        // Restore case in fingerprint from checksum bits
        // ...
    }
}
```

---

## Security Analysis

### Collision Resistance

- HMAC-SHA3-512 provides 256-bit preimage resistance
- Each character extracts ~5.86 bits (Base58 = 58 symbols)
- MEDIUM size (22 chars) = ~129 bits of entropy
- Birthday attack requires ~2^64 attempts for MEDIUM

### Key Binding

HMAC ensures fingerprint is bound to the public key:

- Cannot forge fingerprint without knowing key
- Cannot find key from fingerprint (preimage resistance)

### Chain Security

Each character depends on all previous via HMAC chain:

- Changing any character changes all subsequent
- No shortcuts to compute later characters

---

## Use Cases in Recrypt

1. **Public key fingerprints:** Human-verifiable identity
2. **File content addressing:** Error-resistant hashes
3. **Share IDs:** User can manually enter/verify
4. **API tokens:** Built-in integrity checking

---

## References

- Python implementation: `python-prototype/src/dcypher/hdprint/algorithms.py`
- BCH codes: `python-prototype/src/dcypher/lib/paiready.py`
- Security analysis: `python-prototype/src/dcypher/hdprint/security.py`
