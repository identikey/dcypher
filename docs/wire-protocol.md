# Wire Protocol: Multiple Serialization Formats

**Status:** ✅ DECIDED  
**Decision:** Support multiple serialization formats; maintenance overhead is minimal

---

## Supported Formats

| Format          | Primary Use              | Content-Type             |
| --------------- | ------------------------ | ------------------------ |
| **Protobuf**    | Wire protocol, storage   | `application/x-protobuf` |
| **ASCII Armor** | Human export, key backup | `text/plain`             |
| **JSON**        | API responses, debugging | `application/json`       |

---

## Format Selection

### Protobuf (Default)

Used for:

- Client ↔ Server communication
- Chunk storage format
- Internal serialization

**Why:**

- Compact (no base64 overhead)
- Fast (zero-copy deserialization with prost)
- Typed (schema-driven, catches errors early)
- Versioned (field numbers enable evolution)

### ASCII Armor

Used for:

- Key export/import
- Manual backup
- Email sharing (if ever needed)
- Human inspection

**Why:**

- Human-readable
- PGP-familiar format
- Copy-paste friendly
- Works in any text editor

### JSON

Used for:

- REST API responses (with content negotiation)
- Debug output
- Configuration files
- Logging

**Why:**

- Universal tooling support
- Easy debugging
- Browser-friendly

---

## Protobuf Schema

```protobuf
syntax = "proto3";
package dcypher.v1;

// Core message types

message FileMetadata {
    uint32 version = 1;
    bytes file_hash = 2;           // Blake3 hash of plaintext (32 bytes)
    bytes wrapped_key = 3;         // PRE-encrypted symmetric key
    bytes bao_root = 4;            // Bao root hash (32 bytes)
    repeated bytes chunk_hashes = 5; // Ordered chunk hashes
    uint64 total_size = 6;
    uint64 created_at = 7;         // Unix timestamp
    MultiSignature signature = 8;
}

message Chunk {
    uint32 index = 1;
    bytes data = 2;                // Encrypted chunk data
    bytes bao_proof = 3;           // Optional Bao slice proof
}

message MultiSignature {
    bytes ed25519_signature = 1;
    repeated PqSignature pq_signatures = 2;
}

message PqSignature {
    string algorithm = 1;          // e.g., "ML-DSA-87"
    bytes public_key = 2;
    bytes signature = 3;
}

// Key types

message PublicKeyBundle {
    bytes ed25519_key = 1;
    repeated PqPublicKey pq_keys = 2;
    bytes pre_public_key = 3;      // OpenFHE PRE public key
}

message PqPublicKey {
    string algorithm = 1;
    bytes key_data = 2;
}

message RecryptKey {
    bytes from_pubkey_fingerprint = 1;  // Blake3 fingerprint of source
    bytes to_pubkey_fingerprint = 2;    // Blake3 fingerprint of destination
    bytes key_data = 3;                 // Serialized OpenFHE rekey
}

// API messages

message UploadRequest {
    FileMetadata metadata = 1;
    repeated Chunk chunks = 2;
}

message DownloadResponse {
    FileMetadata metadata = 1;
    repeated string chunk_urls = 2;     // Pre-signed URLs for chunks
}

message RecryptRequest {
    bytes file_hash = 1;
    bytes recrypt_key_id = 2;
}

message Capability {
    bytes file_hash = 1;
    bytes granted_to = 2;              // Public key fingerprint
    repeated string operations = 3;    // "read", "write", "delete"
    uint64 expires_at = 4;
    bytes issuer_signature = 5;
}
```

---

## ASCII Armor Format

### Structure

```
----- BEGIN DCYPHER {TYPE} -----
{Header}: {Value}
{Header}: {Value}
...

{base64-encoded payload}
----- END DCYPHER {TYPE} -----
```

### Types

- `DCYPHER PUBLIC KEY`
- `DCYPHER SECRET KEY`
- `DCYPHER MESSAGE`
- `DCYPHER CAPABILITY`
- `DCYPHER RECRYPT KEY`

### Example: Public Key

```
----- BEGIN DCYPHER PUBLIC KEY -----
Version: 1
Algorithm: ED25519+ML-DSA-87+PRE
Fingerprint: a3k7x5a_Ab3DeF_Xy9ZmP7q_R2sK1M4V
Created: 2024-01-15T10:30:00Z

eyJlZDI1NTE5IjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FF...
(base64 continues)
----- END DCYPHER PUBLIC KEY -----
```

### Example: Encrypted Message

```
----- BEGIN DCYPHER MESSAGE PART 1/3 -----
Version: 1
FileHash: af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9
BaoRoot: 7d865e959b2466918c9863afca942d0fb89d7c9a
ChunkIndex: 0
TotalChunks: 3

U29tZSBlbmNyeXB0ZWQgZGF0YS4uLg==
(base64 encoded chunk)
----- END DCYPHER MESSAGE PART 1/3 -----
```

---

## JSON Format

For API responses and debugging:

```json
{
  "version": 1,
  "file_hash": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
  "bao_root": "7d865e959b2466918c9863afca942d0fb89d7c9ac54e789c31d21c5c2b2c79f1",
  "total_size": 1048576,
  "chunk_count": 16,
  "created_at": "2024-01-15T10:30:00Z",
  "owner": {
    "fingerprint": "a3k7x5a_Ab3DeF_Xy9ZmP7q_R2sK1M4V"
  },
  "signature": {
    "ed25519": "base64...",
    "pq_signatures": [
      {
        "algorithm": "ML-DSA-87",
        "signature": "base64..."
      }
    ]
  }
}
```

---

## Content Negotiation

HTTP endpoints support content negotiation:

```http
# Request protobuf (default)
GET /api/files/{hash}
Accept: application/x-protobuf

# Request JSON
GET /api/files/{hash}
Accept: application/json

# Request ASCII armor
GET /api/keys/{fingerprint}
Accept: text/plain
```

---

## Implementation

### Rust Traits

```rust
/// Serializable to multiple formats
pub trait MultiFormat: Sized {
    fn to_protobuf(&self) -> Vec<u8>;
    fn from_protobuf(bytes: &[u8]) -> Result<Self>;

    fn to_json(&self) -> String;
    fn from_json(s: &str) -> Result<Self>;

    fn to_armor(&self, armor_type: ArmorType) -> String;
    fn from_armor(s: &str) -> Result<Self>;
}

pub enum ArmorType {
    PublicKey,
    SecretKey,
    Message,
    Capability,
    RecryptKey,
}
```

### Format Detection

```rust
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(b"----- BEGIN DCYPHER") {
        Format::Armor
    } else if data.starts_with(b"{") {
        Format::Json
    } else {
        Format::Protobuf
    }
}

pub fn deserialize_any<T: MultiFormat>(data: &[u8]) -> Result<T> {
    match detect_format(data) {
        Format::Protobuf => T::from_protobuf(data),
        Format::Json => T::from_json(std::str::from_utf8(data)?),
        Format::Armor => T::from_armor(std::str::from_utf8(data)?),
    }
}
```

---

## Size Comparison

For a 1MB file with 16 chunks:

| Format      | Metadata Size | Chunk Overhead | Total Overhead |
| ----------- | ------------- | -------------- | -------------- |
| Protobuf    | ~500 bytes    | ~0.1%          | ~0.15%         |
| JSON        | ~2 KB         | ~0.5%          | ~0.7%          |
| ASCII Armor | ~3 KB         | ~33% (base64)  | ~35%           |

**Recommendation:** Use Protobuf for wire/storage, ASCII armor only for export.

---

## Version Evolution

### Protobuf

Add new fields with new field numbers; old clients ignore unknown fields:

```protobuf
message FileMetadata {
    // ... existing fields ...

    // New in v2
    optional string description = 10;
    optional bytes thumbnail = 11;
}
```

### JSON

Add new fields; old clients ignore unknown fields:

```json
{
  "version": 2,
  "existing_field": "...",
  "new_field": "ignored by v1 clients"
}
```

### ASCII Armor

Add new headers; old parsers ignore unknown headers:

```
----- BEGIN DCYPHER PUBLIC KEY -----
Version: 2
NewHeader: new value
...
```

---

## Dependencies

```toml
[dependencies]
prost = "0.12"
prost-types = "0.12"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.21"

[build-dependencies]
prost-build = "0.12"
```

---

## References

- [Protocol Buffers](https://developers.google.com/protocol-buffers)
- [prost crate](https://docs.rs/prost)
- [OpenPGP ASCII Armor](https://datatracker.ietf.org/doc/html/rfc4880#section-6)
