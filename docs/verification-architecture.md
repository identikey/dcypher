# Verification Architecture: Blake3/Bao Tree Mode

**Status:** ✅ DECIDED  
**Decision:** Use Blake3's built-in Bao tree mode for streaming verification

---

## Summary

File integrity verification uses Blake3's Bao (Blake3 Authenticated Output) tree mode, enabling:

- Streaming chunk verification as data arrives
- Parallel hashing and verification
- No manual Merkle tree construction
- Implicit auth paths (no per-chunk overhead)

---

## Why Bao?

### Comparison with Manual Merkle Tree

| Aspect                 | Manual Merkle (Python) | Bao Tree (Rust)      |
| ---------------------- | ---------------------- | -------------------- |
| Implementation         | Custom code            | Library handles it   |
| Auth path transmission | O(log n) per chunk     | Implicit in encoding |
| Parallelism            | Manual threading       | Built-in             |
| Streaming verification | Complex                | Native support       |
| Battle-tested          | Our code               | Blake3 authors' code |

### Key Benefits

1. **Streaming verification:** Verify chunks as they arrive, no need to buffer entire file
2. **Parallel hashing:** Automatically uses all CPU cores
3. **Implicit proofs:** Auth paths encoded in the Bao format itself
4. **Single root hash:** File identity = 32-byte Blake3 hash

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FILE DATA                                │
│  [chunk 0] [chunk 1] [chunk 2] ... [chunk n]                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      BAO ENCODER                                 │
│  - Computes Blake3 tree over chunks                             │
│  - Produces root hash (file identity)                           │
│  - Optionally produces "outboard" tree (for streaming)          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      OUTPUT                                      │
│  - root_hash: [u8; 32]     (file identity, stored in metadata)  │
│  - encoded_data: Vec<u8>   (interleaved data + tree nodes)      │
│  - OR outboard: Vec<u8>    (tree nodes only, data separate)     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### Encoding (Sender)

```rust
use bao::encode;

// Simple: encode entire file
fn encode_file(data: &[u8]) -> (bao::Hash, Vec<u8>) {
    let (encoded, hash) = encode::encode(data);
    (hash, encoded)
}

// Streaming: encode chunk by chunk
fn encode_streaming(chunks: impl Iterator<Item = Vec<u8>>) -> (bao::Hash, Vec<u8>) {
    let mut encoder = encode::Encoder::new(Vec::new());
    for chunk in chunks {
        encoder.write_all(&chunk).unwrap();
    }
    let (output, hash) = encoder.finalize();
    (hash, output)
}

// Outboard mode: keep data separate from tree
fn encode_outboard(data: &[u8]) -> (bao::Hash, Vec<u8>) {
    let mut outboard = Vec::new();
    let hash = encode::outboard(data, &mut outboard);
    (hash, outboard)
}
```

### Decoding/Verification (Receiver)

```rust
use bao::decode;

// Simple: verify and decode entire file
fn verify_file(encoded: &[u8], expected_hash: &bao::Hash) -> Result<Vec<u8>, Error> {
    decode::decode(encoded, expected_hash)
}

// Streaming: verify chunks as they arrive
fn verify_streaming(
    encoded_stream: impl Read,
    expected_hash: &bao::Hash,
) -> Result<Vec<u8>, Error> {
    let mut decoder = decode::Decoder::new(encoded_stream, expected_hash);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;  // Fails immediately on tampered chunk
    Ok(output)
}

// Outboard mode: verify with separate tree
fn verify_outboard(
    data: &[u8],
    outboard: &[u8],
    expected_hash: &bao::Hash,
) -> Result<(), Error> {
    decode::decode_outboard(data, outboard, expected_hash)?;
    Ok(())
}
```

### Slice Extraction (Random Access)

Bao supports extracting verified slices without downloading entire file:

```rust
use bao::encode::SliceExtractor;

// Extract verified slice from encoded data
fn extract_slice(
    encoded: &[u8],
    start: u64,
    len: u64,
) -> Vec<u8> {
    let mut extractor = SliceExtractor::new(
        std::io::Cursor::new(encoded),
        start,
        len,
    );
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice).unwrap();
    slice
}

// Verify extracted slice
fn verify_slice(
    slice: &[u8],
    expected_hash: &bao::Hash,
    start: u64,
    len: u64,
) -> Result<Vec<u8>, Error> {
    let mut decoder = decode::SliceDecoder::new(
        std::io::Cursor::new(slice),
        expected_hash,
        start,
        len,
    );
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}
```

---

## Storage Modes

### Combined Mode (Interleaved)

Data and tree nodes interleaved in single blob:

```
[header][node][data][node][data]...
```

**Pros:** Single file, streaming verification works
**Cons:** ~6% size overhead, must re-encode to modify

### Outboard Mode

Tree stored separately from data:

```
data.bin   → original file (unchanged)
data.obao  → tree nodes only
```

**Pros:** Original file unmodified, tree is small (~0.01% of file)
**Cons:** Two files to manage, need both for verification

### Recommendation

Use **outboard mode** for storage:

- Original encrypted chunks stored as-is in S3
- Bao tree stored in metadata or alongside
- Enables verification without re-encoding

---

## Wire Protocol Integration

### File Upload

1. Client computes Bao hash while uploading chunks
2. Final root hash sent as file identity
3. Server can verify chunks incrementally

### File Download

1. Client requests file by root hash
2. Server streams chunks with Bao encoding
3. Client verifies each chunk as it arrives
4. Immediate rejection of tampered data

### Chunk Format

```protobuf
message FileChunk {
    uint32 index = 1;
    bytes data = 2;
    bytes bao_proof = 3;  // For slice mode
}
```

---

## Security Properties

1. **Integrity:** Any modification detected immediately
2. **Streaming:** Don't need full file to verify partial content
3. **Random access:** Can verify arbitrary slices
4. **Collision resistance:** 128-bit security (256-bit hash, birthday bound)
5. **Deterministic:** Same file always produces same root hash

---

## Dependencies

```toml
[dependencies]
blake3 = "1"
bao = "0.12"
```

---

## References

- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [bao crate documentation](https://docs.rs/bao)
- [Blake3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
