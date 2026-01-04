# dCypher Rust Port: Master Implementation Plan

**Status:** Design & Specification Phase  
**Target:** Production-ready quantum-resistant proxy recryption system  
**No Compatibility Required:** Clean slate, zero legacy constraints

---

## Executive Summary

Port dCypher from Python prototype to production Rust implementation. The Python codebase served its purpose as proof-of-concept for proxy recryption with post-quantum signatures. The Rust port will be architecturally sound, performant, and production-ready with proper separation of concerns.

**Core Innovation:** Proxy recryption enables untrusted storage where files stay encrypted end-to-end but can be shared/revoked via cryptographic transformation rather than key sharing.

---

## Design Philosophy Changes

### What We're Keeping
- ✅ Proxy recryption via OpenFHE lattice crypto
- ✅ Post-quantum signatures (ML-DSA-87, etc via liboqs)
- ✅ Dual classical keys (ED25519 only, **dropping ECDSA/SECP256k1**)
- ✅ HDprint self-correcting identifiers
- ✅ Multi-signature authorization pattern
- ✅ Nonce-based replay prevention
- ✅ Chunked streaming architecture

### What We're Changing
- ❌ **No ECDSA/SECP256k1** - Unnecessary complexity, ED25519 sufficient for classical fallback
- ❌ **No naive file storage** - Moving to S3-compatible API (Minio for dev)
- ❌ **No IDK ASCII armor as primary format** - More efficient wire protocol needed
- 🔄 **Reconsider encryption approach** - Full-file asymmetric vs hybrid symmetric/asymmetric (PGP-style)
- 🔄 **Standardize hashing** - Blake2b vs Blake3 analysis needed
- 🔄 **HMAC usage review** - Ensure appropriate application
- 🔄 **Hierarchical verification** - Enable streaming chunk verification

### What We're Building New
- 🆕 **S3-compatible storage layer** - Authenticated access via file hash lookup
- 🆕 **Efficient wire protocol** - Binary serialization for performance
- 🆕 **Minimal rad TUI** - Inherit spirit, lose bloat
- 🆕 **Proper Rust architecture** - Workspace with focused crates

---

## Critical Design Questions (Answer Before Coding)

### 1. Encryption Architecture
**Question:** Full-file asymmetric vs hybrid approach?

**Analysis Required:**
- **Pure Asymmetric:** Encrypt entire file with OpenFHE PRE
  - ✅ Simple model: one ciphertext per file
  - ✅ Direct recryption transformation
  - ❌ Performance: FHE expensive for large files
  - ❌ Size overhead: ciphertext expansion significant

- **Hybrid (PGP-style):** Symmetric file encryption + asymmetric key wrapping
  - ✅ Performance: AES/ChaCha20 for bulk data
  - ✅ Small ciphertext: only symmetric key encrypted with FHE
  - ❌ Complexity: two-stage encryption/decryption
  - ❌ Recryption: must transform wrapped key, not file
  - ⚠️  Security: ensure key derivation sound

**Decision Criteria:**
- Performance benchmarks: encrypt/decrypt 1MB, 10MB, 100MB files
- Security analysis: hybrid construction proof
- Ciphertext size comparison
- Streaming capability requirements

**Document in:** `docs/crypto-architecture.md`

---

### 2. Hashing Standardization
**Question:** Blake2b vs Blake3 - when to use each?

**Current State (Python prototype):**
- Blake2b: Merkle trees, chunk hashes, IDK message integrity
- Blake3: HDprint preprocessing (before HMAC-SHA3-512)
- HMAC-SHA3-512: HDprint fingerprint generation

**Analysis Required:**
- **Blake2b advantages:** Mature, simpler, widely deployed
- **Blake3 advantages:** Parallelizable, faster, tree mode built-in
- **HMAC-SHA3-512:** Strong but potentially overkill

**Standardization Options:**
1. **Blake3 everywhere:** Modern choice, best performance
2. **Blake2b everywhere:** Conservative choice, battle-tested
3. **Strategic split:** Blake3 for data, Blake2b for legacy compat (but we don't need compat!)

**Decision Criteria:**
- Performance benchmarks on target hardware
- Security analysis: both are solid, pick on engineering grounds
- Ecosystem support in Rust (both have excellent crates)

**Document in:** `docs/hashing-standard.md`

---

### 3. HMAC Usage Review
**Question:** Where is HMAC appropriate vs plain hashing?

**Current Usage (Python prototype):**
- HMAC-SHA3-512 in HDprint fingerprint generation
- HMAC provides key-based authentication

**Analysis Required:**
- **When HMAC needed:** Keyed integrity, authentication tags
- **When plain hash sufficient:** Content addressing, Merkle trees
- **HDprint case:** Is key-based fingerprint necessary? Or can we use Blake3(public_key || data)?

**Decision Criteria:**
- Threat model: what attacks does HMAC prevent here?
- Performance: HMAC overhead vs plain hash
- Simplicity: fewer primitives = easier audit

**Document in:** `docs/hmac-analysis.md`

---

### 4. Hierarchical Verification Architecture
**Question:** How to enable streaming verification of chunks?

**Requirements:**
- ✅ Verify individual chunks as they arrive (low latency)
- ✅ Verify entire file integrity (security)
- ✅ Support partial downloads (range requests)
- ✅ Enable parallel chunk processing

**Design Options:**

**Option A: Merkle Tree (Current)**
- Root hash = file identity
- Auth paths allow per-chunk verification
- ✅ Well understood, proven security
- ❌ Need to transmit auth paths with chunks
- ❌ Root hash must be known/trusted upfront

**Option B: Blake3 Tree Mode**
- Blake3 has built-in Merkle tree construction
- Can verify chunks with only root hash + chunk positions
- ✅ Simpler implementation (library handles it)
- ✅ Parallelizable by design
- ⚠️  Less battle-tested than Merkle tree construction

**Option C: Hybrid**
- Blake3 for content hashing (fast, parallel)
- Separate Merkle tree for verification structure
- ✅ Best of both worlds
- ❌ More complexity

**Decision Criteria:**
- Streaming verification performance
- Implementation complexity
- Wire protocol efficiency (how much verification data per chunk?)

**Document in:** `docs/verification-architecture.md`

---

### 5. Non-Deterministic Operations
**Question:** What operations are non-deterministic and why does it matter?

**Known Non-Determinism in Python Prototype:**
- ⚠️  **OpenFHE Serialization (line 269):** Same object → different bytes on re-serialize
  - Impact: Can't use byte-level equality for testing
  - Impact: Can't use serialized form as content hash
  - Solution: Semantic equivalence tests, not byte comparison

- ⚠️  **Post-Quantum Signatures:** Many PQ schemes include randomness
  - Impact: Same message + key → different signature each time
  - Impact: Can't rely on signature as deterministic identifier
  - Solution: Verify signatures, don't compare them

**Critical for Rust Port:**
- ✅ Crypto context management: must keep same context instance for related operations
- ✅ Testing strategy: validate cryptographic properties, not byte equality
- ✅ Content addressing: hash plaintext or deterministic representation, not ciphertext
- ✅ Idempotency: operations must be repeatable even if bytes differ

**Document in:** `docs/non-determinism.md`

---

### 6. S3-Compatible Storage Design
**Question:** How to integrate S3 for production storage?

**Requirements:**
- ✅ Local dev: Minio in Docker
- ✅ Production: Any S3-compatible service (AWS, Backblaze, etc)
- ✅ Authenticated access via file hash
- ✅ Support chunked uploads/downloads
- ✅ Range request support for partial retrieval

**Design Sketch:**
```
Storage Layer API:
  - put_chunk(hash, data) -> Result<()>
  - get_chunk(hash) -> Result<Vec<u8>>
  - list_chunks(prefix) -> Result<Vec<ChunkMetadata>>
  - delete_chunk(hash) -> Result<()>

Implementations:
  - MinioStorage (dev)
  - S3Storage (prod)
  - LocalFileStorage (testing)
```

**Key Decisions:**
- **Bucket structure:** One bucket per user? Or shared bucket with namespacing?
- **Object naming:** `/user/{pubkey}/chunks/{hash}` or content-addressed `/chunks/{hash}`?
- **Metadata storage:** S3 object metadata or separate index?
- **Authentication:** Pre-signed URLs? IAM roles? Custom auth layer?

**Document in:** `docs/storage-design.md`

---

### 7. IDK Message Format Revision
**Question:** What should the wire protocol look like?

**Current (ASCII Armor):**
```
----- BEGIN IDK MESSAGE PART 1/8 -----
Headers (key: value)

<base64 payload>
----- END IDK MESSAGE PART 1/8 -----
```

**Pros:** Human-readable, debuggable, PGP-familiar
**Cons:** Size overhead (base64 ~33%), parsing complexity

**New Design Options:**

**Option A: Binary Protocol (Efficient)**
- Protocol Buffers / Cap'n Proto / Flatbuffers
- ✅ Compact: no base64, no text headers
- ✅ Fast: zero-copy deserialization
- ❌ Not human-readable
- ❌ Debugging harder

**Option B: Hybrid**
- Binary for wire protocol performance
- ASCII armor as export/import format for human use
- ✅ Best of both worlds
- ❌ Two serialization paths to maintain

**Decision Criteria:**
- Performance: serialize/deserialize benchmarks
- Debuggability: how often do we need to inspect?
- Tooling: can we build good debug tools for binary format?

**Headers to Revisit:**
- Which headers actually needed?
- Can we compress/deduplicate repeated headers?
- Version negotiation strategy

**Document in:** `docs/wire-protocol.md`

---

## HDprint System: Full Specification

### What It Is
Self-correcting hierarchical identifier system combining:
- **Paiready checksum:** BCH error-correcting, Base58L lowercase
- **HDprint fingerprint:** HMAC-SHA3-512 chain, hierarchical scaling

### Format
```
{paiready}_{hdprint}
myzgemb_5ubrZa_T9w1LJRx_hEGmdyaM
```

### Key Benefits

**1. Error Correction**
- Single character typos automatically corrected
- User types: `1pk2bdr_...` (2 errors in checksum)
- System corrects to: `4pkabdr_...`
- Implementation: 5× BCH(t=1, m=7) interleaved codes

**2. Case Insensitivity**
- User types everything lowercase: `myzgemb_5ubrza_t9w1ljrx_hegmdyam`
- System restores proper case: `myzgemb_5ubrZa_T9w1LJRx_hEGmdyaM`
- Implementation: Case bit field encoded in checksum

**3. Hierarchical Scaling**
- TINY: 17.6 bits security (testing)
- SMALL: 64.4 bits (low security)
- MEDIUM: 111.3 bits (standard)
- RACK: 158.2 bits (high security)
- Multiple racks for even higher security

**4. Human Friendly**
- Base58 encoding (no confusing chars: 0/O, 1/l)
- Underscore separators for visual parsing
- Meaningful structure: checksum first, then hierarchical segments

### Use Cases in dCypher
- Public key fingerprints (human-verifiable)
- File content addressing (error-resistant)
- Share IDs (user can manually enter/verify)
- API tokens (built-in integrity checking)

### Security Properties
- **Collision Resistance:** HMAC-SHA3-512 base provides >256-bit security
- **Preimage Resistance:** Can't reverse engineer source from identifier
- **Second Preimage Resistance:** Can't find different input with same identifier

### Implementation Notes
- **Algorithm:** BLAKE3 preprocessing → HMAC-SHA3-512 iterative chain
- **Key Material:** Can use public key, file hash, or any unique data
- **Deterministic:** Same input → same identifier (important for testing)
- **Efficient:** Sub-millisecond generation for MEDIUM size

**Document in:** `docs/hdprint-specification.md`

---

## Implementation Phases

### Phase 0: Planning & Specification (Current)
**Duration:** 2-3 days  
**Deliverables:**
- ✅ This master plan
- 🔲 Answer all 7 design questions above
- 🔲 Architecture decision records for each question
- 🔲 Rust workspace structure defined
- 🔲 Dependency analysis (crates needed)

**Design Docs to Write:**
1. `docs/crypto-architecture.md` - Encryption approach decision
2. `docs/hashing-standard.md` - Blake2b vs Blake3 + HMAC analysis
3. `docs/verification-architecture.md` - Streaming chunk verification
4. `docs/non-determinism.md` - Testing strategy for non-deterministic crypto
5. `docs/storage-design.md` - S3 integration architecture
6. `docs/wire-protocol.md` - Binary vs ASCII armor decision
7. `docs/hdprint-specification.md` - Full HDprint writeup

---

### Phase 1: Rust Workspace Setup & FFI Foundations
**Duration:** 3-5 days  
**Goal:** Get OpenFHE and liboqs working in Rust

**Tasks:**
1. Create workspace structure:
   ```
   dcypher-rust/
   ├── Cargo.toml (workspace)
   ├── crates/
   │   ├── dcypher-ffi/      # START HERE
   │   ├── dcypher-core/     
   │   ├── dcypher-proto/    
   │   ├── dcypher-storage/  
   │   └── dcypher-hdprint/  
   ├── dcypher-cli/          
   ├── dcypher-server/       
   └── docs/
   ```

2. **dcypher-ffi crate:**
   - OpenFHE bindings via cxx
   - Reference: `vendor/openfhe-rs/` in Python repo
   - liboqs bindings (check crates.io first, may exist)
   - ED25519 via libsodium or RustCrypto
   - Build system: `build.rs` with cxx-build
   - Basic smoke tests: encrypt/decrypt roundtrip

3. **Validation:**
   - Can create crypto context in Rust
   - Can generate keypairs
   - Can encrypt/decrypt small message
   - Can generate recryption key
   - Can perform recryption transformation
   - Decrypt after recryption succeeds

**Non-Determinism Note:**
- Write tests that validate cryptographic properties (plaintext recovered)
- NOT byte-level comparison of ciphertexts/serialized keys

**Dependencies to evaluate:**
- `cxx` for OpenFHE bindings
- `oqs-sys` or `pqcrypto` for liboqs (check which is maintained)
- `ed25519-dalek` for ED25519 signatures
- `blake3` crate for hashing (assuming we standardize on Blake3)

---

### Phase 2: Core Cryptography (dcypher-core)
**Duration:** 4-5 days  
**Goal:** Production-ready crypto operations library

**Architecture:**
```rust
dcypher-core/
├── src/
│   ├── lib.rs
│   ├── context.rs      // Crypto context management
│   ├── keys.rs         // Key generation, serialization
│   ├── encrypt.rs      // Encryption operations
│   ├── recrypt.rs      // Recryption operations (NOTE: "recrypt" not "re_encrypt")
│   ├── sign.rs         // ED25519 + PQ signatures
│   └── types.rs        // Core types: PublicKey, SecretKey, Ciphertext, RecryptKey
└── tests/
    ├── roundtrip.rs    // Basic encrypt/decrypt
    ├── recryption.rs   // Full Alice->Bob flow
    └── signatures.rs   // Multi-sig verification
```

**Key Design Decisions:**
- **Encryption approach:** Implement decision from Phase 0 (full-file vs hybrid)
- **Context management:** Singleton pattern or explicit passing? (Recommend explicit for testability)
- **Error handling:** Custom error types with `thiserror`
- **Async or sync:** Start sync, async can wrap later if needed

**API Sketch:**
```rust
// Core encryption operations
pub fn encrypt(ctx: &CryptoContext, pk: &PublicKey, data: &[u8]) -> Result<Ciphertext>;
pub fn decrypt(ctx: &CryptoContext, sk: &SecretKey, ct: &Ciphertext) -> Result<Vec<u8>>;

// Recryption operations (NOTE: "recrypt" terminology)
pub fn generate_recrypt_key(ctx: &CryptoContext, from_sk: &SecretKey, to_pk: &PublicKey) -> Result<RecryptKey>;
pub fn recrypt(ctx: &CryptoContext, rk: &RecryptKey, ct: &Ciphertext) -> Result<Ciphertext>;

// Multi-signature
pub struct MultiSig {
    ed25519_sig: Signature,
    pq_sigs: Vec<PqSignature>,
}
pub fn sign_message(msg: &[u8], keys: &SigningKeys) -> Result<MultiSig>;
pub fn verify_message(msg: &[u8], sig: &MultiSig, pks: &VerifyingKeys) -> Result<bool>;
```

**Testing Strategy:**
- Property-based tests with `proptest`:
  - encrypt(decrypt(x)) == x
  - decrypt_bob(recrypt(encrypt_alice(x))) == x
  - verify(sign(msg)) == true
- Known-answer tests with fixed keys (for regression)
- Performance benchmarks with `criterion`

**Critical:** Document non-determinism in tests
- Ciphertext bytes will differ each run (randomness)
- Serialized keys may differ (OpenFHE non-canonical)
- Test semantic equivalence, not byte equality

---

### Phase 3: Protocol Layer (dcypher-proto)
**Duration:** 3-4 days  
**Goal:** Wire protocol for serialization/deserialization

**Architecture:**
```rust
dcypher-proto/
├── src/
│   ├── lib.rs
│   ├── wire.rs         // Binary wire format (protobuf/capnp/flatbuf)
│   ├── armor.rs        // ASCII armor format (optional, for export)
│   ├── merkle.rs       // Merkle tree construction + verification
│   └── message.rs      // High-level message construction
└── tests/
    ├── serialization.rs
    └── verification.rs
```

**Key Decisions (from Phase 0):**
- Wire format: Binary (protobuf?) for performance
- ASCII armor: Optional export format for human debugging
- Merkle vs Blake3 tree mode for verification
- Header fields to include (revisit IDK spec)

**Message Types:**
```rust
// Core message structure
pub struct DcypherMessage {
    pub version: u32,
    pub chunks: Vec<Chunk>,
    pub metadata: Metadata,
    pub signatures: MultiSig,
}

pub struct Chunk {
    pub index: u32,
    pub ciphertext: Ciphertext,
    pub proof: VerificationProof, // Merkle path or Blake3 proof
}

pub struct Metadata {
    pub file_hash: Hash,
    pub chunk_count: u32,
    pub total_size: u64,
    // ... other fields TBD in Phase 0
}
```

**Verification Flow:**
- Compute chunk hash
- Verify against proof + root hash
- Verify signature over metadata
- Return verified chunk OR error

**Testing:**
- Round-trip serialization
- Merkle tree proofs for various tree sizes
- Signature verification
- Malformed message handling

---

### Phase 4: Storage Layer (dcypher-storage)
**Duration:** 3-4 days  
**Goal:** S3-compatible storage abstraction

**Architecture:**
```rust
dcypher-storage/
├── src/
│   ├── lib.rs
│   ├── traits.rs       // Storage trait abstraction
│   ├── s3.rs           // S3/Minio implementation
│   ├── local.rs        // Local filesystem (testing)
│   └── chunking.rs     // Chunk management logic
└── tests/
    ├── s3_integration.rs    // Requires Minio running
    └── local_storage.rs
```

**Storage Trait:**
```rust
#[async_trait]
pub trait ChunkStorage {
    async fn put_chunk(&self, hash: &Hash, data: &[u8]) -> Result<()>;
    async fn get_chunk(&self, hash: &Hash) -> Result<Vec<u8>>;
    async fn exists(&self, hash: &Hash) -> Result<bool>;
    async fn delete_chunk(&self, hash: &Hash) -> Result<()>;
    async fn list_chunks(&self, prefix: &str) -> Result<Vec<ChunkMetadata>>;
}
```

**Implementations:**
1. **MinioStorage** - Development environment
   - Uses `rusoto_s3` or `aws-sdk-rust`
   - Docker compose for local Minio
   - Configuration via env vars

2. **S3Storage** - Production
   - Same interface, different endpoint
   - Supports any S3-compatible service

3. **LocalFileStorage** - Testing
   - Simple filesystem backend
   - No external dependencies
   - Fast for unit tests

**Key Design (from Phase 0):**
- Authenticated access model
- Bucket/object naming scheme
- Metadata handling strategy

**Testing:**
- Unit tests with LocalFileStorage
- Integration tests with Minio (Docker)
- Error handling: network failures, permission errors
- Concurrent access patterns

**Docker Compose for Dev:**
```yaml
version: '3'
services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
```

---

### Phase 5: HDprint Implementation (dcypher-hdprint)
**Duration:** 2-3 days  
**Goal:** Self-correcting identifier system

**Architecture:**
```rust
dcypher-hdprint/
├── src/
│   ├── lib.rs
│   ├── hdprint.rs      // Hierarchical fingerprint generation
│   ├── paiready.rs     // BCH error-correcting checksum
│   ├── bch.rs          // BCH codec implementation
│   └── base58.rs       // Base58/Base58L encoding
└── tests/
    ├── generation.rs   // Deterministic identifier generation
    ├── correction.rs   // Error correction validation
    └── roundtrip.rs    // Case restoration
```

**Python Reference:**
- Most implementation in `src/dcypher/hdprint/`
- Can mostly port directly, well-contained
- May need Rust BCH library or port from Python

**Key Features to Preserve:**
- Deterministic generation (same input → same output)
- Single char error correction in checksum
- Case restoration from lowercase input
- Hierarchical scaling (tiny/small/medium/rack)

**Testing:**
- Known-answer tests from Python prototype
- Error correction: inject typos, verify correction
- Case round-trip: lowercase input → proper case output
- Performance: generation should be <1ms for MEDIUM size

---

### Phase 6: HTTP API Server (dcypher-server)
**Duration:** 4-5 days  
**Goal:** Production REST API with Axum

**Architecture:**
```rust
dcypher-server/
├── src/
│   ├── main.rs
│   ├── routes/
│   │   ├── accounts.rs
│   │   ├── files.rs
│   │   ├── recryption.rs   // NOTE: "recryption" terminology
│   │   └── health.rs
│   ├── auth.rs             // Nonce + signature verification
│   ├── state.rs            // Application state
│   └── error.rs            // Error responses
└── tests/
    └── integration/
        ├── accounts_test.rs
        ├── recryption_test.rs
        └── e2e_test.rs
```

**Framework:** Axum (modern, fast, well-integrated with Tower)

**API Routes:**
```
POST   /accounts                    - Create account (ED25519 + PQ keys)
GET    /accounts/{pubkey}           - Get account info
POST   /accounts/{pubkey}/keys      - Add/remove PQ keys
GET    /accounts/{pubkey}/files     - List files

POST   /files/{hash}/register       - Start file upload
POST   /files/{hash}/chunks         - Upload chunk
GET    /files/{hash}/chunks/{n}     - Download chunk
GET    /files/{hash}                - Download complete file

POST   /recryption/share            - Create share policy
GET    /recryption/shares/{pubkey}  - List shares
GET    /recryption/share/{id}       - Download shared file (with recryption)
DELETE /recryption/share/{id}       - Revoke share

GET    /health                      - Health check
```

**Key Features:**
- Multi-signature verification middleware
- Nonce-based replay prevention
- Rate limiting (Tower middleware)
- Structured logging with `tracing`
- Metrics with `metrics` crate
- Graceful shutdown

**Configuration:**
```rust
pub struct Config {
    pub host: String,
    pub port: u16,
    pub storage_backend: StorageConfig,
    pub crypto_params: CryptoParams,
    pub nonce_window: Duration,
}
```

**Testing:**
- Unit tests for each route handler
- Integration tests with test client
- E2E tests: full Alice->Bob sharing flow
- Load testing with `drill` or similar

---

### Phase 7: CLI Application (dcypher-cli)
**Duration:** 3-4 days  
**Goal:** User-friendly command-line interface

**Architecture:**
```rust
dcypher-cli/
├── src/
│   ├── main.rs
│   ├── commands/
│   │   ├── identity.rs   // Key management
│   │   ├── encrypt.rs
│   │   ├── decrypt.rs
│   │   ├── share.rs
│   │   └── files.rs
│   ├── client.rs         // HTTP client for server
│   └── config.rs         // CLI config management
└── tests/
    └── cli_tests.rs
```

**CLI Framework:** `clap` v4 with derive macros

**Command Structure:**
```
dcypher identity new [--output identity.json]
dcypher identity show <identity-file>

dcypher keys generate
dcypher keys inspect <pubkey>

dcypher encrypt <file> --for <pubkey> --output <file.enc>
dcypher decrypt <file.enc> --with <identity> --output <file>

dcypher share create <file-hash> --to <pubkey>
dcypher share list
dcypher share revoke <share-id>

dcypher files upload <file> [--server http://localhost:8000]
dcypher files download <file-hash> --output <file>
dcypher files list

dcypher server start [--config server.toml]
```

**Key Features:**
- Interactive prompts with `dialoguer` for sensitive operations
- Progress bars with `indicatif` for uploads/downloads
- Colored output with `colored`
- Config file support (TOML)
- Shell completions generation

**Identity File Format:**
```json
{
  "version": "1.0",
  "public_key": {
    "ed25519": "...",
    "pq_keys": [{"alg": "ML-DSA-87", "key": "..."}],
    "pre_key": "..."
  },
  "secret_key": {
    "ed25519": "...",
    "pq_keys": [{"alg": "ML-DSA-87", "key": "..."}],
    "pre_key": "..."
  },
  "crypto_context": "..." // Serialized context
}
```

**Testing:**
- Command parsing tests
- Integration tests with mock server
- E2E tests with real server

---

### Phase 8: Minimal Rad TUI (dcypher-tui)
**Duration:** 2-3 days  
**Goal:** Inherit spirit, lose bloat

**Framework:** `ratatui` (formerly tui-rs) - lightweight, no heavy deps

**Screens (Minimal Set):**
1. **Dashboard** - System status, active operations
2. **Files** - Browse, upload, download
3. **Sharing** - Create/revoke shares
4. **Keys** - Identity management

**What We're NOT Building:**
- ❌ CPU/memory monitoring widgets
- ❌ ASCII art animations
- ❌ Matrix rain effects
- ❌ Extensive profiling UI

**Rad Spirit Elements:**
- ✅ Clean cyberpunk color scheme
- ✅ Clear visual hierarchy
- ✅ Real-time operation feedback
- ✅ Keyboard-first navigation
- ✅ Instant responsiveness

**Testing:**
- UI component tests
- Integration tests with mock backend
- Snapshot tests for layout

---

## Workspace Structure (Final)

```
dcypher/
├── README.md
├── Cargo.toml                      # Workspace root
├── Cargo.lock
│
├── crates/
│   ├── dcypher-ffi/                # OpenFHE + liboqs FFI bindings
│   │   ├── Cargo.toml
│   │   ├── build.rs                # cxx-build integration
│   │   └── src/
│   │
│   ├── dcypher-core/               # Core crypto operations
│   │   ├── Cargo.toml
│   │   └── src/
│   │
│   ├── dcypher-proto/              # Wire protocol + serialization
│   │   ├── Cargo.toml
│   │   └── src/
│   │
│   ├── dcypher-storage/            # S3-compatible storage layer
│   │   ├── Cargo.toml
│   │   └── src/
│   │
│   └── dcypher-hdprint/            # Self-correcting identifiers
│       ├── Cargo.toml
│       └── src/
│
├── dcypher-cli/                    # CLI binary
│   ├── Cargo.toml
│   └── src/
│
├── dcypher-server/                 # HTTP API server binary
│   ├── Cargo.toml
│   └── src/
│
├── dcypher-tui/                    # TUI binary
│   ├── Cargo.toml
│   └── src/
│
├── docs/                           # Design documents
│   ├── crypto-architecture.md
│   ├── hashing-standard.md
│   ├── verification-architecture.md
│   ├── non-determinism.md
│   ├── storage-design.md
│   ├── wire-protocol.md
│   └── hdprint-specification.md
│
├── python-prototype/               # ARCHIVED: Original Python implementation
│   └── [all existing Python code]
│
└── docker/
    ├── docker-compose.dev.yml      # Minio + services for development
    └── Dockerfile                  # Production build
```

---

## Key Dependencies (Preliminary)

### Cryptography
- `cxx` - C++/Rust FFI for OpenFHE bindings
- `oqs-sys` or `pqcrypto` - Post-quantum crypto via liboqs
- `ed25519-dalek` - ED25519 signatures
- `blake3` - Hashing (pending standardization decision)
- `rand` + `rand_core` - Cryptographic RNG

### Serialization
- `serde` + `serde_json` - Config files, identity files
- `prost` or `capnp` or `flatbuffers` - Wire protocol (TBD)
- `base64` - ASCII armor encoding
- `hex` - Hex encoding for debugging

### Storage
- `aws-sdk-rust` or `rusoto_s3` - S3 API client
- `tokio` - Async runtime
- `tower` + `tower-http` - HTTP middleware

### Server
- `axum` - HTTP framework
- `tracing` + `tracing-subscriber` - Structured logging
- `metrics` + `metrics-exporter-prometheus` - Observability
- `tower-http` - CORS, compression, rate limiting

### CLI/TUI
- `clap` - CLI argument parsing
- `ratatui` - TUI framework
- `dialoguer` - Interactive prompts
- `indicatif` - Progress bars
- `colored` - Terminal colors

### Development
- `thiserror` - Error handling
- `anyhow` - Error propagation in binaries
- `proptest` - Property-based testing
- `criterion` - Benchmarking
- `mockall` - Mocking for tests

---

## Migration Notes from Python Prototype

### Files to Reference (Now Archived)
```
python-prototype/
├── src/dcypher/lib/pre.py          # Core crypto operations
├── src/dcypher/lib/idk_message.py  # Message format (needs revision)
├── src/dcypher/hdprint/            # HDprint implementation (port directly)
├── src/dcypher/routers/            # API endpoint logic
└── docs/spec.md                    # Original IDK spec (update for Rust)
```

### What NOT to Port
- ❌ `dcypher/lib/auth.py` - ECDSA verification (dropping SECP256k1)
- ❌ `dcypher/routers/storage.py` - Naive file storage (moving to S3)
- ❌ `dcypher/tui/widgets/` - Heavy widgets (minimal TUI instead)
- ❌ `dcypher/lib/profiling.py` - Profiling infrastructure (use Rust tooling)
- ❌ Test harness for Python-Rust compatibility (not needed)

### Terminology Migration
- `re_encrypt` → `recrypt`
- `re_encryption_key` → `recrypt_key`
- `rekey` → `recrypt_key` (consistent naming)
- Everything else: `recryption` (already correct)

### No Compatibility Requirements
- ✅ Can't decrypt Python ciphertexts with Rust (different serialization)
- ✅ Can't verify Python signatures with Rust (different key formats)
- ✅ Can't parse Python IDK messages with Rust (format changing)
- ✅ Fresh start = clean design

**This is a feature, not a bug.**

---

## Success Criteria

### Phase 0 Complete When:
- [ ] All 7 design questions answered with documented decisions
- [ ] Architecture docs written and reviewed
- [ ] Rust workspace structure defined
- [ ] Dependency list finalized

### Phase 1 Complete When:
- [ ] Can encrypt/decrypt in Rust using OpenFHE
- [ ] Can generate/verify ED25519 signatures
- [ ] Can generate/verify PQ signatures (ML-DSA-87)
- [ ] Can generate recryption keys
- [ ] Can perform recryption transformation
- [ ] All FFI smoke tests passing

### Phase 2 Complete When:
- [ ] Core crypto API stable and documented
- [ ] Property-based tests passing
- [ ] Known-answer tests for regression
- [ ] Benchmarks baseline established
- [ ] Documentation with examples

### Phase 3 Complete When:
- [ ] Wire protocol defined and implemented
- [ ] Merkle tree/Blake3 tree verification working
- [ ] Message serialization round-trips
- [ ] Signature verification integrated
- [ ] Streaming verification functional

### Phase 4 Complete When:
- [ ] Local file storage working
- [ ] Minio integration functional
- [ ] S3 integration tested
- [ ] Docker compose dev environment
- [ ] Concurrent access patterns validated

### Phase 5 Complete When:
- [ ] HDprint generation deterministic
- [ ] Error correction working
- [ ] Case restoration working
- [ ] All Python test vectors passing (ported to Rust)
- [ ] Performance benchmarks met (<1ms for MEDIUM)

### Phase 6 Complete When:
- [ ] All API routes functional
- [ ] Multi-sig verification working
- [ ] Nonce replay prevention validated
- [ ] E2E Alice->Bob sharing flow works
- [ ] Load testing baseline established

### Phase 7 Complete When:
- [ ] All CLI commands functional
- [ ] Interactive mode polished
- [ ] Config file management working
- [ ] Integration with server validated
- [ ] Shell completions generated

### Phase 8 Complete When:
- [ ] All TUI screens functional
- [ ] Keyboard navigation smooth
- [ ] Real-time updates working
- [ ] Clean visual design
- [ ] No performance regressions

### Overall Complete When:
- [ ] Full Alice->Bob E2E flow works CLI-to-CLI via server
- [ ] TUI provides full functionality
- [ ] Documentation complete (user guide + API docs)
- [ ] Deployment guide written
- [ ] Security audit prep document ready

---

## Open Questions for Team Discussion

1. **Encryption approach:** Full-file vs hybrid? (Performance benchmarks needed)
2. **Hashing standard:** Blake2b vs Blake3 everywhere? (Both are fine, pick one)
3. **Wire protocol:** Protobuf vs Cap'n Proto vs Flatbuffers? (Need to decide)
4. **Storage naming:** Content-addressed vs user-namespaced? (Security implications)
5. **Verification:** Merkle tree vs Blake3 tree mode? (API differences)
6. **HMAC usage:** Keep in HDprint or simplify? (Security analysis needed)
7. **ASCII armor:** Keep as export format or drop entirely? (Debuggability tradeoff)

---

## Timeline Estimate

**Phase 0:** 2-3 days (design decisions)  
**Phase 1:** 3-5 days (FFI bindings)  
**Phase 2:** 4-5 days (core crypto)  
**Phase 3:** 3-4 days (protocol)  
**Phase 4:** 3-4 days (storage)  
**Phase 5:** 2-3 days (HDprint)  
**Phase 6:** 4-5 days (server)  
**Phase 7:** 3-4 days (CLI)  
**Phase 8:** 2-3 days (TUI)  

**Total:** 26-36 days (~5-7 weeks)

**With buffer for unknowns:** 8-10 weeks to production-ready

---

## Next Steps

1. **Immediate:** Archive Python prototype into subdirectory
2. **This Week:** Answer all design questions, write architecture docs
3. **Next Week:** Begin Phase 1 (FFI bindings)
4. **Regular Reviews:** Weekly check-ins on progress + blockers
5. **Documentation:** Update this plan as we learn

---

## Notes for Future Maintainers

- **Non-determinism is normal:** Don't expect byte-level equality in tests
- **Context is precious:** Keep crypto context alive for related operations
- **Recryption not re-encryption:** Consistent terminology throughout
- **S3 is flexible:** Easy to swap storage backends via trait
- **HDprint is magical:** Don't mess with it unless you understand BCH codes
- **Security over performance:** But both are achievable with good design

---

**This document is the source of truth for the Rust port. Update it as decisions are made.**

