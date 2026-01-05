# dCypher Python Prototype (ARCHIVED)

**Status:** 📦 Archived - Reference Implementation Only  
**Purpose:** Proof-of-concept that validated proxy recryption approach

---

## ⚠️ Important Notice

This Python implementation is **archived and not actively maintained**. It served its purpose as a proof-of-concept to validate:

- OpenFHE integration for proxy recryption
- Post-quantum signature schemes (liboqs)
- IDK message format with Merkle tree verification
- HDprint self-correcting identifier system
- Multi-signature authorization patterns

**All new development is in Rust.** See `../docs/IMPLEMENTATION_PLAN.md` for the production implementation.

---

## What's Here

This directory contains the original Python prototype with:

- **src/dcypher/** - Core implementation

  - `lib/pre.py` - OpenFHE proxy recryption wrapper
  - `lib/idk_message.py` - IDK message format implementation
  - `hdprint/` - Self-correcting identifier system
  - `routers/` - FastAPI endpoints
  - `tui/` - Full-featured terminal UI
  - `cli/` - Command-line interface

- **tests/** - Test suite (35 unit + 31 integration tests)

  - Reference for porting to Rust
  - Demonstrates expected behavior

- **docs/** - Original specifications
  - `spec.md` - IDK message format specification
  - Various design documents

---

## Key Learnings & Design Issues

### What Worked Well ✅

- OpenFHE integration via Python bindings
- Multi-signature authorization pattern
- HDprint error correction (BCH codes)
- Chunked streaming architecture
- Merkle tree verification

### Issues to Fix in Rust Port ⚠️

- **Non-deterministic serialization**: OpenFHE produces different bytes for same object
- **Context lifetime bugs**: Parallel tests destroy shared context
- **ECDSA complexity**: Unnecessary, ED25519 sufficient
- **Naive storage**: Need S3-compatible backend
- **ASCII armor overhead**: Need efficient binary protocol
- **Mixed terminology**: "re-encrypt" vs "recrypt" inconsistent

---

## Cannot Be Used For

- ❌ Production deployments (prototype only)
- ❌ Compatibility with Rust version (different formats)
- ❌ Running without Docker (OpenFHE Linux-only)
- ❌ Security auditing (not production-ready)

---

## Can Be Used For

- ✅ Understanding proxy recryption flow
- ✅ Reference implementation for algorithms
- ✅ Test vector generation (though not byte-compatible)
- ✅ HDprint implementation details
- ✅ API design inspiration

---

## Running the Prototype (If Needed)

**Requirements:**

- Python 3.11+
- Docker (for OpenFHE)
- Just task runner

```bash
cd python-prototype

# Build OpenFHE and Python bindings in Docker
just docker-build

# Run tests
just docker-test

# Run server
just docker-run

# Run TUI
just docker-cli terminal
```

**Note:** Local development on macOS requires Docker since OpenFHE needs Linux.

---

## File Organization

```
python-prototype/
├── src/dcypher/
│   ├── lib/
│   │   ├── pre.py              # OpenFHE wrapper (PORT THIS)
│   │   ├── idk_message.py      # Message format (REVISE FOR RUST)
│   │   ├── api_client.py       # HTTP client
│   │   └── paiready.py         # BCH checksum system
│   ├── hdprint/                # Self-correcting identifiers (PORT DIRECTLY)
│   │   ├── algorithms.py       # Core HDprint generation
│   │   ├── paiready.py         # Error correction
│   │   └── bch.rs              # BCH codec
│   ├── routers/                # FastAPI endpoints (REWRITE IN RUST)
│   │   ├── accounts.py         # Account management
│   │   ├── storage.py          # File storage (REPLACE WITH S3)
│   │   └── recryption.py       # Recryption operations
│   ├── cli/                    # CLI commands (REWRITE IN RUST)
│   └── tui/                    # Terminal UI (MINIMAL VERSION IN RUST)
│
├── tests/
│   ├── unit/                   # 35 unit tests
│   └── integration/            # 31 integration tests
│
└── docs/
    ├── spec.md                 # IDK message specification
    └── ...                     # Various design docs
```

---

## Key Implementation Details

### OpenFHE Integration

- Uses BFVrns scheme with plaintext modulus 65537
- Ring dimension determined by security level (128/192/256 bits)
- Serialization is non-canonical (same object → different bytes)
- Context must be kept alive for all related operations

### Multi-Signature Pattern

```python
# Every operation requires:
1. ED25519 signature (classical fallback)
2. ECDSA signature (BEING REMOVED IN RUST)
3. All PQ key signatures (ML-DSA-87 mandatory + optional)
4. Nonce for replay prevention
```

### HDprint System

- BLAKE3 preprocessing → HMAC-SHA3-512 iterative chain
- 5× BCH(t=1, m=7) interleaved codes for error correction
- Base58L lowercase for checksum, Base58 mixed-case for fingerprint
- Deterministic generation (same input → same identifier)

### IDK Message Format

```
----- BEGIN IDK MESSAGE PART 1/N -----
Headers (key: value format)

<base64 ciphertext payload>
----- END IDK MESSAGE PART 1/N -----
```

**Rust version will use efficient binary protocol instead.**

---

## Performance Characteristics

**Python Prototype (Reference):**

- Key generation: ~200ms
- Encrypt 1KB: ~50ms
- Decrypt 1KB: ~50ms
- Recryption: ~30ms
- HDprint generation: <1ms

**Rust target:** 2-5x faster due to reduced overhead

---

## Security Notes

### Known Issues (Python)

- Non-canonical serialization makes content addressing tricky
- Shared context in server vulnerable to destruction
- No rate limiting on endpoints
- Nonce storage unbounded (memory leak)
- File storage has no size limits

### Addressed in Rust

- ✅ Proper context lifetime management
- ✅ Rate limiting via Tower middleware
- ✅ Bounded nonce cache with expiration
- ✅ S3 storage with quotas
- ✅ Streaming to avoid memory issues

---

## Test Suite Notes

The test suite is comprehensive but not fully compatible with Rust:

**Can Port:**

- ✅ Test structure and scenarios
- ✅ Multi-sig authorization flows
- ✅ HDprint generation and correction
- ✅ Merkle tree verification logic

**Cannot Port:**

- ❌ Byte-level ciphertext comparisons (non-deterministic)
- ❌ Serialized key equality checks (format changing)
- ❌ IDK message parsing (format changing)

**Strategy:** Port test logic, not test assertions. Focus on semantic equivalence.

---

## Dependencies (Python)

Major dependencies preserved for reference:

- `openfhe` - FHE library (via Docker)
- `fastapi` - HTTP server framework
- `textual` - TUI framework
- `click` - CLI framework
- `ecdsa` - ECDSA signatures (REMOVING)
- `ed25519` - ED25519 signatures (KEEPING)
- Custom `liboqs` integration (PORT TO RUST)

---

## Migration Notes

### Functions Worth Porting 1:1

- `src/dcypher/lib/pre.py` - Core crypto operations
- `src/dcypher/hdprint/algorithms.py` - HDprint generation
- `src/dcypher/hdprint/bch.py` - BCH error correction
- `src/dcypher/lib/idk_message.py` - Merkle tree construction

### Functions to Rewrite

- Storage layer (moving to S3)
- Serialization (moving to binary protocol)
- Authentication (removing ECDSA)
- TUI (minimal version)

### Functions to Skip

- Docker-specific setup
- Profiling infrastructure
- ASCII art widgets
- Heavy TUI monitoring

---

## Questions? Issues?

This is an archived reference implementation. For questions about the Rust implementation, see:

- `../docs/IMPLEMENTATION_PLAN.md` - Master implementation plan
- `../README.md` - Current project status

Do not file issues against this Python code—it is preserved for reference only.

---

**Last Updated:** January 2026  
**Archived:** Reference implementation only
