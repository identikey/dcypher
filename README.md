# dCypher: Quantum-Resistant Proxy Recryption System

**Status:** 🚧 In Development - Rust Port Phase  
**Version:** 2.0 (Rust Implementation)  

---

## Overview

dCypher is a production-ready proxy recryption system that enables secure, revocable file sharing with untrusted storage providers. Built on lattice-based cryptography (OpenFHE) with post-quantum signatures (liboqs), it provides end-to-end encryption where files can be shared without exposing private keys or plaintext.

### Core Innovation

**Proxy Recryption:** Transform ciphertext encrypted for Alice into ciphertext for Bob without ever decrypting. The storage provider can facilitate sharing without accessing plaintext.

**Quantum-Resistant:** Uses ML-DSA-87 and other post-quantum signature algorithms alongside lattice-based encryption for long-term security.

**Self-Correcting Identifiers:** HDprint system provides human-readable identifiers that automatically correct typos and restore proper case from lowercase input.

---

## Current Status

### ✅ Phase 0: Planning (CURRENT)
- [x] Master implementation plan written (`RUST_PORT_PLAN.md`)
- [ ] Architecture decision documents
- [ ] Design questions answered
- [ ] Workspace structure defined

### 🔲 Upcoming Phases
- Phase 1: FFI Bindings (OpenFHE + liboqs)
- Phase 2: Core Cryptography
- Phase 3: Protocol Layer
- Phase 4: Storage Layer (S3-compatible)
- Phase 5: HDprint Implementation
- Phase 6: HTTP API Server
- Phase 7: CLI Application
- Phase 8: Minimal TUI

**Timeline:** 8-10 weeks to production-ready

---

## Repository Structure

```
dcypher/
├── RUST_PORT_PLAN.md          # 📋 Master implementation plan - READ THIS FIRST
├── README.md                   # This file
│
├── python-prototype/           # 📦 ARCHIVED: Original Python proof-of-concept
│   ├── src/                    # Reference implementation
│   ├── tests/                  # Test suite (ported to Rust)
│   ├── docs/                   # Original specifications
│   └── README.md               # Python implementation docs
│
├── vendor/                     # Third-party dependencies
│   ├── openfhe-development/    # OpenFHE C++ library
│   ├── liboqs/                 # Post-quantum crypto library
│   └── ...
│
└── [Rust workspace to be created in Phase 1]
```

---

## Quick Start (Coming Soon)

```bash
# Phase 1+: Build from source
cargo build --release

# Generate identity
dcypher identity new --output alice.json

# Encrypt file
dcypher encrypt myfile.txt --for <bob-pubkey> --output myfile.enc

# Share with Bob (generates recryption key)
dcypher share create <file-hash> --to <bob-pubkey>

# Bob downloads (server recrypts on-the-fly)
dcypher share download <share-id> --output myfile.txt
```

---

## Key Features

### 🔐 Cryptography
- **OpenFHE BFVrns** for lattice-based proxy recryption
- **ED25519** for classical signatures
- **ML-DSA-87** (mandatory) + optional PQ algorithms
- **Multi-signature** authorization (all keys must sign)

### 💾 Storage
- **S3-compatible** storage layer (Minio for dev, any S3 for prod)
- **Authenticated access** via file hash lookup
- **Chunked streaming** for large files
- **Content-addressed** storage

### 🎯 HDprint Identifiers
- **Error correction**: Automatically fixes single-character typos
- **Case restoration**: Type lowercase, get proper mixed-case
- **Hierarchical scaling**: 17.6 to 158+ bits security
- **Human-friendly**: Base58 encoding, visual separators

### 🌐 API & Interfaces
- **HTTP REST API** (Axum framework)
- **CLI application** with rich interactions
- **Minimal TUI** for visual operations

---

## Design Philosophy

### What Changed from Python Prototype

**Removed:**
- ❌ ECDSA/SECP256k1 (ED25519 sufficient for classical fallback)
- ❌ Naive file storage (moved to S3-compatible)
- ❌ ASCII armor as primary format (moving to efficient binary protocol)

**Enhanced:**
- ✅ Proper Rust architecture with focused crates
- ✅ S3-compatible storage for production
- ✅ Efficient wire protocol (binary + optional ASCII export)
- ✅ Standardized hashing (Blake2b vs Blake3 analysis)
- ✅ Streaming chunk verification

**No Compatibility Required:**
- This is a clean slate implementation
- Cannot decrypt Python ciphertexts (different serialization)
- No migration path needed (no production deployments exist)

---

## Documentation

- **[RUST_PORT_PLAN.md](RUST_PORT_PLAN.md)** - Master implementation plan with all phases
- **python-prototype/docs/** - Original specifications and design docs
- **Phase-specific docs** - To be created in `docs/` as implementation progresses

### Key Design Documents (To Be Written)
1. `docs/crypto-architecture.md` - Encryption approach (full-file vs hybrid)
2. `docs/hashing-standard.md` - Blake2b vs Blake3 decision
3. `docs/verification-architecture.md` - Streaming chunk verification
4. `docs/non-determinism.md` - Testing strategy for crypto
5. `docs/storage-design.md` - S3 integration architecture
6. `docs/wire-protocol.md` - Binary protocol specification
7. `docs/hdprint-specification.md` - Complete HDprint system writeup

---

## Development

### Prerequisites
- Rust 1.75+ (stable)
- OpenFHE C++ library
- liboqs (post-quantum crypto)
- Docker (for Minio development environment)

### Python Prototype (Archived)

The original Python proof-of-concept is preserved in `python-prototype/` for reference. It demonstrated the feasibility of proxy recryption with post-quantum signatures and includes a full TUI implementation.

**To explore the prototype:**
```bash
cd python-prototype
# See python-prototype/README.md for setup instructions
```

**Note:** The Python implementation is archived and not actively maintained. All new development is in Rust.

---

## Terminology

- **Recryption**: Transformation of ciphertext from one key to another (not "re-encryption")
- **Recryption Key**: The key that enables recryption transformation (not "rekey" or "re-encryption key")
- **Recrypted**: Data that has undergone recryption transformation

This terminology is standardized throughout the Rust implementation.

---

## Architecture Highlights

### Workspace Structure (Phase 1+)
```
dcypher/
├── crates/
│   ├── dcypher-ffi/          # OpenFHE + liboqs bindings
│   ├── dcypher-core/         # Core crypto operations
│   ├── dcypher-proto/        # Wire protocol
│   ├── dcypher-storage/      # S3-compatible storage
│   └── dcypher-hdprint/      # Identifier system
├── dcypher-cli/              # CLI binary
├── dcypher-server/           # HTTP API binary
└── dcypher-tui/              # TUI binary
```

### Key Crates
- **dcypher-ffi**: Safe Rust bindings to OpenFHE (C++) and liboqs (C)
- **dcypher-core**: Pure Rust API for encryption, decryption, recryption
- **dcypher-proto**: Message format, Merkle trees, serialization
- **dcypher-storage**: Pluggable storage backends (S3, Minio, local)
- **dcypher-hdprint**: Self-correcting identifier generation

---

## Security Model

### Trust Assumptions
- **Untrusted Storage**: Storage provider cannot read plaintext
- **Trusted Proxy**: Server performs recryption honestly (can be verified)
- **Client-side Keys**: Users control their private keys
- **Multi-signature**: All keys must authorize operations

### Cryptographic Guarantees
- **End-to-end Encryption**: Only key holders decrypt
- **Quantum Resistance**: Post-quantum signatures + lattice crypto
- **Forward Secrecy**: Recryption keys can be revoked
- **Integrity**: Merkle tree verification for all chunks

---

## Contributing

Currently in active development for Rust port. Check `RUST_PORT_PLAN.md` for current phase and open tasks.

---

## License

[License TBD]

---

## Links

- **Website**: [identikey.io/recryption](https://identikey.io/recryption)
- **Proxy Recryption Explainer**: [identikey.io/recryption](https://identikey.io/recryption)

---

**For detailed implementation plan and current status, see [RUST_PORT_PLAN.md](RUST_PORT_PLAN.md)**
