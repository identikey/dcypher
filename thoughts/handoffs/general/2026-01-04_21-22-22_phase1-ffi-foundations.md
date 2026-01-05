---
date: 2026-01-04T21:22:22-08:00
researcher: Claude
git_commit: ac66c22e03b92b3dd39eaf1100393231289b377a
branch: main
repository: dcypher
topic: "Phase 1 FFI Foundations Implementation"
tags: [implementation, rust, ffi, openfhe, cryptography, pre]
status: in_progress
last_updated: 2026-01-04
last_updated_by: Claude
type: implementation_strategy
---

# Handoff: Phase 1 FFI Foundations - OpenFHE Bindings Strategy

## Task(s)

Working from `docs/plans/2026-01-04-phase-1-ffi-foundations.md` to build the Rust FFI layer for cryptographic primitives.

| Phase                       | Status      | Notes                                                                                            |
| --------------------------- | ----------- | ------------------------------------------------------------------------------------------------ |
| 1a: Workspace Scaffolding   | ✅ Complete | Cargo workspace + dcypher-ffi crate structure                                                    |
| 1b: OpenFHE FFI Integration | 🔄 Revised  | Original plan to use vendored openfhe-rs abandoned; new approach: create minimal custom bindings |
| 1c: liboqs PQ Signatures    | ⏳ Pending  | Stub implementation in place                                                                     |
| 1d: ED25519 Signatures      | ✅ Complete | Fully functional via ed25519-dalek                                                               |
| 1e: Integration Tests       | ⏳ Pending  | Blocked on 1b/1c                                                                                 |

### Key Pivot

After attempting to integrate the vendored `openfhe-rs` (v0.3.2), discovered:

1. It's adapted for OpenFHE v1.2.1, but our vendored OpenFHE is v1.3.0
2. API breaking changes in serialization and enum values
3. openfhe-rs appears abandoned (~1 year since last meaningful commit)
4. We only need ~15% of the API surface

**Decision**: Create `dcypher-openfhe-sys` with minimal custom bindings tailored for PRE operations.

## Critical References

- `docs/plans/2026-01-04-phase-1-ffi-foundations.md` - Main implementation plan (Phase 1b section updated)
- `docs/plans/openfhe-minimal-bindings-analysis.md` - NEW: Detailed analysis of required API surface
- `docs/openfhe-threading-model.md` - **IMPORTANT**: Thread safety patterns for production proxy
- `python-prototype/src/dcypher/lib/pre.py` - Reference implementation showing exact OpenFHE usage

## Recent Changes

- `Cargo.toml:1-32` - Created workspace root with member crates
- `crates/dcypher-ffi/` - New crate with:
  - `src/lib.rs` - Module exports with status comments
  - `src/error.rs` - Error types (FfiError enum)
  - `src/ed25519.rs` - Complete ED25519 implementation (works!)
  - `src/openfhe/mod.rs` - Stub implementation pending dcypher-openfhe-sys
  - `src/openfhe/pre.rs` - Coefficient conversion utilities (bytes ↔ i64)
  - `src/liboqs/` - Stub implementation for PQ signatures

## Learnings

### OpenFHE Version Compatibility

- `vendor/openfhe-rs` is a git submodule - don't edit directly
- openfhe-rs v0.3.2 is for OpenFHE v1.2.1
- Our OpenFHE submodule is v1.3.0
- Breaking changes: `ScalingTechnique` enum gained 2 values, serialization API changed

### Required OpenFHE API (from Python prototype)

Only 15 functions needed:

```
Context: create_bfv_context, get_ring_dimension
Keys: keygen, get_public_key, get_secret_key
Crypto: make_plaintext, encrypt, decrypt, get_packed_value
PRE: generate_recrypt_key, recrypt
Serialization: serialize_*, deserialize_* (need byte-based, not file-based)
```

### Build Environment

- User had old OpenFHE headers in `/usr/local/include/openfhe` from prototype work
- Should be cleaned: `sudo rm -rf /usr/local/include/openfhe`
- Need reproducible build from `vendor/openfhe-development/`
- Consider `just setup-openfhe` target for building to local prefix

## Artifacts

Created/modified files:

- `Cargo.toml` - Workspace root
- `crates/dcypher-ffi/Cargo.toml`
- `crates/dcypher-ffi/build.rs`
- `crates/dcypher-ffi/src/lib.rs`
- `crates/dcypher-ffi/src/error.rs`
- `crates/dcypher-ffi/src/ed25519.rs`
- `crates/dcypher-ffi/src/openfhe/mod.rs`
- `crates/dcypher-ffi/src/openfhe/pre.rs`
- `crates/dcypher-ffi/src/liboqs/mod.rs`
- `crates/dcypher-ffi/src/liboqs/sig.rs`
- `docs/plans/openfhe-minimal-bindings-analysis.md` - **NEW: Key reference**
- `docs/plans/2026-01-04-phase-1-ffi-foundations.md:204-248` - Updated Phase 1b section
- `docs/openfhe-threading-model.md` - **NEW: Production threading patterns**
- `Justfile` - Updated `build-openfhe` with OpenMP, added `check-omp`
- `crates/dcypher-openfhe-sys/build.rs` - Added `link_openmp()` for libomp/libgomp

## Action Items & Next Steps

### Immediate (Phase 1b)

1. **Clean system OpenFHE**: `sudo rm -rf /usr/local/include/openfhe`

2. **Create `crates/dcypher-openfhe-sys/`** with minimal bindings:

   - Copy structure from openfhe-rs as reference (don't use directly)
   - Implement only the 15 functions identified in analysis
   - Target OpenFHE 1.3.0 compatibility
   - Use byte-based serialization (stringstream, not file)

3. **Build infrastructure**:

   - Add `just setup-openfhe` to build OpenFHE from vendor source
   - Install to `vendor/openfhe-development/install/`
   - Configure build.rs to use that path
   - Consider static linking for deployment

4. **Wire up dcypher-ffi**:
   - Replace stubs in `src/openfhe/mod.rs` with real implementation
   - Add smoke tests for PRE roundtrip

### Later (Phase 1c)

- Investigate liboqs Rust bindings (check crates.io for `oqs`, `pqcrypto`)
- Or create minimal bindings similar to openfhe approach

## Other Notes

### Submodule Status

- `vendor/openfhe-rs` - Git submodule, reverted to clean state
- `vendor/openfhe-development` - OpenFHE v1.3.0 source
- `vendor/liboqs` - liboqs source with built libraries at `build/lib/`

### Test Status

```bash
cargo test -p dcypher-ffi  # 5 tests pass (ed25519 + coefficient conversion)
```

### Memory: Terminology

Per memory 12922366: Use "recrypt" not "re-encrypt" for all PRE operations in the Rust implementation.

### Key Insight

The Python prototype's `pre.py` uses a very small OpenFHE surface. The openfhe-rs bindings are overkill and maintenance burden. A minimal custom implementation (~500 lines total) is more maintainable than tracking 1500+ lines of unused bindings.

### Threading Model (Production Critical)

OpenMP ≠ Thread Safety. See `docs/openfhe-threading-model.md` for full details.

**Summary**:

- OpenMP: Parallelizes _within_ each operation (faster individual ops)
- Thread safety: Achieved via architecture, not OpenMP

**Safe pattern for recryption proxy**:

```
Startup (single thread):  create context, load keys
Runtime (concurrent):     encrypt/decrypt/recrypt calls are thread-safe
```

**Build commands updated**:

- `just build-openfhe` now enables OpenMP on macOS (auto-detects Homebrew libomp)
- `just check-omp` verifies OpenMP availability
- `crates/dcypher-openfhe-sys/build.rs` links against libomp/libgomp

**Why tests use `--test-threads=1`**: Tests create/destroy contexts (unsafe). Production code that initializes once is fine.
