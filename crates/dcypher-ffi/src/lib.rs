//! dcypher-ffi: FFI bindings for cryptographic primitives
//!
//! This crate provides Rust wrappers for:
//! - OpenFHE (lattice-based Proxy Re-Encryption via BFV scheme)
//! - liboqs (post-quantum signatures, specifically ML-DSA-87)
//! - ED25519 (classical signatures via ed25519-dalek)
//!
//! # Status
//!
//! - ✅ ED25519: Fully functional via ed25519-dalek
//! - ✅ OpenFHE: Functional via dcypher-openfhe-sys (enable with `openfhe` feature)
//! - 🚧 liboqs: Stub implementation pending bindings (Phase 1c)

pub mod error;

pub mod openfhe;

#[cfg(feature = "liboqs")]
pub mod liboqs;

pub mod ed25519;
