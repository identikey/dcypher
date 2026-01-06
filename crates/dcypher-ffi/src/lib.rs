//! dcypher-ffi: FFI bindings for cryptographic primitives
//!
//! This crate provides Rust wrappers for:
//! - OpenFHE (lattice-based Proxy Recryption via BFV scheme)
//! - liboqs (post-quantum signatures via ML-DSA)
//! - ED25519 (classical signatures via ed25519-dalek)
//!
//! # Status
//!
//! - ✅ ED25519: Fully functional via ed25519-dalek
//! - ✅ OpenFHE: Functional via dcypher-openfhe-sys (enable with `openfhe` feature)
//! - ✅ liboqs: ML-DSA-44/65/87 via oqs crate (enable with `liboqs` feature)

pub mod error;

pub mod openfhe;

pub mod liboqs;

pub mod ed25519;
