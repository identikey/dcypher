//! dcypher-ffi: FFI bindings for cryptographic primitives
//!
//! This crate provides Rust wrappers for:
//! - OpenFHE (lattice-based Proxy Recryption via BFV scheme)
//! - liboqs (post-quantum signatures via ML-DSA)
//! - ED25519 (classical signatures via ed25519-dalek)
//!
//! # Architecture
//!
//! ```text
//! dcypher-core (high-level API)
//!     └── dcypher-ffi (this crate - safe Rust wrappers)
//!             └── dcypher-openfhe-sys (raw CXX FFI to OpenFHE C++)
//!                     └── vendor/openfhe-development/ (upstream OpenFHE)
//!                     └── vendor/openfhe-install/ (built OpenFHE libs)
//! ```
//!
//! **Note:** There was previously a `vendor/openfhe-rs/` directory used as reference
//! during development. It has been removed—all OpenFHE bindings are now here and in
//! `dcypher-openfhe-sys`.
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
