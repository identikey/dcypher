# Examples

This directory contains runnable examples demonstrating dCypher's core cryptographic operations.

## Running Examples

```bash
# From workspace root
cargo run --example <name>
```

## Available Examples

### 1. basic_encryption

**What it shows**: Simple hybrid encryption/decryption workflow

- Generate keypair
- Encrypt data of various sizes
- Decrypt and verify integrity
- Shows KEM-DEM hybrid encryption with Bao integrity checking

```bash
cargo run --example basic_encryption
```

### 2. alice_bob_carol

**What it shows**: Multi-hop proxy re-encryption flow

- Alice encrypts data for herself
- Alice delegates to Bob (generates recryption key)
- Proxy transforms ciphertext for Bob
- Bob delegates to Carol (generates second recryption key)
- Proxy transforms again for Carol
- All parties decrypt same plaintext—proxy sees nothing

```bash
cargo run --example alice_bob_carol
```

### 3. multi_signature

**What it shows**: Hybrid classical + post-quantum signatures

- Generate ED25519 + ML-DSA-87 keypairs
- Sign messages with both schemes
- Verify signatures (both must pass)
- Demonstrate tamper detection

```bash
cargo run --example multi_signature
```

## Notes

- Examples currently use `MockBackend` for demonstration
- Production code will use `LatticeBackend` (OpenFHE) once Phase 3 (serialization) is complete
- All examples verify correctness with assertions
- Multi-signature shows real post-quantum (ML-DSA-87) operations via liboqs
