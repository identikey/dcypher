# dCypher: A Quantum-Resistant Recryption Proxy

**dCypher** is an open-source, easy-to-deploy, production-ready recryption proxy that enables private, shareable, and revocable cloud storage.

The goal of dCypher is to fundamentally change how we interact with cloud storage. It flips the game board so you can store your data on any cloud provider, **without that provider ever having access to the unencrypted data**. At the same time, you can securely share that data with any other individual or group and revoke their access at any time.

This project solves a major missing component in decentralized systems, bringing them closer to par with their centralized equivalents by offering secure access control over encrypted data stored with untrusted intermediaries.

### How It Works

dCypher acts as a proxy that can take ciphertext encrypted for a specific private key and re-encrypt it for a different private key, without ever decrypting the data itself. This technique, known as Proxy Re-Encryption (PRE), allows a storage provider to serve data to authorized users on behalf of the data owner, without having access to the plaintext or the owner's private keys.

We use the excellent OpenFHE library to implement lattice-based cryptography, making the system quantum-resistant.

### Features

* **Untrusted Storage:** Store your data on any S3-compatible cloud service, a local server, or even a Raspberry Pi, with the guarantee that the provider cannot read it.
* **Secure, Revocable Sharing:** Delegate and revoke read access to your encrypted files for any user/public key via a simple ACL API.
* **Quantum-Resistant:** Designed with post-quantum cryptography (PQC) to ensure long-term data security.
* **Flexible Deployment:** Architected to be deployed on cloud hardware, local servers, or scalable "serverless" platforms.
* **Open Source:** Free to use and build upon under a permissive license (MIT/Apache).

dCypher is a core component of the IdentiKey vision for a user-controlled internet where individuals maintain sovereignty over their digital identities and data.

---

**Learn more about the technology and our vision at [identikey.io/recryption](https://identikey.io/recryption)**.

## HDprint with Paiready: Self-Correcting Hierarchical Identifiers

dCypher includes an innovative identifier system called **HDprint with Paiready** that generates human-readable, error-resistant identifiers for cryptographic objects like public or private keys, certificates, cryptocurrency, and encrypted data references.

### Key Features

* **Self-Correcting:** Automatically fixes single-character typos in checksums using BCH error correction codes
* **Case-Insensitive Input:** Type everything in lowercase - the system restores proper mixed-case formatting
* **Hierarchical Scaling:** Multiple security levels from 17.6 bits (testing) to 158.2+ bits (production)
* **Human-Friendly:** Visual structure with underscores, Base58 encoding avoids confusing characters
* **Cryptographically Strong:** HMAC-SHA3-512 chain with BLAKE3 preprocessing for collision resistance

### Format Structure

```
Pattern: {paiready}_{hdprint}
Example: myzgemb_5ubrZa_T9w1LJRx_hEGmdyaM

Components:
- Paiready checksum: 'myzgemb' (error-correcting, base58 lowercase)
- HDprint fingerprint: '5ubrZa_T9w1LJRx_hEGmdyaM' (hierarchical, base58 mixed-case)
```

### Error Correction Demo

```
Original identifier: 4pkabdr_6QqqSV_GjsEbLU5_c8AJmdYG

User types (all lowercase, 2 typos in checksum):
User input:          1pk2bdr_6qqqsv_gjseblu5_c8ajmdyg

System automatically corrects:
Final identifier:    4pkabdr_6QqqSV_GjsEbLU5_c8AJmdYG
```

Process:

1. BCH error correction fixes typos in checksum
2. Bit field unpacking restores original mixed case in HDprint
3. User gets canonical identifier despite typing errors

### Size Options

```
TINY    mwrjzs1_zF1tjX
        Security: 17.6 bits, Checksum: mwrjzs1
SMALL   k68q6ci_zF1tjX_hhdbg5W6
        Security: 64.4 bits, Checksum: k68q6ci
MEDIUM  ajqkgas_zF1tjX_hhdbg5W6_fJN8yZJV
        Security: 111.3 bits, Checksum: ajqkgas
RACK    38qhkje_zF1tjX_hhdbg5W6_fJN8yZJV_D9UMe8J6
        Security: 158.2 bits, Checksum: 38qhkje
```

### Use Cases

* **Public Key Fingerprints:** Human-verifiable identifiers for cryptocurrency wallets and PKI certificates
* **Database References:** Error-resistant record IDs that users can manually verify
* **API Keys & Tokens:** Built-in error detection for authentication systems  
* **QR Code Content:** Remains scannable even with minor visual damage
* **CLI Tools:** Forgiving input processing for manually-entered identifiers

This identifier system is particularly valuable in dCypher's proxy re-encryption context, where users need to reliably reference and share cryptographic keys and encrypted data objects.

## Development

This project uses [Just](https://github.com/casey/just) for task automation as opposed to Make.

### Available Recipes

Run `just` to see all available recipes, or use these common commands:

* **`build-all`**            # Build both OpenFHE C++ and Python bindings
* **`build-liboqs`**         # Clone and build liboqs C library locally (not system-wide)
* **`build-openfhe`**        # Build OpenFHE C++ library locally (not system-wide)
* **`build-openfhe-python`** # Build OpenFHE Python bindings using local C++ library
* **`clean`**                # Clean all builds
* **`clean-liboqs`**         # Clean liboqs builds
* **`clean-openfhe`**        # Clean OpenFHE builds
* **`cli *args`**            # Run the CLI locally with uv
* **`default`**              # Show available tasks
* **`dev-cli *args`**        # Run CLI in development container
* **`dev-down`**             # Stop development environment
* **`dev-rebuild`**          # Rebuild and restart development environment
* **`dev-shell`**            # Open an interactive bash shell in the development container
* **`dev-test`**             # Run tests in development container
* **`dev-up`**               # Start development environment with volume mounting
* **`docker-bash`**          # Open an interactive bash shell in the Docker container
* **`docker-build-dev`**     # Build the development Docker image
* **`docker-built`**         # Build the Docker image
* **`docker-cli *args`**     # Run the CLI in Docker container
* **`docker-exec command`**  # Run a custom command in the Docker container
* **`docker-run`**           # Run the Docker container
* **`test`**

### Examples

```bash
# Quick local development
just cli

# Build and test with Docker
just docker-build
just docker-run

# Debug in container
just docker-bash

# Run tests in container
just docker-exec "python -m pytest"
## Documentation

The detailed message specification can be found in [docs/spec.md](docs/spec.md).

## Library

The core PRE logic is implemented in `src/lib/pre.py`.

## Tests

To run the tests, execute the following command:

```bash
just build-all
just test
```

**Note**: The Python implementation uses OpenFHE which requires Linux, so local development on macOS requires Docker.

## Building

### Python Implementation (Docker)

```bash
# Build and run the Python proof of concept
just docker-build
just docker-run
```

### Zig Implementation (Native)

```bash
# Build the Zig project
zig build

# Run tests
zig build test

# Build and run in one step
zig build run
```

## Usage

### Python CLI (via Docker)

```bash
# Run the Python CLI in Docker
just docker-cli --help
```

### Zig CLI (Native)

```bash
# Generate a key pair
./zig-out/bin/dcypher keygen --output alice_keys.json

# Generate another key pair
./zig-out/bin/dcypher keygen --output bob_keys.json

# Generate re-encryption key from Alice to Bob
./zig-out/bin/dcypher rekey --from alice_keys.json --to bob_keys.json --output alice_to_bob.json

# Encrypt data with Alice's key
./zig-out/bin/dcypher encrypt --key alice_keys.json --input message.txt --output encrypted.bin

# Re-encrypt data for Bob using the re-encryption key
./zig-out/bin/dcypher reencrypt --rekey alice_to_bob.json --input encrypted.bin --output reencrypted.bin

# Bob decrypts the data with his key
./zig-out/bin/dcypher decrypt --key bob_keys.json --input reencrypted.bin --output message_decrypted.txt

# Start the HTTP server
./zig-out/bin/dcypher serve --port 8080
```

### HTTP API

Start the server:

```bash
./zig-out/bin/dcypher serve --port 8080
```

Available endpoints:

* `GET /health` - Health check
* `POST /api/keygen` - Generate key pair
* `POST /api/rekey` - Generate re-encryption key  
* `POST /api/encrypt` - Encrypt data
* `POST /api/reencrypt` - Re-encrypt data
* `POST /api/decrypt` - Decrypt data

Example request:

```bash
curl -X POST http://localhost:8080/api/keygen
```

## Architecture

### Project Structure

```
dcypher/
├── src/                    # Python implementation
│   ├── cli.py             # Python CLI
│   └── lib/               # Python libraries
├── tests/                 # Python tests
├── Dockerfile             # Docker build for Python
├── Justfile              # Task automation for Python/Docker
├── pyproject.toml        # Python dependencies
├── build.zig             # Main Zig build configuration
├── build.zig.zon         # Zig package dependencies
├── build_openfhe.zig     # OpenFHE integration build
├── openfhe.zig           # Zig OpenFHE bindings
├── openfhe_wrapper.cpp   # C++ wrapper for OpenFHE
├── openfhe_wrapper.h     # C++ header
└── src/                  # Zig implementation (TODO: rename to avoid conflict)
    ├── main.zig          # CLI application entry point
    ├── root.zig          # Library exports  
    ├── cli.zig           # Command-line argument parsing
    ├── server.zig        # HTTP server implementation
    ├── crypto.zig        # Cryptographic operations (stubbed)
    └── tests.zig         # Integration tests
```

## Development Status

### Python Proof of Concept

* ✅ OpenFHE integration working

* ✅ Docker containerization
* ✅ Basic CLI interface
* ✅ Proxy re-encryption example

### Zig Implementation  

* ✅ Project structure and build system

* ✅ CLI argument parsing
* ✅ HTTP server with REST endpoints
* ✅ File I/O operations
* ✅ JSON serialization/deserialization
* ❌ Actual proxy re-encryption cryptography implementation
* ❌ Integration with OpenFHE via C++ wrapper
* ❌ Production-ready error handling

## Security Considerations

⚠️ **Warning**: This is currently a development scaffold with stub implementations. Do not use in production until proper cryptographic implementations are added.

When implementing the actual cryptography:

* Use constant-time operations to prevent timing attacks
* Properly handle key generation with secure randomness
* Implement proper key serialization with integrity checks
* Add input validation and sanitization
* Consider memory safety for sensitive data

## License

[Add your license here]
