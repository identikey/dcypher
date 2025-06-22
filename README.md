# dCypher Recryption

[description](https://identikey.io/recryption)

## Project Structure

This project contains two implementations of proxy re-encryption:

1. **Python Proof of Concept** - Uses OpenFHE for cryptographic operations, runs in Docker
2. **Zig Implementation** - High-performance native implementation (work in progress)

## Python Proof of Concept Development

This uses [Just](https://github.com/casey/just) for task automation and Docker for consistent builds. Install Just with:

```bash
brew install just
```

### Available Tasks

Run `just` to see all available tasks, or use these common commands:

- **`just cli <args>`** - Run the CLI locally with uv  
- **`just docker-build`** - Build the Docker image  
- **`just docker-run`** - Run the Docker container
- **`just docker-bash`** - Open interactive bash shell in container
- **`just docker-cli <args>`** - Run CLI in Docker container
- **`just docker-exec <command>`** - Run a custom command in the container

### Examples

```bash
# Quick local development (Note: OpenFHE only works in Docker on macOS)
just docker-cli --help

# Build and test with Docker
just docker-build
just docker-run

# Debug in container
just docker-bash

# Run tests in container
just docker-exec "python -m pytest"
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

- `GET /health` - Health check
- `POST /api/keygen` - Generate key pair
- `POST /api/rekey` - Generate re-encryption key  
- `POST /api/encrypt` - Encrypt data
- `POST /api/reencrypt` - Re-encrypt data
- `POST /api/decrypt` - Decrypt data

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
- ✅ OpenFHE integration working
- ✅ Docker containerization
- ✅ Basic CLI interface
- ✅ Proxy re-encryption example

### Zig Implementation  
- ✅ Project structure and build system
- ✅ CLI argument parsing
- ✅ HTTP server with REST endpoints
- ✅ File I/O operations
- ✅ JSON serialization/deserialization
- ❌ Actual proxy re-encryption cryptography implementation
- ❌ Integration with OpenFHE via C++ wrapper
- ❌ Production-ready error handling

## Security Considerations

⚠️ **Warning**: This is currently a development scaffold with stub implementations. Do not use in production until proper cryptographic implementations are added.

When implementing the actual cryptography:
- Use constant-time operations to prevent timing attacks
- Properly handle key generation with secure randomness
- Implement proper key serialization with integrity checks
- Add input validation and sanitization
- Consider memory safety for sensitive data

## License

[Add your license here]
