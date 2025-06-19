# Zig Re-encryption Proxy

A high-performance re-encryption proxy service implemented in Zig, providing both CLI tools and HTTP API for proxy re-encryption operations.

## Features

- **CLI Interface**: Command-line tools for key generation, encryption, re-encryption, and decryption
- **HTTP Server**: REST API service for proxy re-encryption operations
- **Proxy Re-encryption**: Support for transforming ciphertext from one key to another without decrypting
- **Cross-platform**: Built with Zig for maximum portability and performance

## Current Status

🚧 **Work in Progress** - This is currently a scaffold with stub implementations. The cryptographic operations are not yet fully implemented.

### Implemented (Stub)
- ✅ CLI argument parsing
- ✅ HTTP server with REST endpoints
- ✅ File I/O operations
- ✅ JSON serialization/deserialization
- ✅ Basic project structure and tests

### TODO
- ❌ Actual proxy re-encryption cryptography implementation
- ❌ Integration with OpenFHE or similar crypto library
- ❌ Key serialization/deserialization
- ❌ Production-ready error handling
- ❌ Authentication and authorization
- ❌ TLS/HTTPS support

## Building

```bash
# Build the project
zig build

# Run tests
zig build test

# Build and run in one step
zig build run
```

## Usage

### CLI Commands

```bash
# Generate a key pair
./zig-proxy keygen --output alice_keys.json

# Generate another key pair
./zig-proxy keygen --output bob_keys.json

# Generate re-encryption key from Alice to Bob
./zig-proxy rekey --from alice_keys.json --to bob_keys.json --output alice_to_bob.json

# Encrypt data with Alice's key
./zig-proxy encrypt --key alice_keys.json --input message.txt --output encrypted.bin

# Re-encrypt data for Bob using the re-encryption key
./zig-proxy reencrypt --rekey alice_to_bob.json --input encrypted.bin --output reencrypted.bin

# Bob decrypts the data with his key
./zig-proxy decrypt --key bob_keys.json --input reencrypted.bin --output message_decrypted.txt

# Start the HTTP server
./zig-proxy serve --port 8080
```

### HTTP API

Start the server:
```bash
./zig-proxy serve --port 8080
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

```
src/
├── main.zig       # CLI application entry point
├── root.zig       # Library exports
├── cli.zig        # Command-line argument parsing
├── server.zig     # HTTP server implementation
├── crypto.zig     # Cryptographic operations (stubbed)
└── tests.zig      # Integration tests
```

## Proxy Re-encryption Workflow

1. **Key Generation**: Alice and Bob each generate key pairs
2. **Re-key Generation**: Generate a re-encryption key from Alice's private key to Bob's public key
3. **Initial Encryption**: Alice encrypts data with her public key
4. **Re-encryption**: Proxy transforms Alice's ciphertext using the re-encryption key
5. **Final Decryption**: Bob decrypts the transformed ciphertext with his private key

## Development

### Running Tests

```bash
# Run all tests
zig build test

# Run specific test
zig test src/tests.zig
```

### Code Structure

- `main.zig`: Entry point with command routing
- `cli.zig`: Argument parsing utilities
- `server.zig`: HTTP server with REST API
- `crypto.zig`: Cryptographic operations (currently stubbed)
- `tests.zig`: Comprehensive test suite

### Adding New Features

1. Add the function signature to the appropriate module
2. Implement the function (or stub it initially)
3. Add tests in `tests.zig`
4. Update the CLI or API as needed
5. Run tests to ensure everything works

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
