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
## Development

This project uses [Just](https://github.com/casey/just) for task automation as opposed to Make. 

### Available Recipes

Run `just` to see all available recipes, or use these common commands:

- **`build-all`**            # Build both OpenFHE C++ and Python bindings
- **`build-liboqs`**         # Clone and build liboqs C library locally (not system-wide)
- **`build-openfhe`**        # Build OpenFHE C++ library locally (not system-wide)
- **`build-openfhe-python`** # Build OpenFHE Python bindings using local C++ library
- **`clean`**                # Clean all builds
- **`clean-liboqs`**         # Clean liboqs builds
- **`clean-openfhe`**        # Clean OpenFHE builds
- **`cli *args`**            # Run the CLI locally with uv
- **`default`**              # Show available tasks
- **`dev-cli *args`**        # Run CLI in development container
- **`dev-down`**             # Stop development environment
- **`dev-rebuild`**          # Rebuild and restart development environment
- **`dev-shell`**            # Open an interactive bash shell in the development container
- **`dev-test`**             # Run tests in development container
- **`dev-up`**               # Start development environment with volume mounting
- **`docker-bash`**          # Open an interactive bash shell in the Docker container
- **`docker-build-dev`**     # Build the development Docker image
- **`docker-built`**         # Build the Docker image
- **`docker-cli *args`**     # Run the CLI in Docker container
- **`docker-exec command`**  # Run a custom command in the Docker container
- **`docker-run`**           # Run the Docker container
- **`test`**

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
