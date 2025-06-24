# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Environment

This is a Python project using `uv` for dependency management and `just` for task automation. The project demonstrates proxy re-encryption (PRE) using OpenFHE cryptographic library.

### Common Commands

**Development:**
- `just cli` - Run the CLI locally with uv
- `just test` - Run tests with pytest in parallel
- `uv run python src/cli.py` - Direct CLI execution
- `uv run python src/main.py` - Run FastAPI server

**Docker Development:**
- `just dev-up` - Start development container with volume mounting
- `just dev-shell` - Interactive shell in development container  
- `just dev-test` - Run tests in development container
- `just dev-cli <args>` - Execute CLI commands in container
- `just dev-down` - Stop development environment

**Docker Production:**
- `just docker-build-dev` - Build development image
- `just docker-run` - Run production container
- `just docker-bash` - Interactive shell in production container

### Testing

- Primary test command: `just test` (uses pytest with parallel execution)
- Tests are organized in `tests/unit/` and `tests/integration/`
- Configuration in `pyproject.toml` under `[tool.pytest.ini_options]`
- Some tests have external dependency warnings filtered out

## Architecture Overview

### Core Components

**Proxy Re-Encryption Library** (`src/lib/pre.py`):
- Implements OpenFHE BFVrns scheme for homomorphic encryption
- Handles bytes-to-coefficients conversion for encryption
- Provides crypto context creation and key generation

**CLI Interface** (`src/cli.py`):
- Click-based command-line tool with identity management
- Integrates with KeyManager for cryptographic operations
- Connects to FastAPI backend via API_BASE_URL

**FastAPI Backend** (`src/main.py`):
- REST API with routers for accounts, storage, and system operations
- Background task for cleanup of expired uploads
- CORS-enabled for cross-origin requests

**Message Specification** (`docs/spec.md`):
- IdentiKey Message format with Merkle tree integrity verification
- ECDSA signatures for authentication
- Chunked transmission with Base64 encoding
- Supports proxy re-encryption ciphertext transport

### Key Libraries

**Authentication & Cryptography:**
- `src/lib/auth.py` - ECDSA authentication
- `src/lib/pq_auth.py` - Post-quantum authentication using liboqs
- `src/lib/key_manager.py` - Cryptographic key management
- `src/security.py` - Security utilities

**Data Handling:**
- `src/lib/idk_message.py` - IdentiKey message format implementation
- `src/lib/api_client.py` - HTTP client for backend communication
- `src/app_state.py` - Application state management
- `src/models.py` - Data models

### OpenFHE Integration

The project includes three OpenFHE components in subdirectories:
- `openfhe-development/` - Core C++ OpenFHE library
- `openfhe-python/` - Python bindings
- `openfhe-rs/` - Rust bindings

These are external dependencies required for the proxy re-encryption functionality.

### Configuration

- `pyproject.toml` - Primary Python project configuration
- Dependencies managed through uv with dev dependencies separated
- Environment variable `API_BASE_URL` defaults to "http://127.0.0.1:8000"
- FastAPI server runs on uvicorn with auto-reload in development

### File Organization

```
src/
├── lib/           # Core libraries (PRE, auth, key management)
├── routers/       # FastAPI route handlers
├── cli.py         # Command-line interface
├── main.py        # FastAPI application entry point
└── *.py          # Utilities and models

tests/
├── unit/          # Unit tests
└── integration/   # Integration tests
```

This architecture separates cryptographic operations, API handling, and CLI functionality while maintaining integration through shared libraries and consistent data models.