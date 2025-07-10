# DCypher Development Environment

This document explains how to set up and use the DCypher development environment with local builds of liboqs and OpenFHE.

## Quick Start

### Option 1: Use Just commands (Recommended)

```bash
# Build everything
just build-all

# Check liboqs algorithms
just check-liboqs

# Run the server
just serve

# Run tests
just test
```

### Option 2: Manual environment setup

```bash
# Set up environment variables
source ./env.sh

# Now you can run any command directly
uv run python scripts/check_liboqs_algorithms.py
uv run uvicorn src.main:app --reload
uv run pytest tests/
```

## Environment Setup Details

The `env.sh` script automatically:

1. **Detects local builds** of liboqs and OpenFHE in the `build/` directory
2. **Sets environment variables**:
   - `OQS_INSTALL_PATH`: Points liboqs-python to our local liboqs build
   - `LD_LIBRARY_PATH`: Includes paths to local shared libraries
   - `PYTHONPATH`: Includes the `src/` directory for imports

3. **Provides helpful feedback** about what was found and what commands you can run

## Build Targets

### Core Libraries

- `just build-liboqs`: Build liboqs C library locally
- `just build-openfhe`: Build OpenFHE C++ library locally
- `just build-liboqs-python`: Build and install liboqs-python bindings
- `just build-openfhe-python`: Build and install OpenFHE Python bindings
- `just build-all`: Build everything

### Cleaning

- `just clean-liboqs`: Clean liboqs builds
- `just clean-openfhe`: Clean OpenFHE builds  
- `just clean-liboqs-python`: Clean liboqs-python builds
- `just clean`: Clean everything

### Testing & Running

- `just check-liboqs`: Check available liboqs algorithms
- `just serve`: Run the FastAPI server with hot reload
- `just test`: Run the test suite

## Troubleshooting

### "liboqs not found, installing it in /home/user/_oqs"

This means the environment variables aren't set up properly. Solution:

```bash
# Make sure you've built liboqs locally
just build-liboqs

# Then either:
source ./env.sh  # For manual runs
# OR
just check-liboqs  # Use the Just command
```

### Version mismatch warnings

The warning about liboqs version (0.13.0) vs liboqs-python version (0.12.0) is normal and doesn't affect functionality.

### Missing algorithms

If you're missing expected algorithms:

1. Rebuild liboqs: `just clean-liboqs && just build-liboqs`
2. Reinstall liboqs-python: `just clean-liboqs-python && just build-liboqs-python`

## Development Workflow

For active development:

```bash
# Set up environment once per shell session
source ./env.sh

# Now you can run commands directly
uv run python scripts/check_liboqs_algorithms.py
uv run python -m pytest tests/test_crypto.py -v
uv run uvicorn src.main:app --reload --port 8000
```

Or use Just commands which handle environment setup automatically:

```bash
just serve    # Starts development server
just test     # Runs test suite
just check-liboqs  # Checks algorithm availability
```
