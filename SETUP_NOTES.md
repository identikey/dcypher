# DCypher Container Setup Notes

## Issues Resolved

### 1. Missing `just` Command
**Problem**: The `just` task runner was not installed in the container, even though it was specified in `config.toml`.

**Solution**: Manually installed `just` using the official installer:
```bash
sudo curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | sudo bash -s -- --to /usr/local/bin
```

### 2. Missing OpenFHE Shared Libraries
**Problem**: Tests failed with `ImportError: libOPENFHEpke.so.1: cannot open shared object file: No such file or directory`

**Solution**: 
1. Installed missing system dependencies:
   ```bash
   sudo apt-get update && sudo apt-get install -y build-essential cmake pkg-config libssl-dev git curl wget
   ```

2. Built the OpenFHE and liboqs libraries:
   ```bash
   just clean  # Clean any previous builds
   just build-all  # Build OpenFHE C++ library, Python bindings, and liboqs
   ```

3. Set proper library paths:
   ```bash
   export LD_LIBRARY_PATH="/workspace/openfhe-local/lib:/workspace/liboqs-local/lib:${LD_LIBRARY_PATH:-}"
   ```

## Current Status

✅ **Fixed**: `just` command is now available  
✅ **Fixed**: OpenFHE libraries are built and accessible  
✅ **Fixed**: Tests can run successfully (977 passed, 8 failed, 75 skipped)  

The remaining 8 test failures are related to:
- Missing `cryptography` module for backup functionality
- Some API client test configuration issues
- PRE (Proxy Re-Encryption) key handling edge cases

## Running Tests

### Option 1: Using the test runner script
```bash
./run_tests.sh [pytest arguments]
```

### Option 2: Using just (recommended)
```bash
just test
```

### Option 3: Manual with environment variables
```bash
export LD_LIBRARY_PATH="/workspace/openfhe-local/lib:/workspace/liboqs-local/lib:${LD_LIBRARY_PATH:-}"
uv run pytest tests/
```

## Available Just Tasks

Run `just` to see all available tasks:
- `just build-all` - Build OpenFHE and liboqs libraries
- `just test` - Run tests with proper environment
- `just clean` - Clean build artifacts
- `just cli [args]` - Run the CLI locally
- `just dev-up` - Start development Docker environment

## Notes

- The OpenFHE and liboqs libraries are built locally in `openfhe-local/` and `liboqs-local/` directories
- Library paths are automatically set in the updated `just test` command
- The container environment is now properly configured for development and testing