#!/bin/bash

# DCypher Test Runner
# Sets up the environment and runs tests with proper library paths

# Set library paths for OpenFHE and liboqs
export LD_LIBRARY_PATH="/workspace/openfhe-local/lib:/workspace/liboqs-local/lib:${LD_LIBRARY_PATH:-}"

# Set Python path
export PYTHONPATH="/workspace/src:${PYTHONPATH:-}"

# Run tests with uv
echo "Running tests with proper library paths..."
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo ""

# Run the tests
uv run pytest "$@"