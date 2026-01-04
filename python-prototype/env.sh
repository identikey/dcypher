#!/bin/bash
# DCypher Development Environment Setup
# Source this file to set up environment variables for local builds

set -Eeuvxo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Local build directories
BUILD_DIR="$PROJECT_ROOT/build"
LIBOQS_LIB="$BUILD_DIR/lib"
OPENFHE_LIB="$BUILD_DIR/lib"

echo "🔧 Setting up DCypher development environment..."

# Check for local liboqs build
if [[ -d "$LIBOQS_LIB" && -f "$LIBOQS_LIB/liboqs.so" ]]; then
    echo "✅ Found local liboqs build at: $BUILD_DIR"
    export OQS_INSTALL_PATH="$BUILD_DIR"
    
    # Update LD_LIBRARY_PATH
    if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
        export LD_LIBRARY_PATH="$LIBOQS_LIB:$LD_LIBRARY_PATH"
    else
        export LD_LIBRARY_PATH="$LIBOQS_LIB"
    fi
else
    echo "⚠️  No local liboqs build found at: $LIBOQS_LIB"
    echo "   Run: just build-liboqs"
fi

# Check for local OpenFHE build
if [[ -d "$OPENFHE_LIB" && -f "$OPENFHE_LIB/libOPENFHEcore.so" ]]; then
    echo "✅ Found local OpenFHE build"
    
    # Update LD_LIBRARY_PATH for OpenFHE (if not already added above)
    if [[ "${LD_LIBRARY_PATH:-}" != *"$OPENFHE_LIB"* ]]; then
        if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
            export LD_LIBRARY_PATH="$OPENFHE_LIB:$LD_LIBRARY_PATH"
        else
            export LD_LIBRARY_PATH="$OPENFHE_LIB"
        fi
    fi
else
    echo "⚠️  No local OpenFHE build found"
    echo "   Run: just build-openfhe"
fi

# Set up Python path
export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"

# Export variables for subprocesses
export OQS_INSTALL_PATH
export LD_LIBRARY_PATH
export PYTHONPATH

echo "📋 Environment variables set:"
echo "   OQS_INSTALL_PATH: ${OQS_INSTALL_PATH:-'(not set)'}"
echo "   LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "   PYTHONPATH: $PYTHONPATH"
echo ""
echo "🚀 Ready for development! You can now run:"
echo "   uv run python scripts/check_liboqs_algorithms.py"
echo "   uv run uvicorn src.main:app --reload"
echo "   uv run pytest tests/" 