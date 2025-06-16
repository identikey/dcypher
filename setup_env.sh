#!/bin/bash
# Setup script for OpenFHE library paths

export DYLD_LIBRARY_PATH="$(pwd)/lib:$DYLD_LIBRARY_PATH"
export LD_LIBRARY_PATH="$(pwd)/lib:$LD_LIBRARY_PATH"

echo "Library paths configured:"
echo "DYLD_LIBRARY_PATH: $DYLD_LIBRARY_PATH"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"

# Run the Python script with the configured environment
exec "$@" 