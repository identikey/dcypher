#!/bin/bash
# Legacy wrapper - use tests/e2e/recryption.sh directly
# Usage: ./test-e2e-recryption.sh [mock|lattice]
exec "$(dirname "$0")/tests/e2e/recryption.sh" "${1:-mock}"
