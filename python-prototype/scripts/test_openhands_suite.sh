#!/bin/bash
# Script to run OpenHands test suite to ensure our fork remains compatible

set -Eeuvxo pipefail
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            OpenHands Full Test Suite Runner                  ║"
echo "║  Ensures our fork remains compatible with upstream           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
ORIGINAL_DIR=$(pwd)
OPENHANDS_DIR="vendor/openhands"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if we're in the right directory
if [ ! -d "$OPENHANDS_DIR" ]; then
    print_error "OpenHands directory not found at $OPENHANDS_DIR"
    exit 1
fi

# Check if Poetry is installed
if ! command -v poetry &> /dev/null; then
    print_error "Poetry is not installed. Please install Poetry first:"
    echo "  curl -sSL https://install.python-poetry.org | python3 -"
    exit 1
fi

# Navigate to OpenHands directory
cd "$OPENHANDS_DIR" || exit 1

# Check if virtual environment already exists
if [ -d ".venv" ] && [ -f ".venv/bin/python" ]; then
    print_status "Virtual environment already exists, activating it..."
    source .venv/bin/activate
else
    # Check if python command exists, if not tell Poetry to use python3
    if ! command -v python &> /dev/null; then
        print_status "Python command not found, configuring Poetry to use python3..."
        # Find python3 path
        PYTHON3_PATH=$(which python3)
        if [ -n "$PYTHON3_PATH" ]; then
            print_status "Found python3 at: $PYTHON3_PATH"
            poetry env use "$PYTHON3_PATH" || {
                print_error "Failed to configure Poetry to use python3"
                exit 1
            }
            # Activate the newly created environment
            if [ -d ".venv" ] && [ -f ".venv/bin/activate" ]; then
                source .venv/bin/activate
            fi
        else
            print_error "No python3 found on the system"
            exit 1
        fi
    fi
fi

print_status "Starting OpenHands full test suite..."
echo ""

# 1. Install dependencies
print_status "Installing OpenHands dependencies..."
poetry install --with dev,test,runtime
print_success "Dependencies installed"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                    Running Full Test Suite"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test suite
run_test_suite() {
    local suite_name=$1
    local test_command=$2
    local test_output_file="/tmp/pytest_output_$$.txt"
    
    echo ""
    print_status "Running $suite_name..."
    echo ""
    
    # Run the test and capture output
    if poetry run $test_command 2>&1 | tee "$test_output_file"; then
        # Parse the output for test results
        local test_summary=$(grep -E "^=+.*(passed|failed|skipped)" "$test_output_file" | tail -1)
        if [ -n "$test_summary" ]; then
            echo ""
            echo "Test Summary: $test_summary"
        fi
        
        echo ""
        print_success "$suite_name passed"
        ((TESTS_PASSED++))
        rm -f "$test_output_file"
        return 0
    else
        # Parse the output for test results even on failure
        local test_summary=$(grep -E "^=+.*(passed|failed|skipped)" "$test_output_file" | tail -1)
        if [ -n "$test_summary" ]; then
            echo ""
            echo "Test Summary: $test_summary"
        fi
        
        echo ""
        print_error "$suite_name failed"
        ((TESTS_FAILED++))
        rm -f "$test_output_file"
        return 1
    fi
}

# Run the full test suite based on their GitHub Actions py-tests.yml
echo "1. Unit Tests"
echo "-------------"
run_test_suite "All unit tests" \
    "pytest -n auto -s ./tests/unit"

echo ""
echo "2. Runtime Tests (if available)"
echo "-------------------------------"
# Note: These require specific runtime setup, may fail without proper environment
if [ -d "tests/runtime" ]; then
    run_test_suite "Runtime tests" \
        "pytest -s tests/runtime/test_bash.py" || true  # Don't fail if runtime isn't set up
else
    echo "Runtime tests directory not found, skipping..."
fi

echo ""
echo "3. E2E Tests (if available)"
echo "---------------------------"
if [ -d "tests/e2e" ]; then
    run_test_suite "E2E tests" \
        "pytest -s tests/e2e" || true  # Don't fail if E2E environment isn't set up
else
    echo "E2E tests directory not found, skipping..."
fi

# Return to original directory
cd "$ORIGINAL_DIR"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                        Test Summary"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    print_success "All tests passed! Our fork is compatible."
    exit 0
else
    print_error "Some tests failed."
    echo ""
    echo "This may indicate:"
    echo "  1. Our modifications broke something"
    echo "  2. Upstream changes are incompatible with our fork"
    echo "  3. Missing dependencies or environment issues"
    echo ""
    echo "Note: Runtime and E2E test failures may be due to missing environment setup."
    exit 1
fi 