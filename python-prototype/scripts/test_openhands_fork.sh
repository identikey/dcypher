#!/bin/bash
# Script to test our fork-specific modifications to OpenHands

set -Eeuvxo pipefail

echo "Testing OpenHands Fork Modifications"
echo "===================================="
echo ""
echo "This tests all custom modifications we've made to the OpenHands codebase"
echo ""

# Save current directory
ORIGINAL_DIR=$(pwd)

# Navigate to OpenHands directory
cd vendor/openhands || exit 1

# Check if Poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "ERROR: Poetry is not installed. Please install Poetry first:"
    echo "  curl -sSL https://install.python-poetry.org | python3 -"
    exit 1
fi

# Check if python command exists, if not use python3
if ! command -v python &> /dev/null; then
    echo "Python command not found, using python3..."
    # Tell Poetry to use python3
    poetry env use python3 2>/dev/null || true
fi

echo "1. Installing OpenHands dependencies..."
poetry install --with dev,test,runtime

echo ""
echo "2. Running Fork-Specific Tests..."
echo ""
echo "Testing Grok Empty Response Fix:"
echo "---------------------------------"

# Run our Grok-specific tests
poetry run pytest tests/unit/test_function_calling.py::test_message_action_empty_response_non_grok -xvs
poetry run pytest tests/unit/test_function_calling.py::test_message_action_empty_response_grok -xvs
poetry run pytest tests/unit/test_function_calling.py::test_message_action_non_empty_response_grok -xvs
poetry run pytest tests/unit/test_function_calling.py::test_message_action_grok_model_variants -xvs
poetry run pytest tests/unit/test_function_calling.py::test_message_action_similar_model_names -xvs

echo ""
echo "3. Running affected test files to ensure no regressions..."
# Run the entire test files that we modified to ensure we didn't break anything
poetry run pytest tests/unit/test_function_calling.py -x

# Add more fork-specific tests here as we make more modifications
# Example:
# echo ""
# echo "Testing Future Modification X:"
# echo "------------------------------"
# poetry run pytest tests/unit/test_future_modification.py -x

# Return to original directory
cd "$ORIGINAL_DIR"

echo ""
echo "Fork modification testing complete!" 