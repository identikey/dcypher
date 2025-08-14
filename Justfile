# DCypher Development Tasks
#
# Show available tasks
default:
    @just --list

run:
    uv run uvicorn main:app --reload

tui:
    uv run python -m src.cli tui

# Run the CLI locally with uv
cli *args:
    uv run python src/cli.py {{args}}

# Run the FastAPI server locally with uv
serve:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    echo "Starting DCypher FastAPI server..."
    uv run uvicorn src.main:app --reload --host 127.0.0.1 --port 8000

lint:
    uv run ruff check src/ tests/
    uv run ruff format src/ tests/

format:
    uv run ruff format src/ tests/

typecheck:
    uv run mypy src/

setup: (submodules)
    #!/usr/bin/env bash
    set -Eeuvxo pipefail

submodules:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Setting up submodules..."
    git submodule update --init --recursive --depth 1


###############
### Testing ###
###############



test:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    echo "Running DCypher test suite..."
    # echo "Running crypto tests sequentially (to avoid OpenFHE context conflicts)..."
    uv run pytest -n auto --dist worksteal ./tests/

test-unit:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    echo "Running DCypher test suite..."
    # echo "Running crypto tests sequentially (to avoid OpenFHE context conflicts)..."
    uv run pytest -n auto --dist worksteal ./tests/unit/

test-integration:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    echo "Running DCypher test suite..."
    # echo "Running crypto tests sequentially (to avoid OpenFHE context conflicts)..."
    uv run pytest -n auto --dist worksteal ./tests/integration/

# Run pytest with custom arguments (for specific files, functions, classes, marks, etc.)
pytest *args:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    uv run pytest {{args}}


# Run all test suites including OpenHands compatibility tests
test-all:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Running comprehensive test suite..."
    echo ""
    echo "1. Running DCypher unit tests..."
    echo "================================="
    just test-unit
    echo ""
    echo "2. Running DCypher integration tests..."
    echo "========================================"
    just test-integration
    echo ""
    echo "3. Running OpenHands fork modification tests..."
    echo "==============================================="
    just test-openhands-fork
    echo ""
    echo "4. Running OpenHands full compatibility tests..."
    echo "================================================="
    just test-openhands
    echo ""
    echo "All test suites completed!"

# Run tests repeatedly until they break or user cancels
test-until-break:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Running tests repeatedly until failure or cancellation (Ctrl+C to stop)..."
    run_count=0
    total_time=0
    while true; do
        run_count=$((run_count + 1))
        echo "Test run #${run_count}..."
        start_time=$(date +%s)
        if ! just test; then
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            echo "FAILED: Tests failed on run #${run_count} after ${duration}s!"
            exit 1
        fi
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        total_time=$((total_time + duration))
        avg_time=$((total_time / run_count))
        echo "PASSED: Test run #${run_count} passed in ${duration}s (avg: ${avg_time}s)"
        sleep 1
    done



##############
### Docker ###
##############


# Run CLI in development container
dev-cli *args:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev uv run python src/cli.py {{args}}

# Rebuild and restart development environment
dev-rebuild:
    docker-compose -f docker-compose.dev.yml down
    docker-compose -f docker-compose.dev.yml build --no-cache
    docker-compose -f docker-compose.dev.yml up -d

# Open an interactive bash shell in the Docker container
docker-bash:
    docker run --rm -it dcypher bash

# Run the CLI in Docker container
docker-cli *args:
    docker run --rm -it dcypher uv run python src/cli.py {{args}}

# Run a custom command in the Docker container
docker-exec command:
    docker run --rm -it dcypher {{command}}


# Run the FastAPI server in development container
docker-dev-serve:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000




############################
### Building & Compiling ###
############################



# Build OpenFHE C++ library locally (not system-wide)
build-openfhe:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building OpenFHE C++ library locally..."
    cd vendor/openfhe-development
    mkdir -p build
    cd build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$(pwd)/../../../build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_UNITTESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=OFF
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
    make install
    echo "OpenFHE installed to: $(pwd)/../../../build"

# Build OpenFHE Python bindings using local C++ library
build-openfhe-python: build-openfhe
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building OpenFHE Python bindings..."
    
    # Get the absolute path to our OpenFHE installation
    OPENFHE_INSTALL_PATH="$(pwd)/build"
    CMAKE_PREFIX_PATH="${OPENFHE_INSTALL_PATH}:${CMAKE_PREFIX_PATH:-}"
    PKG_CONFIG_PATH="${OPENFHE_INSTALL_PATH}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    
    cd vendor/openfhe-python
    uv add pybind11 pybind11-global pybind11-stubgen
    
    # Clean any previous build artifacts
    rm -rf build dist *.egg-info openfhe/*.so
    
    # Build the Python package with OpenFHE path
    env CMAKE_PREFIX_PATH="${OPENFHE_INSTALL_PATH}" \
        PKG_CONFIG_PATH="${OPENFHE_INSTALL_PATH}/lib/pkgconfig:${PKG_CONFIG_PATH:-}" \
        uv run python setup.py build_ext --inplace
    
    cd ../..
    # Install in development mode to replace the file:// dependency
    uv add --editable ./vendor/openfhe-python

# Clone and build liboqs C library locally (not system-wide)
build-liboqs:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building liboqs C library locally..."
    cd vendor/liboqs
    mkdir -p build
    cd build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$(pwd)/../../../build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_ALGS_ENABLED=All
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
    make install
    echo "liboqs installed to: $(pwd)/../../../build"

# Build liboqs-python bindings using local liboqs library
build-liboqs-python: build-liboqs
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building liboqs-python bindings..."
    source ./env.sh
    # Install liboqs-python in development mode from the vendor directory
    uv add --editable vendor/liboqs-python
    echo "liboqs-python installed and available!"

# Build both OpenFHE C++ and Python bindings, and liboqs-python
build-all: setup build-openfhe-python build-liboqs-python build-docs 

# Build just the static libraries
build-static: build-openfhe build-liboqs

build-docs:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail

    uv run python ./src/dcypher/hdprint/docs/readme.py > ./src/dcypher/hdprint/README.txt
    uv run python ./src/dcypher/hdprint/docs/readme_hdprint.py > ./src/dcypher/hdprint/README.hdprint.txt
    uv run python ./src/dcypher/hdprint/docs/readme_paiready.py > ./src/dcypher/hdprint/README.paiready.txt

# Clean OpenFHE builds
clean-openfhe:
    rm -rf vendor/openfhe-development/build vendor/openfhe-python/build vendor/openfhe-python/openfhe/openfhe.so

# Clean liboqs builds
clean-liboqs:
    rm -rf vendor/liboqs/build build/lib/liboqs* build/include/oqs/

# Clean liboqs-python builds
clean-liboqs-python:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    # Remove from uv dependencies if it exists
    if uv pip show liboqs-python >/dev/null 2>&1; then
        uv pip uninstall liboqs-python
    fi
    # Clean any build artifacts
    rm -rf vendor/liboqs-python/build vendor/liboqs-python/dist vendor/liboqs-python/*.egg-info

# Clean OpenFHE-python builds
clean-openfhe-python:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    # Remove from uv dependencies if it exists
    if uv pip show openfhe-python >/dev/null 2>&1; then
        uv pip uninstall openfhe-python
    fi
    # Clean any build artifacts
    rm -rf vendor/openfhe-python/build vendor/openfhe-python/dist vendor/openfhe-python/*.egg-info vendor/openfhe-python/openfhe/openfhe.so

# Clean all builds
clean: clean-openfhe clean-liboqs clean-liboqs-python clean-openfhe-python

# Just cleans up all the intermediary build artifacts.
cleanup:
    rm -rf vendor/liboqs/build vendor/openfhe-development/build

# Check which liboqs algorithms are available
check-liboqs:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Checking liboqs algorithm availability..."
    source ./env.sh
    uv run python scripts/check_liboqs_algorithms.py

