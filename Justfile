# DCypher Development Tasks

# Show available tasks
default:
    @just --list

run:
    uv run uvicorn main:app --reload

tui:
    uv run python -m src.cli tui

# Build the Docker image for Intel processor
docker-build-intel:
    docker build build --platform linux/amd64 -t dcypher --load .

# Build the development Docker image
docker-build-intel-dev:
    docker buildx build --platform linux/amd64 -f dockerfile.dev -t dcypher-dev --load .

# Run the Docker container
docker-run-intel:
    docker run --rm dcypher

# Start development environment with volume mounting
dev-up-intel:
    docker-compose -f docker-compose.dev.yml up -d

# Stop development environment
dev-down-intel:
    docker-compose -f docker-compose.dev.yml down

# Open an interactive bash shell in the development container
dev-shell-intel:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev bash

# Run tests in development container
dev-test-intel:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev uv run pytest tests/ -v

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

# Run the CLI locally with uv
cli *args:
    uv run python src/cli.py {{args}}

# Run the CLI in Docker container
docker-cli *args:
    docker run --rm -it dcypher uv run python src/cli.py {{args}}

# Run a custom command in the Docker container
docker-exec command:
    docker run --rm -it dcypher {{command}}

# Run the FastAPI server locally with uv
serve:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    echo "🚀 Starting DCypher FastAPI server..."
    uv run uvicorn src.main:app --reload --host 127.0.0.1 --port 8000

# Run the FastAPI server in development container
dev-serve:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

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
        -DBUILD_BENCHMARKS=ON
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
    make install
    echo "OpenFHE installed to: $(pwd)/../../../build"

# Build OpenFHE Python bindings using local C++ library
build-openfhe-python: build-openfhe
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building OpenFHE Python bindings..."
    export CMAKE_PREFIX_PATH="$(pwd)/build:${CMAKE_PREFIX_PATH:-}"
    export LD_LIBRARY_PATH="$(pwd)/build/lib:${LD_LIBRARY_PATH:-}"
    export DYLD_LIBRARY_PATH="$(pwd)/build/lib:${DYLD_LIBRARY_PATH:-}"
    cd vendor/openfhe-python
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
build-all: build-openfhe-python build-liboqs-python

# Clean OpenFHE builds
clean-openfhe:
    rm -rf vendor/openfhe-development/build openfhe-local vendor/openfhe-python/build vendor/openfhe-python/openfhe/openfhe.so

# Clean liboqs builds
clean-liboqs:
    rm -rf vendor/liboqs/build liboqs-local

# Clean liboqs-python builds
clean-liboqs-python:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    # Remove from uv dependencies if it exists
    if uv pip show liboqs-python >/dev/null 2>&1; then
        uv remove liboqs-python
    fi
    # Clean any build artifacts
    rm -rf vendor/liboqs-python/build vendor/liboqs-python/dist vendor/liboqs-python/*.egg-info

# Clean OpenFHE-python builds
clean-openfhe-python:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    # Remove from uv dependencies if it exists
    if uv pip show openfhe-python >/dev/null 2>&1; then
        uv remove openfhe-python
    fi
    # Clean any build artifacts
    rm -rf vendor/openfhe-python/build vendor/openfhe-python/dist vendor/openfhe-python/*.egg-info vendor/openfhe-python/openfhe/openfhe.so

# Clean all builds
clean: clean-openfhe clean-liboqs clean-liboqs-python clean-openfhe-python

# Check which liboqs algorithms are available
check-liboqs:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "🔍 Checking liboqs algorithm availability..."
    source ./env.sh
    uv run python scripts/check_liboqs_algorithms.py

test:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    source ./env.sh
    echo "🧪 Running DCypher test suite..."
    # echo "📋 Running crypto tests sequentially (to avoid OpenFHE context conflicts)..."
    uv run pytest -n auto --dist worksteal ./tests/

# Run tests repeatedly until they break or user cancels
test-until-break:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "🔄 Running tests repeatedly until failure or cancellation (Ctrl+C to stop)..."
    run_count=0
    total_time=0
    while true; do
        run_count=$((run_count + 1))
        echo "📋 Test run #${run_count}..."
        start_time=$(date +%s)
        if ! just test; then
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            echo "❌ Tests failed on run #${run_count} after ${duration}s!"
            exit 1
        fi
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        total_time=$((total_time + duration))
        avg_time=$((total_time / run_count))
        echo "✅ Test run #${run_count} passed in ${duration}s (avg: ${avg_time}s)"
        sleep 1
    done

# Build OpenHands (All Hands AI) development environment
doit-build:
    docker build -t dcypher-allhands -f dockerfile.allhands .

# Start OpenHands (All Hands AI) development environment
doit:
    docker run -it --rm --pull=always \
        -e SANDBOX_RUNTIME_CONTAINER_IMAGE=dcypher-allhands \
        -e SANDBOX_VOLUMES=${PWD}:/workspace \
        -e SANDBOX_USER_ID=$(id -u) \
        -e LOG_ALL_EVENTS=true \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v ~/.openhands:/.openhands \
        -p 127.0.0.1:3000:3000 \
        --add-host host.docker.internal:host-gateway \
        --dns 1.1.1.1 \
        --dns 8.8.8.8 \
        --dns 8.8.4.4 \
        --name openhands-app \
        docker.all-hands.dev/all-hands-ai/openhands:0.46
