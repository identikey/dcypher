# DCypher Development Tasks

# Show available tasks
default:
    @just --list

# Build the Docker image for Intel processor
docker-build:
    docker build build --platform linux/amd64 -t dcypher --load .

# Build the development Docker image
docker-build-dev:
    docker buildx build --platform linux/amd64 -f dockerfile.dev -t dcypher-dev --load .

# Run the Docker container
docker-run:
    docker run --rm dcypher

# Start development environment with volume mounting
dev-up:
    docker-compose -f docker-compose.dev.yml up -d

# Stop development environment
dev-down:
    docker-compose -f docker-compose.dev.yml down

# Open an interactive bash shell in the development container
dev-shell:
    docker-compose -f docker-compose.dev.yml exec dcypher-dev bash

# Run tests in development container
dev-test:
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

proxy *args:
    ./zig-out/bin/zig_proxy {{args}}
# Build OpenFHE C++ library locally (not system-wide)
build-openfhe:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building OpenFHE C++ library locally..."
    cd vendor/openfhe-development
    mkdir -p build
    cd build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$(pwd)/../../../openfhe-local" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_UNITTESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=OFF
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
    make install
    echo "OpenFHE installed to: $(pwd)/../../../openfhe-local"

# Build OpenFHE Python bindings using local C++ library
build-openfhe-python: build-openfhe
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building OpenFHE Python bindings..."
    export CMAKE_PREFIX_PATH="$(pwd)/openfhe-local:${CMAKE_PREFIX_PATH:-}"
    export LD_LIBRARY_PATH="$(pwd)/openfhe-local/lib:${LD_LIBRARY_PATH:-}"
    export DYLD_LIBRARY_PATH="$(pwd)/openfhe-local/lib:${DYLD_LIBRARY_PATH:-}"
    cd vendor/openfhe-python
    uv run python setup.py build_ext --inplace
    cd ../..
    # Install in development mode to replace the file:// dependency
    uv add --editable ./vendor/openfhe-python

# Clone and build liboqs C library locally (not system-wide)
build-liboqs:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building liboqs C library locally..."
    cd vendor/liboqs
    mkdir -p build
    cd build
    cmake .. \
        -DCMAKE_INSTALL_PREFIX="$(pwd)/../../../liboqs-local" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD=OFF
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
    make install
    echo "liboqs installed to: $(pwd)/../../../liboqs-local"

# Build both OpenFHE C++ and Python bindings
build-all: build-openfhe-python build-liboqs

# Clean OpenFHE builds
clean-openfhe:
    rm -rf vendor/openfhe-development/build openfhe-local vendor/openfhe-python/build vendor/openfhe-python/openfhe/openfhe.so

# Clean liboqs builds
clean-liboqs:
    rm -rf vendor/liboqs/build liboqs-local

# Clean all builds
clean: clean-openfhe clean-liboqs

test:
    #!/usr/bin/env bash
    set -euo pipefail
    export LD_LIBRARY_PATH="/workspace/openfhe-local/lib:/workspace/liboqs-local/lib:${LD_LIBRARY_PATH:-}"
    export PYTHONPATH="/workspace/src:${PYTHONPATH:-}"
    echo "🧪 Running DCypher test suite..."
    # echo "📋 Running crypto tests sequentially (to avoid OpenFHE context conflicts)..."
    uv run pytest -n auto --dist worksteal ./tests/

# Run tests repeatedly until they break or user cancels
test-until-break:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🔄 Running tests repeatedly until failure or cancellation (Ctrl+C to stop)..."
    run_count=0
    while true; do
        run_count=$((run_count + 1))
        echo "📋 Test run #${run_count}..."
        if ! just test; then
            echo "❌ Tests failed on run #${run_count}!"
            exit 1
        fi
        echo "✅ Test run #${run_count} passed"
        sleep 1
    done

# Start OpenHands (All Hands AI) development environment
doit:
    docker pull docker.all-hands.dev/all-hands-ai/runtime:0.47-nikolaik
    docker run -it --rm --pull=always \
        -e SANDBOX_RUNTIME_CONTAINER_IMAGE=docker.all-hands.dev/all-hands-ai/runtime:0.47-nikolaik \
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
        docker.all-hands.dev/all-hands-ai/openhands:0.47
