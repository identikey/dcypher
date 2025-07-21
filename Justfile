# DCypher Development Tasks
#
# OpenHands Development Mode:
# - Regular builds: Uses the specific commit defined in src/dcypher/openhands_version.py
# - Dev mode builds: Preserves your local changes in vendor/openhands (add 'dev' parameter)
#   Examples: just build-openhands-dev, just setup-openhands-dev, just doit-dev

# Show available tasks
default:
    @just --list

# ONE-COMMAND SETUP: Build everything needed for OpenHands development
setup-openhands force="" dev="": (build-openhands force dev)
    #!/usr/bin/env bash
    echo "SUCCESS: DCypher + OpenHands development environment ready!"
    if [ "{{dev}}" = "dev" ] || [ "{{dev}}" = "current" ]; then
        echo "🔧 Built in DEVELOPMENT MODE with local changes"
        echo "TIP: Run 'just doit-dev' to start with development images"
        echo "TIP: Run 'just dev-frontend' for frontend-only development with hot reload"
    else
        echo "TIP: Run 'just doit' to start the OpenHands interface"
        echo "TIP: Run 'just dev-frontend' for frontend-only development with hot reload"
    fi

# Force rebuild everything from scratch (ignores all caches)
setup-openhands-force: (setup-openhands "force")

# Setup in development mode (preserves local changes in vendor/openhands)
setup-openhands-dev: (setup-openhands "" "dev")

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
    echo "Starting DCypher FastAPI server..."
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
        -DBUILD_BENCHMARKS=OFF
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)
    make install
    echo "OpenFHE installed to: $(pwd)/../../../build"

# Build OpenFHE Python bindings using local C++ library
build-openfhe-python: build-openfhe
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building OpenFHE Python bindings..."
    # Install required build dependencies first
    uv add pybind11 pybind11-global pybind11-stubgen
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
build-all: build-openfhe-python build-liboqs-python build-docs

build-docs:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail

    uv run python ./src/dcypher/hdprint/docs/readme.py > ./src/dcypher/hdprint/README.txt
    uv run python ./src/dcypher/hdprint/docs/readme_hdprint.py > ./src/dcypher/hdprint/README.hdprint.txt
    uv run python ./src/dcypher/hdprint/docs/readme_paiready.py > ./src/dcypher/hdprint/README.paiready.txt

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

# Clean OpenHands images
clean-openhands:
    #!/usr/bin/env bash
    echo "Cleaning OpenHands images..."
    # Clean runtime images
    docker images | grep "ghcr.io/all-hands-ai/runtime" | awk '{print $1":"$2}' | xargs -r docker rmi -f 2>/dev/null || true
    docker images | grep "docker.all-hands.dev/all-hands-ai/runtime" | awk '{print $1":"$2}' | xargs -r docker rmi -f 2>/dev/null || true
    # Clean app images  
    docker images | grep "ghcr.io/all-hands-ai/openhands" | awk '{print $1":"$2}' | xargs -r docker rmi -f 2>/dev/null || true
    docker images | grep "docker.all-hands.dev/all-hands-ai/openhands" | awk '{print $1":"$2}' | xargs -r docker rmi -f 2>/dev/null || true
    # Clean DCypher custom image
    docker rmi -f dcypher-openhands:latest 2>/dev/null || true
    echo "OpenHands images cleaned"

# Show OpenHands image status and sources
status-openhands:
    #!/usr/bin/env bash
    echo "OpenHands Image Status"
    echo "======================"
    echo ""
    echo "Runtime Images:"
    docker images | grep -E "(runtime|REPOSITORY)" | head -1
    docker images | grep "all-hands-ai/runtime" | while read line; do
        IMAGE=$(echo "$line" | awk '{print $1":"$2}')
        CREATED=$(echo "$line" | awk '{print $4" "$5" "$6}')
        SIZE=$(echo "$line" | awk '{print $7}')
        if echo "$IMAGE" | grep -q "vendored"; then
            echo "  [LOCAL]  $IMAGE ($SIZE, $CREATED) [LOCAL BUILD]"
        else
            echo "  [REMOTE] $IMAGE ($SIZE, $CREATED) [REMOTE/UNKNOWN]"
        fi
    done
    echo ""
    echo "App Images:"
    docker images | grep "all-hands-ai/openhands" | while read line; do
        IMAGE=$(echo "$line" | awk '{print $1":"$2}')
        CREATED=$(echo "$line" | awk '{print $4" "$5" "$6}')
        SIZE=$(echo "$line" | awk '{print $7}')
        if echo "$IMAGE" | grep -q "vendored"; then
            echo "  [LOCAL]  $IMAGE ($SIZE, $CREATED) [LOCAL BUILD]"
        else
            echo "  [REMOTE] $IMAGE ($SIZE, $CREATED) [REMOTE/UNKNOWN]"
        fi
    done
    echo ""
    DEFINED_COMMIT=$(uv run python scripts/get_openhands_sha.py)
    CURRENT_COMMIT=$(cd vendor/openhands && git rev-parse --short HEAD)
    echo "Defined OpenHands commit (source of truth): ${DEFINED_COMMIT}"
    echo "Current vendored repo commit: ${CURRENT_COMMIT}"
    if [ "${DEFINED_COMMIT}" != "${CURRENT_COMMIT}" ]; then
        echo "⚠️  WARNING: Current commit differs from defined commit!"
        echo "   Run 'just build-openhands-force' to sync to defined commit"
    fi
    echo ""
    echo "Legend:"
    echo "   [LOCAL]  = Built from our vendored repo"
    echo "   [REMOTE] = Pulled from remote or unknown source"

# Clean all builds
clean: clean-openfhe clean-liboqs clean-liboqs-python clean-openfhe-python

# Check which liboqs algorithms are available
check-liboqs:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Checking liboqs algorithm availability..."
    source ./env.sh
    uv run python scripts/check_liboqs_algorithms.py

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

# Run OpenHands full test suite to ensure fork compatibility
test-openhands:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Running OpenHands full test suite..."
    ./scripts/test_openhands_suite.sh

# Run tests specific to our fork modifications
test-openhands-fork:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Running OpenHands fork-specific tests..."
    ./scripts/test_openhands_fork.sh

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

# Build OpenHands runtime image from vendored repo (with force and dev options)
build-openhands-runtime force="" dev="":
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building OpenHands runtime image from vendored repo..."
    cd vendor/openhands
    
    # Get OpenHands version and commit SHA from Python source of truth
    OPENHANDS_VERSION=$(cd ../.. && uv run python scripts/get_openhands_version.py --repo)
    VENDORED_COMMIT=$(cd ../.. && uv run python scripts/get_openhands_sha.py)
    
    # Handle development mode (preserve local changes) vs production mode (checkout defined commit)
    if [ "{{dev}}" = "dev" ] || [ "{{dev}}" = "current" ]; then
        CURRENT_COMMIT=$(git rev-parse --short HEAD)
        echo "🔧 DEVELOPMENT MODE: Using current commit ${CURRENT_COMMIT} (preserving local changes)"
        echo "⚠️  WARNING: This may include uncommitted changes!"
        if ! git diff-index --quiet HEAD --; then
            echo "📝 Uncommitted changes detected in vendor/openhands"
        fi
        VENDORED_TAG="${OPENHANDS_VERSION}-dev-${CURRENT_COMMIT}-$(date +%s)"
    else
        # Ensure we're on the correct commit defined in Python source of truth
        echo "Checking out OpenHands commit ${VENDORED_COMMIT} from Python source of truth..."
        git checkout ${VENDORED_COMMIT}
        VENDORED_TAG="${OPENHANDS_VERSION}-vendored-${VENDORED_COMMIT}"
    fi
    
    LOCAL_RUNTIME_TAG="docker.all-hands.dev/all-hands-ai/runtime:${VENDORED_TAG}"
    
    echo "Building OpenHands runtime with tag: ${LOCAL_RUNTIME_TAG}"
    
    # Check if our specific image exists (unless force rebuild)
    if [ "{{force}}" = "force" ]; then
        echo "Force rebuild requested - skipping cache check"
        SHOULD_BUILD=true
    elif docker image inspect ${LOCAL_RUNTIME_TAG} >/dev/null 2>&1; then
        echo "OpenHands runtime ${LOCAL_RUNTIME_TAG} already exists"
        SHOULD_BUILD=false
    else
        echo "OpenHands runtime not found - will build ${LOCAL_RUNTIME_TAG}"
        SHOULD_BUILD=true
    fi
    
    if [ "$SHOULD_BUILD" = true ]; then
        echo "Installing OpenHands dependencies with Poetry..."
        poetry install --no-dev
        echo "Generating runtime Dockerfile..."
        poetry run python3 openhands/runtime/utils/runtime_build.py \
            --base_image nikolaik/python-nodejs:python3.12-nodejs22 \
            --build_folder containers/runtime
        echo "Building runtime image..."
        ./containers/build.sh -i runtime --load
        
        # Tag the built image with our vendored-specific tag
        RUNTIME_TAG="oh_v${OPENHANDS_VERSION}_image_nikolaik_s_python-nodejs_tag_python3.12-nodejs22"
        docker tag ghcr.io/all-hands-ai/runtime:${RUNTIME_TAG} ${LOCAL_RUNTIME_TAG}
    fi
    
    # Always ensure the standard tag points to our version (override any remote pulls)
    cd ../..
    docker tag ${LOCAL_RUNTIME_TAG} docker.all-hands.dev/all-hands-ai/runtime:${OPENHANDS_VERSION}
    echo "OpenHands runtime ready as docker.all-hands.dev/all-hands-ai/runtime:${OPENHANDS_VERSION}"
    if [ "{{dev}}" = "dev" ] || [ "{{dev}}" = "current" ]; then
        echo "Source: DEVELOPMENT MODE with local changes"
    else
        echo "Source: vendored repo commit ${VENDORED_COMMIT}"
    fi

build-openhands-app force="" dev="":
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Building OpenHands app image from vendored repo..."
    
    # Get OpenHands version and commit SHA from Python source of truth
    cd vendor/openhands
    OPENHANDS_VERSION=$(cd ../.. && uv run python scripts/get_openhands_version.py --repo)
    VENDORED_COMMIT=$(cd ../.. && uv run python scripts/get_openhands_sha.py)
    
    # Handle development mode (preserve local changes) vs production mode (checkout defined commit)
    if [ "{{dev}}" = "dev" ] || [ "{{dev}}" = "current" ]; then
        CURRENT_COMMIT=$(git rev-parse --short HEAD)
        echo "🔧 DEVELOPMENT MODE: Using current commit ${CURRENT_COMMIT} (preserving local changes)"
        echo "⚠️  WARNING: This may include uncommitted changes!"
        if ! git diff-index --quiet HEAD --; then
            echo "📝 Uncommitted changes detected in vendor/openhands"
        fi
        VENDORED_TAG="${OPENHANDS_VERSION}-dev-${CURRENT_COMMIT}-$(date +%s)"
    else
        # Ensure we're on the correct commit defined in Python source of truth
        echo "Checking out OpenHands commit ${VENDORED_COMMIT} from Python source of truth..."
        git checkout ${VENDORED_COMMIT}
        VENDORED_TAG="${OPENHANDS_VERSION}-vendored-${VENDORED_COMMIT}"
    fi
    
    LOCAL_APP_TAG="docker.all-hands.dev/all-hands-ai/openhands:${VENDORED_TAG}"
    
    echo "Building OpenHands app with tag: ${LOCAL_APP_TAG}"
    
    # Check if our specific image exists (unless force rebuild)
    if [ "{{force}}" = "force" ]; then
        echo "Force rebuild requested - skipping cache check"
        SHOULD_BUILD=true
    elif docker image inspect ${LOCAL_APP_TAG} >/dev/null 2>&1; then
        echo "OpenHands app ${LOCAL_APP_TAG} already exists"
        SHOULD_BUILD=false
    else
        echo "OpenHands app not found - will build ${LOCAL_APP_TAG}"
        SHOULD_BUILD=true
    fi
    
    if [ "$SHOULD_BUILD" = true ]; then
        echo "Building OpenHands app image..."
        ./containers/build.sh -i openhands --load
        
        # The OpenHands app build creates an untagged image - find the most recent one  
        UNTAGGED_IMAGE=$(docker images -q | head -1)
        if [ -n "$UNTAGGED_IMAGE" ]; then
            docker tag "$UNTAGGED_IMAGE" ${LOCAL_APP_TAG}
            echo "Tagged untagged image $UNTAGGED_IMAGE as ${LOCAL_APP_TAG}"
        else
            echo "WARNING: Could not find recently built untagged image"
            docker images | head -5
        fi
    fi
    
    # Always ensure the standard tag points to our version (override any remote pulls)
    cd ../..
    docker tag ${LOCAL_APP_TAG} docker.all-hands.dev/all-hands-ai/openhands:${OPENHANDS_VERSION}
    echo "OpenHands app ready as docker.all-hands.dev/all-hands-ai/openhands:${OPENHANDS_VERSION}"
    if [ "{{dev}}" = "dev" ] || [ "{{dev}}" = "current" ]; then
        echo "Source: DEVELOPMENT MODE with local changes"
    else
        echo "Source: vendored repo commit ${VENDORED_COMMIT}"
    fi

# Build all OpenHands dependencies
build-openhands force="" dev="": (build-openhands-runtime force dev) (build-openhands-app force dev)

# Force rebuild all OpenHands images (ignores cache)
build-openhands-force: (build-openhands "force")

# Build OpenHands images in development mode (preserves local changes)
build-openhands-dev: (build-openhands "" "dev")

# Force rebuild OpenHands images in development mode 
build-openhands-dev-force: (build-openhands "force" "dev")

# Update OpenHands to a specific commit SHA and rebuild
update-openhands-commit sha:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Updating OpenHands source of truth to commit {{sha}}..."
    
    # First, check out the commit in vendored repo to validate it exists
    cd vendor/openhands
    git fetch origin  # Make sure we have latest refs
    git checkout {{sha}}
    
    # Get full SHA for the commit
    FULL_SHA=$(git rev-parse HEAD)
    SHORT_SHA=$(git rev-parse --short HEAD)
    
    # Update the Python source of truth
    cd ../..
    python scripts/update_openhands_version.py --commit {{sha}} --full-sha ${FULL_SHA}
    
    echo "✅ Updated OpenHands source of truth:"
    echo "   Short SHA: ${SHORT_SHA}"
    echo "   Full SHA: ${FULL_SHA}"
    echo ""
    echo "🔄 Now rebuild with: just build-openhands-force"

# Update OpenHands to current vendored repo state
update-openhands-current:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    echo "Updating OpenHands source of truth to current vendored repo state..."
    python scripts/update_openhands_version.py --auto
    echo ""
    echo "🔄 Now rebuild with: just build-openhands-force"

build-doit force="" dev="": (build-openhands force dev)
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    OPENHANDS_VERSION="${OPENHANDS_VERSION:-$(uv run python scripts/get_openhands_version.py --repo)}"
    echo "Building DCypher OpenHands AI development environment..."
    
    # Add --no-cache if force rebuild is requested
    DOCKER_ARGS=""
    if [ "{{force}}" = "force" ]; then
        DOCKER_ARGS="--no-cache"
        echo "🔄 Force rebuild requested - ignoring Docker cache"
    fi
    
    docker build -t dcypher-openhands \
        -f Dockerfile.allhands \
        --build-arg OPENHANDS_VERSION=${OPENHANDS_VERSION} \
        ${DOCKER_ARGS} \
        .
    echo "DCypher OpenHands image ready!"
    if [ "{{dev}}" = "dev" ] || [ "{{dev}}" = "current" ]; then
        echo "🔧 Built with DEVELOPMENT MODE OpenHands images"
    fi

# Force rebuild DCypher OpenHands environment
build-doit-force: (build-doit "force")

# Build DCypher OpenHands environment in development mode
build-doit-dev force="": (build-doit force "dev")

# Force rebuild DCypher OpenHands environment in development mode
build-doit-dev-force: (build-doit-dev "force")

# Start OpenHands development environment
doit:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    OPENHANDS_VERSION=${OPENHANDS_VERSION:-$(uv run python scripts/get_openhands_version.py --repo)}
    echo "Starting DCypher OpenHands AI development environment..."
    docker run -it --rm \
        -e L=DEBUG \
        -e SANDBOX_RUNTIME_CONTAINER_IMAGE=dcypher-openhands \
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
        docker.all-hands.dev/all-hands-ai/openhands:${OPENHANDS_VERSION}

# Build and start OpenHands development environment with local changes
# Usage: just doit-dev                    # Use existing images (fast)
#        just doit-dev --build            # Force rebuild images (slower but fresh)
doit-dev build="":
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    
    OPENHANDS_VERSION=${OPENHANDS_VERSION:-$(uv run python scripts/get_openhands_version.py --repo)}
    
    # Check if build is needed
    NEED_BUILD=false
    if [ "{{build}}" = "--build" ] || [ "{{build}}" = "force" ]; then
        echo "🔨 Force rebuild requested"
        NEED_BUILD=true
    elif ! docker image inspect dcypher-openhands:latest >/dev/null 2>&1; then
        echo "📦 DCypher image not found - building..."
        NEED_BUILD=true
    elif ! docker image inspect docker.all-hands.dev/all-hands-ai/openhands:${OPENHANDS_VERSION} >/dev/null 2>&1; then
        echo "📦 OpenHands v${OPENHANDS_VERSION} image not found - building..."
        NEED_BUILD=true
    else
        echo "📦 Using existing images (run with --build to force rebuild)"
    fi
    
    # Build if needed
    if [ "$NEED_BUILD" = "true" ]; then
        FORCE_ARG=""
        if [ "{{build}}" = "--build" ] || [ "{{build}}" = "force" ]; then
            FORCE_ARG="force"
        fi
        just build-doit-dev "${FORCE_ARG}"
    fi
    
    echo "🔧 Starting DCypher OpenHands AI development environment (DEV MODE)..."
    echo "💡 This uses your local changes in vendor/openhands"
    echo "📁 Mounting OpenHands source directories for live development"
    echo "🔄 Hot reload enabled - Python changes will be picked up automatically"
    echo "⚙️  Preserving container's virtual environment and frontend build"
    echo "🚀 Smart caching - only rebuilds when images are missing or forced"
    docker run -it --rm \
        -e LOG_LEVEL=DEBUG \
        -e SANDBOX_RUNTIME_CONTAINER_IMAGE=dcypher-openhands \
        -e SANDBOX_VOLUMES=${PWD}:/workspace,${PWD}/vendor/openhands:/openhands:rw \
        -e SANDBOX_USER_ID=$(id -u) \
        -e LOG_ALL_EVENTS=true \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v ~/.openhands:/.openhands \
        -v ${PWD}/vendor/openhands/openhands:/app/openhands \
        -v ${PWD}/vendor/openhands/microagents:/app/microagents \
        -v ${PWD}/vendor/openhands/pyproject.toml:/app/pyproject.toml \
        -v ${PWD}/vendor/openhands/poetry.lock:/app/poetry.lock \
        -v ${PWD}/vendor/openhands/README.md:/app/README.md \
        -v ${PWD}/vendor/openhands/MANIFEST.in:/app/MANIFEST.in \
        -v ${PWD}/vendor/openhands/LICENSE:/app/LICENSE \
        -p 127.0.0.1:3000:3000 \
        --add-host host.docker.internal:host-gateway \
        --dns 1.1.1.1 \
        --dns 8.8.8.8 \
        --dns 8.8.4.4 \
        --name openhands-app \
        docker.all-hands.dev/all-hands-ai/openhands:${OPENHANDS_VERSION} \
        uvicorn openhands.server.listen:app --host 0.0.0.0 --port 3000 --reload --reload-exclude "./workspace"

# Build and start OpenHands development environment with force rebuild
doit-dev-rebuild: (doit-dev "--build")

# Run OpenHands frontend locally with hot reload (requires backend running separately)
doit-dev-frontend:
    #!/usr/bin/env bash
    set -Eeuvxo pipefail
    
    # Check if Node.js is available
    if ! command -v node >/dev/null 2>&1; then
        echo "❌ Node.js is required for frontend development"
        echo "Please install Node.js 22.x or later: https://nodejs.org/"
        exit 1
    fi
    
    # Check Node.js version
    NODE_VERSION=$(node --version | sed 's/v//')
    NODE_MAJOR=$(echo $NODE_VERSION | cut -d. -f1)
    if [ "$NODE_MAJOR" -lt 22 ]; then
        echo "❌ Node.js 22.x or later is required (current: $NODE_VERSION)"
        echo "Please update Node.js: https://nodejs.org/"
        exit 1
    fi
    
    echo "🎨 Starting OpenHands frontend development server..."
    echo "💡 Make sure the backend is running first (e.g., 'just doit' or 'just doit-dev')"
    echo ""
    
    cd vendor/openhands/frontend
    
    # Check if node_modules exists and package.json is newer
    if [ ! -d "node_modules" ] || [ "package.json" -nt "node_modules" ]; then
        echo "📦 Installing/updating frontend dependencies..."
        npm install
    fi
    
    # Set environment variables for local development
    export VITE_BACKEND_HOST=127.0.0.1:3000
    export VITE_BACKEND_BASE_URL=127.0.0.1:3000
    export VITE_FRONTEND_PORT=3001
    export VITE_MOCK_API=false
    export VITE_USE_TLS=false
    export VITE_INSECURE_SKIP_VERIFY=false
    
    echo "🚀 Starting frontend at http://localhost:3001"
    echo "🔧 Environment: Connected to backend at http://127.0.0.1:3000"
    echo ""
    
    # Start frontend dev server
    npm run dev


lint:
    uv run ruff check src/ tests/
    uv run ruff format src/ tests/

format:
    uv run ruff format src/ tests/

typecheck:
    uv run mypy src/