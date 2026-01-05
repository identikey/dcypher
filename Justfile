# DCypher Rust Development Tasks
#
# Build system for Rust FFI bindings to OpenFHE and liboqs

# Show available tasks
default:
    @just --list

# --------------------
# Rust Development
# --------------------

# Build the workspace
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run all tests (sequential: OpenFHE has global state that can't be shared across test threads)
# Note: OpenMP parallelism happens *within* each operation, not across test cases
test:
    cargo test -- --test-threads=1

# Run tests for dcypher-ffi specifically
test-ffi:
    cargo test -p dcypher-ffi

# Run tests for dcypher-openfhe-sys (must be sequential due to OpenFHE global state)
test-openfhe:
    cargo test -p dcypher-openfhe-sys -- --test-threads=1

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
format:
    cargo fmt

# Check formatting without applying
format-check:
    cargo fmt -- --check

# Build documentation
docs:
    cargo doc --no-deps

# Clean Rust build artifacts
clean-rust:
    cargo clean

# --------------------
# Submodules
# --------------------

# Initialize/update git submodules
submodules:
    git submodule update --init --recursive --depth 1

# --------------------
# OpenFHE (Static)
# --------------------

# Build OpenFHE as a static library (with OpenMP for thread safety)
build-openfhe:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    echo "Building OpenFHE C++ library (static + OpenMP)..."
    
    INSTALL_DIR="$(pwd)/vendor/openfhe-install"
    
    # Find OpenMP on macOS (Homebrew libomp)
    OMP_ROOT=""
    if [[ "$(uname)" == "Darwin" ]]; then
        if [[ -d "/opt/homebrew/opt/libomp" ]]; then
            OMP_ROOT="/opt/homebrew/opt/libomp"
        elif [[ -d "/usr/local/opt/libomp" ]]; then
            OMP_ROOT="/usr/local/opt/libomp"
        fi
    fi
    
    cd vendor/openfhe-development
    rm -rf build
    mkdir -p build
    cd build
    
    CMAKE_ARGS=(
        -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_STATIC=ON
        -DBUILD_UNITTESTS=OFF
        -DBUILD_EXAMPLES=OFF
        -DBUILD_BENCHMARKS=OFF
    )
    
    if [[ -n "${OMP_ROOT}" ]]; then
        echo "Using OpenMP from: ${OMP_ROOT}"
        CMAKE_ARGS+=(
            -DWITH_OPENMP=ON
            "-DOpenMP_C_FLAGS=-Xpreprocessor -fopenmp"
            "-DOpenMP_CXX_FLAGS=-Xpreprocessor -fopenmp"
            -DOpenMP_C_LIB_NAMES=omp
            -DOpenMP_CXX_LIB_NAMES=omp
            "-DOpenMP_omp_LIBRARY=${OMP_ROOT}/lib/libomp.dylib"
            "-DCMAKE_C_FLAGS=-I${OMP_ROOT}/include"
            "-DCMAKE_CXX_FLAGS=-I${OMP_ROOT}/include"
        )
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "⚠️  libomp not found. Install with: brew install libomp"
        echo "   Building without OpenMP (reduced parallelism)"
        CMAKE_ARGS+=(-DWITH_OPENMP=OFF)
    else
        # Linux: OpenMP usually just works with GCC
        echo "Using system OpenMP (GCC/libgomp)"
        CMAKE_ARGS+=(-DWITH_OPENMP=ON)
    fi
    
    cmake .. "${CMAKE_ARGS[@]}"
    
    # Cross-platform nproc
    NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    make -j${NPROC}
    make install
    
    echo ""
    echo "✅ OpenFHE static libraries installed to: ${INSTALL_DIR}"
    echo "   Libraries: ${INSTALL_DIR}/lib/"
    echo "   Headers:   ${INSTALL_DIR}/include/openfhe/"
    if [[ -n "${OMP_ROOT}" ]] || [[ "$(uname)" != "Darwin" ]]; then
        echo "   OpenMP:    ✅ Enabled (parallel ops)"
    else
        echo "   OpenMP:    ❌ Disabled"
    fi
    echo ""
    echo "Note: For recryption proxy, CryptoContext and keys should be"
    echo "      immutable after setup. Concurrent recrypt ops on different"
    echo "      ciphertexts are thread-safe."

# Check if OpenMP is available (macOS: brew install libomp)
check-omp:
    #!/usr/bin/env bash
    if [[ "$(uname)" == "Darwin" ]]; then
        if [[ -d "/opt/homebrew/opt/libomp" ]]; then
            echo "✅ libomp found at /opt/homebrew/opt/libomp"
            ls -la /opt/homebrew/opt/libomp/lib/
        elif [[ -d "/usr/local/opt/libomp" ]]; then
            echo "✅ libomp found at /usr/local/opt/libomp"
            ls -la /usr/local/opt/libomp/lib/
        else
            echo "❌ libomp not found. Install with: brew install libomp"
            exit 1
        fi
    else
        if command -v gcc &>/dev/null && gcc -fopenmp -E - < /dev/null &>/dev/null; then
            echo "✅ OpenMP available via GCC"
        else
            echo "❌ OpenMP not available. Install gcc or libgomp."
            exit 1
        fi
    fi

# Clean OpenFHE build artifacts
clean-openfhe:
    rm -rf vendor/openfhe-development/build vendor/openfhe-install

# --------------------
# liboqs (Static)
# --------------------

# Build liboqs as a static library
build-liboqs:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    echo "Building liboqs C library (static)..."
    
    INSTALL_DIR="$(pwd)/vendor/liboqs-install"
    
    # Find OpenSSL on macOS (Homebrew) or Linux
    if [[ -d "/opt/homebrew/opt/openssl@3" ]]; then
        OPENSSL_ROOT="/opt/homebrew/opt/openssl@3"
    elif [[ -d "/usr/local/opt/openssl@3" ]]; then
        OPENSSL_ROOT="/usr/local/opt/openssl@3"
    elif command -v brew &>/dev/null; then
        OPENSSL_ROOT="$(brew --prefix openssl@3 2>/dev/null || echo "")"
    else
        OPENSSL_ROOT=""
    fi
    
    cd vendor/liboqs
    rm -rf build
    mkdir -p build
    cd build
    
    CMAKE_ARGS=(
        -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_SHARED_LIBS=OFF
        -DOQS_BUILD_ONLY_LIB=ON
    )
    
    if [[ -n "${OPENSSL_ROOT}" ]]; then
        echo "Using OpenSSL from: ${OPENSSL_ROOT}"
        CMAKE_ARGS+=(
            -DOQS_USE_OPENSSL=ON
            -DOPENSSL_ROOT_DIR="${OPENSSL_ROOT}"
        )
    else
        echo "⚠️  OpenSSL not found, building without OpenSSL acceleration"
        CMAKE_ARGS+=(-DOQS_USE_OPENSSL=OFF)
    fi
    
    cmake .. "${CMAKE_ARGS[@]}"
    
    # Cross-platform nproc
    NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    make -j${NPROC}
    make install
    
    echo ""
    echo "✅ liboqs static library installed to: ${INSTALL_DIR}"
    echo "   Library: ${INSTALL_DIR}/lib/liboqs.a"
    echo "   Headers: ${INSTALL_DIR}/include/oqs/"

# Clean liboqs build artifacts
clean-liboqs:
    rm -rf vendor/liboqs/build vendor/liboqs-install

# --------------------
# Combined Targets
# --------------------

# Build all C/C++ dependencies (static)
build-deps: build-openfhe build-liboqs
    @echo ""
    @echo "✅ All dependencies built (static linking ready)"

# Clean all C/C++ dependency builds
clean-deps: clean-openfhe clean-liboqs

# Clean everything (Rust + deps)
clean-all: clean-rust clean-deps

# Full rebuild from scratch
rebuild-all: clean-all submodules build-deps build

# --------------------
# Setup
# --------------------

# First-time setup: submodules + deps + build
setup: submodules build-deps build
    @echo ""
    @echo "🚀 Setup complete! Try: just test-ffi"

# Show dependency install locations
show-deps:
    #!/usr/bin/env bash
    echo "Dependency install locations:"
    echo ""
    if [[ -d "vendor/openfhe-install" ]]; then
        echo "✅ OpenFHE: vendor/openfhe-install/"
        ls -la vendor/openfhe-install/lib/*.a 2>/dev/null || echo "   (no static libs found)"
    else
        echo "❌ OpenFHE: not built (run: just build-openfhe)"
    fi
    echo ""
    if [[ -d "vendor/liboqs-install" ]]; then
        echo "✅ liboqs: vendor/liboqs-install/"
        ls -la vendor/liboqs-install/lib/*.a 2>/dev/null || echo "   (no static libs found)"
    else
        echo "❌ liboqs: not built (run: just build-liboqs)"
    fi

