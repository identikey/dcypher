# OpenFHE Shared Library Build Plan

## Current State Analysis

### What We Have
- **OpenFHE Libraries**: Pre-built in `/workspace/build/lib/`
  - `libOPENFHEcore.1.3.0.dylib` (Core functionality)
  - `libOPENFHEpke.1.3.0.dylib` (Public Key Encryption)
  - `libOPENFHEbinfhe.1.3.0.dylib` (Binary FHE)
- **liboqs Library**: `liboqs.0.14.0-rc1.dylib` (Post-quantum crypto)
- **C++ Wrapper**: `openfhe_wrapper.cpp/h` with C interface
- **Zig Integration**: `openfhe.zig` with Zig wrapper types
- **Build Configuration**: CMake configs and pkg-config files

### Current Issues
1. **build.zig** doesn't link OpenFHE libraries
2. **build_openfhe.zig** has incorrect paths (references `../openfhe-development/`)
3. **No unified shared library** combining our wrapper with OpenFHE
4. **Missing Python FFI interface**

## Optimal Build Strategy

### Approach: Multi-Layer Architecture

```
┌─────────────────────────────────────────┐
│           Python Application            │
├─────────────────────────────────────────┤
│         Python FFI Wrapper             │
│         (ctypes/cffi)                   │
├─────────────────────────────────────────┤
│      libdcypher_ffi.so/.dylib          │
│    (Our C API + OpenFHE Wrapper)       │
├─────────────────────────────────────────┤
│         OpenFHE Libraries               │
│  (libOPENFHEcore, libOPENFHEpke, etc)   │
├─────────────────────────────────────────┤
│            liboqs Library               │
│      (Post-quantum algorithms)          │
└─────────────────────────────────────────┘
```

### Phase 1: Create Unified Shared Library

#### 1.1 Design the C FFI API
Create a clean C interface that Python can easily call:

**File: `src/ffi/dcypher_ffi.h`**
```c
// Context management
typedef struct dcypher_context dcypher_context_t;
dcypher_context_t* dcypher_context_create(int plaintext_modulus, int security_level);
void dcypher_context_destroy(dcypher_context_t* ctx);
int dcypher_context_serialize(dcypher_context_t* ctx, char** output, size_t* output_len);
dcypher_context_t* dcypher_context_deserialize(const char* data, size_t data_len);

// Key management
typedef struct dcypher_keypair dcypher_keypair_t;
dcypher_keypair_t* dcypher_keygen(dcypher_context_t* ctx);
void dcypher_keypair_destroy(dcypher_keypair_t* keypair);
int dcypher_keypair_serialize_public(dcypher_keypair_t* keypair, char** output, size_t* output_len);
int dcypher_keypair_serialize_private(dcypher_keypair_t* keypair, char** output, size_t* output_len);

// Encryption/Decryption
typedef struct dcypher_ciphertext dcypher_ciphertext_t;
dcypher_ciphertext_t* dcypher_encrypt(dcypher_context_t* ctx, dcypher_keypair_t* keypair, 
                                      const int64_t* data, size_t data_len);
int dcypher_decrypt(dcypher_context_t* ctx, dcypher_keypair_t* keypair, 
                    dcypher_ciphertext_t* ciphertext, int64_t** output, size_t* output_len);

// Proxy Re-encryption
typedef struct dcypher_reenc_key dcypher_reenc_key_t;
dcypher_reenc_key_t* dcypher_rekey_gen(dcypher_context_t* ctx, dcypher_keypair_t* from_key, 
                                       dcypher_keypair_t* to_key);
dcypher_ciphertext_t* dcypher_reencrypt(dcypher_context_t* ctx, dcypher_ciphertext_t* ciphertext, 
                                        dcypher_reenc_key_t* reenc_key);

// Error handling
const char* dcypher_get_last_error(void);
void dcypher_clear_error(void);
```

#### 1.2 Update Build System

**Strategy**: Create a comprehensive build.zig that:
1. Builds the C++ wrapper with proper OpenFHE linking
2. Creates a shared library for Python FFI
3. Creates a static library for Zig applications
4. Handles cross-platform differences

### Phase 2: Implementation Steps

#### Step 1: Restructure Source Files
```
src/
├── ffi/
│   ├── dcypher_ffi.h          # C API header
│   ├── dcypher_ffi.cpp        # C API implementation
│   └── dcypher_ffi.zig        # Zig FFI wrapper
├── wrapper/
│   ├── openfhe_wrapper.h      # Existing C++ wrapper (move here)
│   └── openfhe_wrapper.cpp    # Existing C++ wrapper (move here)
├── crypto.zig                 # Zig crypto implementation
├── main.zig                   # CLI application
└── root.zig                   # Library root
```

#### Step 2: Update build.zig

**Key Changes**:
1. **Fix library paths** to use `/workspace/build/`
2. **Create multiple build targets**:
   - Shared library for Python FFI
   - Static library for Zig applications
   - CLI executable
3. **Proper OpenFHE linking** with all required libraries
4. **Cross-platform support** for .so/.dylib/.dll

#### Step 3: Create Python FFI Wrapper

**File: `src/lib/zig_crypto.py`**
```python
import ctypes
import os
from typing import Optional, List, Tuple

# Load the shared library
_lib_path = os.path.join(os.path.dirname(__file__), '..', '..', 'zig-out', 'lib', 'libdcypher_ffi.so')
_lib = ctypes.CDLL(_lib_path)

class DcypherContext:
    def __init__(self, plaintext_modulus: int = 65537, security_level: int = 128):
        self._ptr = _lib.dcypher_context_create(plaintext_modulus, security_level)
        if not self._ptr:
            raise RuntimeError("Failed to create crypto context")
    
    def __del__(self):
        if hasattr(self, '_ptr') and self._ptr:
            _lib.dcypher_context_destroy(self._ptr)
```

### Phase 3: Detailed Implementation Plan

#### 3.1 Update build.zig (Priority: HIGH)

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define build paths
    const openfhe_lib_path = b.path("build/lib");
    const openfhe_include_path = b.path("build/include");

    // Create shared library for Python FFI
    const ffi_lib = b.addSharedLibrary(.{
        .name = "dcypher_ffi",
        .target = target,
        .optimize = optimize,
    });

    // Add C++ sources
    ffi_lib.addCSourceFiles(.{
        .files = &.{
            "src/wrapper/openfhe_wrapper.cpp",
            "src/ffi/dcypher_ffi.cpp",
        },
        .flags = &.{
            "-std=c++17",
            "-fPIC",
            "-DOPENFHE_VERSION=1.3.0",
            "-DMATHBACKEND=4",
        },
    });

    // Add include paths
    ffi_lib.addIncludePath(openfhe_include_path);
    ffi_lib.addIncludePath(b.path("src/wrapper"));
    ffi_lib.addIncludePath(b.path("src/ffi"));

    // Link OpenFHE libraries
    ffi_lib.addLibraryPath(openfhe_lib_path);
    ffi_lib.linkSystemLibrary("OPENFHEcore");
    ffi_lib.linkSystemLibrary("OPENFHEpke");
    ffi_lib.linkSystemLibrary("OPENFHEbinfhe");
    ffi_lib.linkSystemLibrary("oqs");

    // Platform-specific linking
    switch (target.result.os.tag) {
        .macos => {
            ffi_lib.linkFramework("Security");
            ffi_lib.linkSystemLibrary("omp");
        },
        .linux => {
            ffi_lib.linkSystemLibrary("gomp");
            ffi_lib.linkSystemLibrary("pthread");
        },
        else => {},
    }

    ffi_lib.linkLibCpp();
    b.installArtifact(ffi_lib);

    // Create Zig library module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create static library for Zig applications
    const zig_lib = b.addStaticLibrary(.{
        .name = "dcypher",
        .root_module = lib_mod,
    });

    zig_lib.linkLibrary(ffi_lib);
    b.installArtifact(zig_lib);

    // Create CLI executable
    const exe = b.addExecutable(.{
        .name = "dcypher",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("dcypher", lib_mod);
    exe.linkLibrary(ffi_lib);
    b.installArtifact(exe);
}
```

#### 3.2 Create C FFI Implementation (Priority: HIGH)

**File: `src/ffi/dcypher_ffi.cpp`**
- Implement all C API functions
- Proper error handling with thread-local error storage
- Memory management with clear ownership rules
- Serialization support for context and keys

#### 3.3 Update Zig Integration (Priority: MEDIUM)

**File: `src/ffi/dcypher_ffi.zig`**
- Zig wrapper around C FFI API
- Type-safe interfaces
- RAII-style resource management
- Integration with existing crypto.zig

#### 3.4 Create Python Wrapper (Priority: HIGH)

**File: `src/lib/zig_crypto.py`**
- Complete ctypes wrapper
- Pythonic API matching existing interface
- Proper error handling and exceptions
- Context managers for resource cleanup

### Phase 4: Testing and Validation

#### 4.1 Build Testing
- [ ] Test compilation on macOS (current)
- [ ] Test compilation on Linux
- [ ] Test compilation on Windows
- [ ] Verify all libraries link correctly

#### 4.2 Functionality Testing
- [ ] C API basic operations test
- [ ] Zig wrapper functionality test
- [ ] Python FFI integration test
- [ ] Cross-language compatibility test

#### 4.3 Performance Testing
- [ ] Benchmark against Python-only implementation
- [ ] Memory usage analysis
- [ ] Concurrent access testing

## Implementation Priority

### Week 1: Foundation
1. **Restructure source files** into new layout
2. **Update build.zig** with proper OpenFHE linking
3. **Test basic compilation** and library creation

### Week 2: C FFI API
1. **Implement dcypher_ffi.h/cpp** with core functions
2. **Add error handling** and memory management
3. **Test C API** with simple C program

### Week 3: Python Integration
1. **Create Python FFI wrapper**
2. **Update existing Python code** to use Zig backend
3. **Run existing test suite** with Zig backend

### Week 4: Optimization and Testing
1. **Performance benchmarking**
2. **Cross-platform testing**
3. **Documentation and examples**

## Success Criteria

- [ ] **Shared library builds** successfully on target platforms
- [ ] **Python can call** all crypto operations through FFI
- [ ] **Performance improvement** of 2x+ over Python-only
- [ ] **All existing tests pass** with Zig backend
- [ ] **Memory usage** is stable with no leaks
- [ ] **API compatibility** maintained for existing Python code

## Risk Mitigation

### Technical Risks
- **OpenFHE linking complexity**: Use CMake configs and pkg-config files
- **Cross-platform differences**: Test early and often on different platforms
- **Memory management**: Use RAII patterns and comprehensive testing

### Integration Risks
- **API compatibility**: Maintain existing Python interfaces exactly
- **Performance regression**: Continuous benchmarking during development
- **Build complexity**: Keep build system as simple as possible

This plan provides a clear path to creating a high-performance shared library that both Zig and Python can use, while maintaining full compatibility with existing code.