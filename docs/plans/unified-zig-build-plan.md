# Unified Zig Build System Plan

## Current State Analysis

### What Works Well
- **Justfile builds**: OpenFHE and liboqs build successfully to `/workspace/build/`
- **Library structure**: All required libraries are present and properly versioned
- **CMake integration**: Complex C++ projects build correctly with their native build systems

### What Needs Integration
- **build.zig**: Currently doesn't link to the pre-built libraries
- **build_openfhe.zig**: Has incorrect paths and is separate from main build
- **Dependency management**: No clear dependency chain between C++ libs and Zig build

## Optimal Strategy: Hybrid Build System

### Philosophy
- **Keep CMake for C++ dependencies**: OpenFHE and liboqs are complex projects best built with their native CMake
- **Enhance build.zig**: Make it the primary interface that orchestrates everything
- **Clear dependency chain**: build.zig should check for and optionally build dependencies

### Architecture

```
┌─────────────────────────────────────────┐
│            zig build                    │
│         (Primary Interface)            │
├─────────────────────────────────────────┤
│     Dependency Check & Build           │
│   (OpenFHE + liboqs via CMake)         │
├─────────────────────────────────────────┤
│        C++ Wrapper Build               │
│     (openfhe_wrapper.cpp)              │
├─────────────────────────────────────────┤
│         Zig Library Build              │
│    (Static + Shared + FFI)             │
├─────────────────────────────────────────┤
│        Final Artifacts                 │
│  (CLI, Libraries, Python FFI)          │
└─────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Enhanced build.zig

#### 1.1 Dependency Detection and Building

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Check for dependencies and build if needed
    const deps_step = b.step("deps", "Build C++ dependencies (OpenFHE + liboqs)");
    const build_deps_cmd = b.addSystemCommand(&.{
        "just", "build-all"
    });
    deps_step.dependOn(&build_deps_cmd.step);

    // Define paths
    const build_dir = b.path("build");
    const lib_dir = build_dir.path(b, "lib");
    const include_dir = build_dir.path(b, "include");

    // Check if dependencies exist
    const deps_exist = checkDependencies(b, lib_dir);
    if (!deps_exist) {
        std.log.warn("Dependencies not found. Run 'zig build deps' first or 'just build-all'");
    }

    // ... rest of build configuration
}

fn checkDependencies(b: *std.Build, lib_dir: []const u8) bool {
    const required_libs = [_][]const u8{
        "libOPENFHEcore.dylib",
        "libOPENFHEpke.dylib", 
        "libOPENFHEbinfhe.dylib",
        "liboqs.dylib",
    };
    
    for (required_libs) |lib| {
        const lib_path = b.fmt("{s}/{s}", .{lib_dir, lib});
        const file = std.fs.cwd().openFile(lib_path, .{}) catch return false;
        file.close();
    }
    return true;
}
```

#### 1.2 Multi-Target Build Configuration

```zig
// Create multiple build targets
const BuildTargets = struct {
    ffi_lib: *std.Build.Step.Compile,      // Shared lib for Python
    zig_lib: *std.Build.Step.Compile,      // Static lib for Zig
    cli_exe: *std.Build.Step.Compile,      // CLI executable
    test_exe: *std.Build.Step.Compile,     // Test executable
};

fn createBuildTargets(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) BuildTargets {
    // FFI Shared Library (for Python)
    const ffi_lib = b.addSharedLibrary(.{
        .name = "dcypher_ffi",
        .target = target,
        .optimize = optimize,
    });
    
    // Configure C++ compilation
    configureCppBuild(b, ffi_lib);
    
    // Zig Static Library
    const zig_lib = b.addStaticLibrary(.{
        .name = "dcypher",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // CLI Executable
    const cli_exe = b.addExecutable(.{
        .name = "dcypher",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Test Executable
    const test_exe = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    return BuildTargets{
        .ffi_lib = ffi_lib,
        .zig_lib = zig_lib,
        .cli_exe = cli_exe,
        .test_exe = test_exe,
    };
}
```

#### 1.3 Cross-Platform Library Linking

```zig
fn configureCppBuild(b: *std.Build, compile: *std.Build.Step.Compile) void {
    const target_os = compile.rootModuleTarget().os.tag;
    
    // Add C++ sources
    compile.addCSourceFiles(.{
        .files = &.{
            "src/wrapper/openfhe_wrapper.cpp",
            "src/ffi/dcypher_ffi.cpp",
        },
        .flags = &.{
            "-std=c++17",
            "-fPIC",
            "-DOPENFHE_VERSION=1.3.0",
            "-DMATHBACKEND=4",
            "-Wall",
            "-Wextra",
        },
    });

    // Add include paths
    compile.addIncludePath(b.path("build/include"));
    compile.addIncludePath(b.path("src/wrapper"));
    compile.addIncludePath(b.path("src/ffi"));

    // Add library paths
    compile.addLibraryPath(b.path("build/lib"));

    // Link OpenFHE libraries
    compile.linkSystemLibrary("OPENFHEcore");
    compile.linkSystemLibrary("OPENFHEpke");
    compile.linkSystemLibrary("OPENFHEbinfhe");
    compile.linkSystemLibrary("oqs");

    // Platform-specific configuration
    switch (target_os) {
        .macos => {
            compile.linkFramework("Security");
            compile.linkSystemLibrary("omp");
            // Set rpath for dylib loading
            compile.addRPath(b.path("build/lib"));
        },
        .linux => {
            compile.linkSystemLibrary("gomp");
            compile.linkSystemLibrary("pthread");
            compile.linkSystemLibrary("dl");
            // Set rpath for .so loading
            compile.addRPath(b.path("build/lib"));
        },
        .windows => {
            // Windows-specific configuration
            compile.linkSystemLibrary("ws2_32");
            compile.linkSystemLibrary("advapi32");
        },
        else => {},
    }

    compile.linkLibCpp();
}
```

### Phase 2: Build Steps and Commands

#### 2.1 Comprehensive Build Steps

```zig
pub fn build(b: *std.Build) void {
    // ... target and optimize setup ...

    const targets = createBuildTargets(b, target, optimize);

    // Install artifacts
    b.installArtifact(targets.ffi_lib);
    b.installArtifact(targets.zig_lib);
    b.installArtifact(targets.cli_exe);

    // Create build steps
    const deps_step = b.step("deps", "Build C++ dependencies");
    const build_deps_cmd = b.addSystemCommand(&.{"just", "build-all"});
    deps_step.dependOn(&build_deps_cmd.step);

    const lib_step = b.step("lib", "Build libraries only");
    lib_step.dependOn(&targets.ffi_lib.step);
    lib_step.dependOn(&targets.zig_lib.step);

    const cli_step = b.step("cli", "Build CLI executable");
    cli_step.dependOn(&targets.cli_exe.step);

    const test_step = b.step("test", "Run tests");
    const run_tests = b.addRunArtifact(targets.test_exe);
    test_step.dependOn(&run_tests.step);

    const all_step = b.step("all", "Build everything");
    all_step.dependOn(lib_step);
    all_step.dependOn(cli_step);

    // Run step for CLI
    const run_cmd = b.addRunArtifact(targets.cli_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the CLI");
    run_step.dependOn(&run_cmd.step);

    // Clean step
    const clean_step = b.step("clean", "Clean build artifacts");
    const clean_cmd = b.addSystemCommand(&.{
        "rm", "-rf", "zig-out", ".zig-cache"
    });
    clean_step.dependOn(&clean_cmd.step);

    // Full clean (including C++ deps)
    const clean_all_step = b.step("clean-all", "Clean everything including dependencies");
    const clean_all_cmd = b.addSystemCommand(&.{"just", "clean"});
    clean_all_step.dependOn(clean_step);
    clean_all_step.dependOn(&clean_all_cmd.step);
}
```

#### 2.2 Development Workflow Commands

```zig
// Add development-focused build steps
const dev_step = b.step("dev", "Development build with debug info");
const dev_targets = createBuildTargets(b, target, .Debug);
// Configure dev_targets...

const check_step = b.step("check", "Check code without building");
const check_cmd = b.addSystemCommand(&.{"zig", "fmt", "--check", "src/"});
check_step.dependOn(&check_cmd.step);

const fmt_step = b.step("fmt", "Format code");
const fmt_cmd = b.addSystemCommand(&.{"zig", "fmt", "src/"});
fmt_step.dependOn(&fmt_cmd.step);
```

### Phase 3: Integration with Justfile

#### 3.1 Update Justfile to Use Zig Build

```just
# Build everything using Zig build system
build:
    zig build all

# Build dependencies only
build-deps:
    zig build deps

# Build and run CLI
run *args:
    zig build run -- {{args}}

# Development build
dev:
    zig build dev

# Run tests
test:
    zig build test

# Clean everything
clean:
    zig build clean-all

# Format code
fmt:
    zig build fmt

# Check code
check:
    zig build check
```

#### 3.2 Maintain Existing Commands for Compatibility

```just
# Legacy commands (for compatibility)
build-openfhe:
    # ... existing implementation ...

build-liboqs:
    # ... existing implementation ...

build-all: build-openfhe build-liboqs
```

### Phase 4: File Structure Reorganization

#### 4.1 Proposed Structure

```
src/
├── ffi/
│   ├── dcypher_ffi.h          # C API header
│   ├── dcypher_ffi.cpp        # C API implementation  
│   └── dcypher_ffi.zig        # Zig FFI wrapper
├── wrapper/
│   ├── openfhe_wrapper.h      # Move from root
│   └── openfhe_wrapper.cpp    # Move from root
├── crypto.zig                 # Enhanced with real implementations
├── main.zig                   # CLI application
├── root.zig                   # Library root
├── server.zig                 # HTTP server
├── cli.zig                    # CLI utilities
└── tests.zig                  # Test suite
```

#### 4.2 Migration Steps

1. **Move existing files**:
   ```bash
   mkdir -p src/wrapper src/ffi
   mv openfhe_wrapper.h src/wrapper/
   mv openfhe_wrapper.cpp src/wrapper/
   ```

2. **Update imports** in Zig files to reflect new structure

3. **Remove build_openfhe.zig** (functionality moved to main build.zig)

### Phase 5: Implementation Checklist

#### Week 1: Foundation
- [ ] **Restructure source files** into new layout
- [ ] **Create enhanced build.zig** with dependency detection
- [ ] **Test basic compilation** with existing libraries
- [ ] **Update Justfile** to use Zig build commands

#### Week 2: Build System Features
- [ ] **Implement multi-target builds** (FFI, static, CLI)
- [ ] **Add cross-platform library linking**
- [ ] **Create comprehensive build steps**
- [ ] **Test on multiple platforms**

#### Week 3: Integration and Testing
- [ ] **Integrate with existing Python code**
- [ ] **Create C FFI implementation**
- [ ] **Add comprehensive testing**
- [ ] **Performance benchmarking**

#### Week 4: Polish and Documentation
- [ ] **Documentation updates**
- [ ] **Error handling improvements**
- [ ] **CI/CD integration**
- [ ] **Release preparation**

## Benefits of This Approach

### For Development
- **Single command**: `zig build` does everything
- **Clear dependencies**: Build system manages the dependency chain
- **Cross-platform**: Zig handles platform differences
- **Fast iteration**: Incremental builds and caching

### For Deployment
- **Simplified builds**: One build system to understand
- **Better artifacts**: Proper shared libraries for Python FFI
- **Clear versioning**: All artifacts built together
- **Reproducible builds**: Consistent across environments

### For Maintenance
- **Less complexity**: Fewer build files to maintain
- **Better error messages**: Zig provides clear build errors
- **Integrated testing**: Tests built into the build system
- **Documentation**: Build steps are self-documenting

## Migration Strategy

### Phase 1: Immediate (This Week)
1. **Create new build.zig** with dependency detection
2. **Test with existing libraries** in build/ directory
3. **Update Justfile** to use zig build commands
4. **Verify all existing functionality works**

### Phase 2: Enhancement (Next Week)
1. **Add C FFI implementation**
2. **Create Python wrapper**
3. **Implement real crypto operations**
4. **Add comprehensive testing**

This approach gives us the best of both worlds: robust CMake builds for complex C++ dependencies, and a clean, integrated Zig build system for our own code.