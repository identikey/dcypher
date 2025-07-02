const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Check for dependencies and build if needed
    const deps_step = b.step("deps", "Build C++ dependencies (OpenFHE + liboqs)");
    const build_deps_cmd = b.addSystemCommand(&.{"just", "build-all"});
    deps_step.dependOn(&build_deps_cmd.step);

    // Define paths
    const build_dir = b.path("build");
    const lib_dir = build_dir.path(b, "lib");
    const include_dir = build_dir.path(b, "include");

    // Check if dependencies exist
    const deps_exist = checkDependencies(b, lib_dir);
    if (!deps_exist) {
        std.log.warn("Dependencies not found. Run 'zig build deps' first or 'just build-all'", .{});
    }

    // Create build targets
    const targets = createBuildTargets(b, target, optimize, include_dir, lib_dir);

    // Install artifacts
    b.installArtifact(targets.ffi_lib);
    b.installArtifact(targets.zig_lib);
    b.installArtifact(targets.cli_exe);

    // Create build steps
    const lib_step = b.step("lib", "Build libraries only");
    lib_step.dependOn(&targets.ffi_lib.step);
    lib_step.dependOn(&targets.zig_lib.step);

    const cli_step = b.step("cli", "Build CLI executable");
    cli_step.dependOn(&targets.cli_exe.step);

    // Add OpenFHE test
    const test_openfhe = b.addExecutable(.{
        .name = "test_openfhe",
        .root_source_file = b.path("src/test_openfhe.zig"),
        .target = target,
        .optimize = optimize,
    });
    configureCppBuild(b, test_openfhe, include_dir, lib_dir);
    const test_openfhe_step = b.step("test-openfhe", "Run OpenFHE test");
    const run_test = b.addRunArtifact(test_openfhe);
    test_openfhe_step.dependOn(&run_test.step);

    // Add test for unified C FFI API
    const test_dcypher_ffi = b.addExecutable(.{
        .name = "test_dcypher_ffi",
        .root_source_file = b.path("src/test_dcypher_ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    configureCppBuild(b, test_dcypher_ffi, include_dir, lib_dir);
    const test_dcypher_ffi_step = b.step("test-dcypher-ffi", "Run unified C FFI API test");
    const run_ffi_test = b.addRunArtifact(test_dcypher_ffi);
    test_dcypher_ffi_step.dependOn(&run_ffi_test.step);

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
    const clean_cmd = b.addSystemCommand(&.{"rm", "-rf", "zig-out", ".zig-cache"});
    clean_step.dependOn(&clean_cmd.step);

    // Full clean (including C++ deps)
    const clean_all_step = b.step("clean-all", "Clean everything including dependencies");
    const clean_all_cmd = b.addSystemCommand(&.{"just", "clean"});
    clean_all_step.dependOn(clean_step);
    clean_all_step.dependOn(&clean_all_cmd.step);

    // Development workflow commands
    const check_step = b.step("check", "Check code without building");
    const check_cmd = b.addSystemCommand(&.{"zig", "fmt", "--check", "src/"});
    check_step.dependOn(&check_cmd.step);

    const fmt_step = b.step("fmt", "Format code");
    const fmt_cmd = b.addSystemCommand(&.{"zig", "fmt", "src/"});
    fmt_step.dependOn(&fmt_cmd.step);
}

// Build targets structure
const BuildTargets = struct {
    ffi_lib: *std.Build.Step.Compile,      // Shared lib for Python
    zig_lib: *std.Build.Step.Compile,      // Static lib for Zig
    cli_exe: *std.Build.Step.Compile,      // CLI executable
    test_exe: *std.Build.Step.Compile,     // Test executable
};

fn createBuildTargets(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, include_dir: std.Build.LazyPath, lib_dir: std.Build.LazyPath) BuildTargets {
    // Create library module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // FFI Shared Library (for Python)
    const ffi_lib = b.addSharedLibrary(.{
        .name = "dcypher_ffi",
        .target = target,
        .optimize = optimize,
    });
    
    // Configure C++ compilation for FFI library
    configureCppBuild(b, ffi_lib, include_dir, lib_dir);
    
    // Zig Static Library
    const zig_lib = b.addStaticLibrary(.{
        .name = "dcypher",
        .root_module = lib_mod,
    });
    
    // CLI Executable
    const cli_exe = b.addExecutable(.{
        .name = "dcypher",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Add library module import to CLI
    cli_exe.root_module.addImport("dcypher", lib_mod);
    
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

fn configureCppBuild(b: *std.Build, compile: *std.Build.Step.Compile, include_dir: std.Build.LazyPath, lib_dir: std.Build.LazyPath) void {
    const target_os = compile.rootModuleTarget().os.tag;
    
    // C++ source files for OpenFHE
    compile.addCSourceFile(.{
        .file = b.path("src/wrapper/openfhe_wrapper.cpp"),
        .flags = &[_][]const u8{
            "-std=c++17",
            "-fPIC",
            "-DOPENFHE_VERSION=1.3.0",
            "-DMATHBACKEND=4",
            "-Wall",
            "-Wextra",
        },
    });
    
    // Add unified C FFI API implementation
    compile.addCSourceFile(.{
        .file = b.path("src/ffi/dcypher_ffi.cpp"),
        .flags = &[_][]const u8{
            "-std=c++17",
            "-fPIC",
            "-DOPENFHE_VERSION=1.3.0",
            "-DMATHBACKEND=4",
            "-Wall",
            "-Wextra",
        },
    });

    // Add include paths for OpenFHE and wrapper
    compile.addIncludePath(include_dir);
    compile.addIncludePath(b.path("src/wrapper"));
    compile.addIncludePath(b.path("src/ffi"));
    
    // Add OpenFHE-specific include paths for static linking
    compile.addIncludePath(b.path("build/include/openfhe/core"));
    compile.addIncludePath(b.path("build/include/openfhe/pke"));
    compile.addIncludePath(b.path("build/include/openfhe/binfhe"));
    // Add base openfhe path so cereal/cereal.hpp can be found
    compile.addIncludePath(b.path("build/include/openfhe"));

    // Add library paths
    compile.addLibraryPath(lib_dir);

    // Link OpenFHE libraries
    compile.linkSystemLibrary("OPENFHEcore");
    compile.linkSystemLibrary("OPENFHEpke");
    compile.linkSystemLibrary("OPENFHEbinfhe");
    compile.linkSystemLibrary("oqs");

    // Note: OpenMP disabled for static linking - will use Zig native threading or static OpenMP later
    // compile.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    // compile.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    // compile.linkSystemLibrary("omp");
    // compile.addRPath(.{ .cwd_relative = "/opt/homebrew/lib" });

    // Platform-specific configuration
    switch (target_os) {
        .macos => {
            compile.linkFramework("Security");
            // Set rpath for dylib loading
            compile.addRPath(lib_dir);
        },
        .linux => {
            compile.linkSystemLibrary("gomp");
            compile.linkSystemLibrary("pthread");
            compile.linkSystemLibrary("dl");
            // Set rpath for .so loading
            compile.addRPath(lib_dir);
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

fn checkDependencies(b: *std.Build, lib_dir: std.Build.LazyPath) bool {
    _ = b; // suppress unused parameter warning
    _ = lib_dir; // For now, assume dependencies exist
    // TODO: Implement actual dependency checking
    return true;
}
