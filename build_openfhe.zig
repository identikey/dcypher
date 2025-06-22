const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the OpenFHE wrapper library
    const openfhe_wrapper = b.addSharedLibrary(.{
        .name = "openfhe_wrapper",
        .target = target,
        .optimize = optimize,
    });

    // Add C++ source files
    openfhe_wrapper.addCSourceFile(.{
        .file = b.path("openfhe_wrapper.cpp"),
        .flags = &.{ 
            "-std=c++17", 
            "-fPIC",
            "-I../openfhe-development/src/pke/include",
            "-I../openfhe-development/src/core/include", 
            "-I../openfhe-development/src/binfhe/include"
        },
    });

    // Link OpenFHE libraries
    openfhe_wrapper.addLibraryPath(b.path("../include"));
    openfhe_wrapper.linkSystemLibrary("OPENFHEpke");
    openfhe_wrapper.linkSystemLibrary("OPENFHEcore");
    openfhe_wrapper.linkSystemLibrary("OPENFHEbinfhe");

    // Link C++ standard library
    openfhe_wrapper.linkLibCpp();

    // Install the wrapper library
    b.installArtifact(openfhe_wrapper);

    // Create the main Zig executable that uses OpenFHE
    const exe = b.addExecutable(.{
        .name = "openfhe_zig_example",
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add include path for our wrapper header
    exe.addIncludePath(b.path("."));
    
    // Link our wrapper library
    exe.linkLibrary(openfhe_wrapper);
    
    // Add library paths for OpenFHE
    exe.addLibraryPath(b.path("../include"));
    exe.linkSystemLibrary("OPENFHEpke");
    exe.linkSystemLibrary("OPENFHEcore");
    exe.linkSystemLibrary("OPENFHEbinfhe");
    
    // Link C++ standard library
    exe.linkLibCpp();

    // Install the executable
    b.installArtifact(exe);

    // Create run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the OpenFHE Zig example");
    run_step.dependOn(&run_cmd.step);
}
