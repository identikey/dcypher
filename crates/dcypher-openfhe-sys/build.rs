use std::env;
use std::path::PathBuf;

/// Link against OpenMP runtime (required when OpenFHE is built with OpenMP)
fn link_openmp() {
    #[cfg(target_os = "macos")]
    {
        // Homebrew libomp locations (Apple Silicon vs Intel)
        let omp_paths = ["/opt/homebrew/opt/libomp/lib", "/usr/local/opt/libomp/lib"];

        for path in &omp_paths {
            let lib_path = PathBuf::from(path);
            if lib_path.join("libomp.dylib").exists() {
                println!("cargo::rustc-link-search=native={path}");
                println!("cargo::rustc-link-lib=omp");
                return;
            }
        }

        // If libomp not found, OpenFHE was probably built without OpenMP
        // which is fine but suboptimal for concurrent operations
        eprintln!("cargo::warning=libomp not found; OpenFHE may have been built without OpenMP");
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, OpenMP is typically provided by libgomp (GCC) or libomp (LLVM)
        // The linker will find it in standard paths
        println!("cargo::rustc-link-lib=gomp");
    }
}

fn main() {
    // Find the OpenFHE install directory
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let openfhe_install = workspace_root.join("vendor/openfhe-install");

    let openfhe_include = openfhe_install.join("include/openfhe");
    let openfhe_lib = openfhe_install.join("lib");

    // Verify OpenFHE was built
    if !openfhe_lib.join("libOPENFHEpke_static.a").exists() {
        panic!(
            "OpenFHE static libraries not found at {openfhe_lib:?}. Run `just build-openfhe` first."
        );
    }

    // Build the cxx bridge
    cxx_build::bridge("src/lib.rs")
        .file("src/wrapper.cc")
        // OpenFHE includes
        .include(&openfhe_include)
        .include(openfhe_include.join("core"))
        .include(openfhe_include.join("pke"))
        .include(openfhe_include.join("binfhe"))
        .include(openfhe_include.join("core/include"))
        .include(openfhe_include.join("pke/include"))
        // Third-party includes (cereal, etc.)
        .include(openfhe_include.join("third-party/include"))
        // C++ standard
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-O2")
        // Suppress some OpenFHE warnings
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .compile("dcypher_openfhe_sys");

    // Link OpenFHE static libraries (order matters for static linking!)
    println!("cargo::rustc-link-search=native={}", openfhe_lib.display());
    println!("cargo::rustc-link-lib=static=OPENFHEpke_static");
    println!("cargo::rustc-link-lib=static=OPENFHEbinfhe_static");
    println!("cargo::rustc-link-lib=static=OPENFHEcore_static");

    // Link C++ standard library
    #[cfg(target_os = "macos")]
    println!("cargo::rustc-link-lib=c++");
    #[cfg(target_os = "linux")]
    println!("cargo::rustc-link-lib=stdc++");

    // Link OpenMP runtime (required when OpenFHE built with -DWITH_OPENMP=ON)
    link_openmp();

    // Rebuild if these change
    println!("cargo::rerun-if-changed=src/lib.rs");
    println!("cargo::rerun-if-changed=src/wrapper.h");
    println!("cargo::rerun-if-changed=src/wrapper.cc");
    println!("cargo::rerun-if-changed=build.rs");
}
