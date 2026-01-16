use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(&["proto/recrypt.proto"], &["proto/"])?;

    println!("cargo:rerun-if-changed=proto/recrypt.proto");
    Ok(())
}
