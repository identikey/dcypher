use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(&["proto/dcypher.proto"], &["proto/"])?;

    println!("cargo:rerun-if-changed=proto/dcypher.proto");
    Ok(())
}
