use std::env;
use std::path::PathBuf;

fn main() {
    // Determine the directory where Cargo is executing the build
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root_dir = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
    
    // The FFI wrapper needs the dynamically linked libpqc_crypto.so
    let obj_dir = root_dir.join("obj");

    // Instruct Cargo to add the obj/ folder to the native library search path
    println!("cargo:rustc-link-search=native={}", obj_dir.display());

    // Instruct Cargo to link the open-core libpqc_crypto.so
    println!("cargo:rustc-link-lib=dylib=pqc_crypto");

    // Instruct Cargo to link system OpenSSL (EVP_PKEY dependencies)
    println!("cargo:rustc-link-lib=dylib=crypto");
}
