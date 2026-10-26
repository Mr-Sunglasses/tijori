//! On macOS, compiles the C shim against macFUSE's libfuse 3 headers. The
//! shim loads libfuse3 at run time, so Tijori still starts (and opens vaults
//! in private mode) on Macs without macFUSE. Without the headers at build
//! time, the mount backend is left out and `mount` reports it unavailable.

use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tijori_macfuse)");
    println!("cargo::rerun-if-changed=src/macos_shim.c");
    println!("cargo::rerun-if-env-changed=TIJORI_FUSE3_PREFIX");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let prefix =
        PathBuf::from(std::env::var("TIJORI_FUSE3_PREFIX").unwrap_or_else(|_| "/usr/local".into()));
    let include = prefix.join("include/fuse3");
    if !include.join("fuse.h").is_file() {
        println!(
            "cargo::warning=macFUSE headers not found in {}; building without mount support",
            include.display()
        );
        return;
    }
    cc::Build::new()
        .file("src/macos_shim.c")
        .include(&include)
        .define("FUSE_USE_VERSION", "31")
        .define("FUSE_DARWIN_ENABLE_EXTENSIONS", "0")
        .flag(format!(
            "-mmacosx-version-min={}",
            std::env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".into())
        ))
        .warnings(true)
        .compile("tijori_macfuse_shim");
    println!("cargo::rustc-cfg=tijori_macfuse");
}
