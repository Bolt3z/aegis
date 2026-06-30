use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{generate_to, shells::*};

#[path = "src/cli.rs"]
mod cli;

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");

    // Make `aegis --version` report the git short hash, so builds are
    // distinguishable (the Cargo version stays 0.1.0 across many builds).
    // Falls back to the Cargo version when git isn't available.
    println!("cargo:rerun-if-changed=.git/HEAD");
    let stamp = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_default());
    println!("cargo:rustc-env=AEGIS_VERSION={stamp}");

    let outdir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"))
            .join("target")
            .join("completions");
    std::fs::create_dir_all(&outdir)?;

    let mut cmd = cli::Cli::command();
    generate_to(Bash, &mut cmd, "aegis", &outdir)?;
    generate_to(Zsh, &mut cmd, "aegis", &outdir)?;
    generate_to(Fish, &mut cmd, "aegis", &outdir)?;
    Ok(())
}
