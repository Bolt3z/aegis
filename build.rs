use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{generate_to, shells::*};

#[path = "src/cli.rs"]
mod cli;

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");

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
