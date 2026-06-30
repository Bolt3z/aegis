use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueHint};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "aegis", version, about = "Aegis — personal file/folder encryption")]
pub struct Cli {
    /// Force GUI dialogs for password prompts (kdialog or zenity).
    #[arg(long, global = true, conflicts_with = "no_gui")]
    pub gui: bool,
    /// Force terminal password prompts even when not running in a terminal.
    #[arg(long, global = true, conflicts_with = "gui")]
    pub no_gui: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Set the master password (stored in the system keyring).
    Init {
        /// Overwrite an existing master password without asking.
        #[arg(long)]
        force: bool,
    },
    /// Show whether a master password is currently stored.
    Status,
    /// Remove the master password from the system keyring.
    Forget,
    /// Encrypt a file or a directory.
    Encrypt {
        /// Path to encrypt (file or directory).
        #[arg(value_hint = ValueHint::AnyPath)]
        input: PathBuf,
        /// Output .bml path (default: <input>.bml).
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
        /// Ask for a custom password instead of using the stored master.
        #[arg(short = 'a', long)]
        ask: bool,
        /// Keep the original file/directory after encryption (default: remove after confirming).
        #[arg(short = 'k', long)]
        keep: bool,
        /// Combine the password with bytes from a keyfile (extra factor; you'll need it to decrypt).
        #[arg(short = 'K', long, value_hint = ValueHint::FilePath)]
        keyfile: Option<PathBuf>,
    },
    /// Decrypt a .bml file or directory archive.
    Decrypt {
        /// Encrypted .bml file.
        #[arg(value_hint = ValueHint::FilePath)]
        input: PathBuf,
        /// Output file or directory (default: <input> with .bml stripped).
        #[arg(short, long, value_hint = ValueHint::AnyPath)]
        output: Option<PathBuf>,
        /// Always prompt for the password, ignore any stored master.
        #[arg(short = 'a', long)]
        ask: bool,
        /// Keep the encrypted .bml after decryption (default: remove after confirming).
        #[arg(short = 'k', long)]
        keep: bool,
        /// Keyfile to combine with the password (required if the .bml header says so).
        #[arg(short = 'K', long, value_hint = ValueHint::FilePath)]
        keyfile: Option<PathBuf>,
    },
    /// Print header information for a .bml file (no password needed).
    Info {
        /// Encrypted .bml file.
        #[arg(value_hint = ValueHint::FilePath)]
        input: PathBuf,
    },
    /// Generate a random keyfile (64 bytes from /dev/urandom by default).
    KeyfileGen {
        /// Path where the keyfile will be written (must not already exist).
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: PathBuf,
        /// Keyfile size in bytes (default: 64).
        #[arg(short, long)]
        size: Option<usize>,
    },
    /// Print a shell completion script (bash, zsh, fish, …) to stdout.
    #[command(hide = true)]
    Completions {
        /// Target shell.
        shell: Shell,
    },
}
