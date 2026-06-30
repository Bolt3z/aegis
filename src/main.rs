use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::generate;

use aegis::{
    FLAG_DIRECTORY, FLAG_KEYFILE, FLAG_MASTER_KEY, HEADER_LEN, Header, KdfParams, decrypt_dir,
    decrypt_file, encrypt_dir, encrypt_file, peek_header,
};

mod cli;
mod gui;
mod keychain;

use aegis::keyfile;

use cli::{Cli, Cmd};

fn resolve_gui_mode(force_gui: bool, force_no_gui: bool) -> bool {
    if force_gui {
        return true;
    }
    if force_no_gui {
        return false;
    }
    !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal())
}

fn default_encrypt_output(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or(Path::new(""));
    let name = input
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("output"));
    let mut new_name: OsString = name.into();
    new_name.push(".bml");
    if parent.as_os_str().is_empty() {
        PathBuf::from(new_name)
    } else {
        parent.join(new_name)
    }
}

fn default_decrypt_output(input: &Path) -> Result<PathBuf, String> {
    if input.extension().and_then(|s| s.to_str()) == Some("bml") {
        Ok(input.with_extension(""))
    } else {
        Err("input has no .bml extension; please pass --output".into())
    }
}

fn rp_password(prompt: &str) -> Result<String, String> {
    rpassword::prompt_password(prompt).map_err(|e| e.to_string())
}

fn ask_password_cli_with_confirm() -> Result<String, String> {
    let password = rp_password("Password: ")?;
    if password.is_empty() {
        return Err("password cannot be empty".into());
    }
    let confirm = rp_password("Confirm:  ")?;
    if password != confirm {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

fn ask_password_cli() -> Result<String, String> {
    let password = rp_password("Password: ")?;
    if password.is_empty() {
        return Err("password cannot be empty".into());
    }
    Ok(password)
}

fn cli_confirm_default_yes(prompt: &str) -> Result<bool, String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let s = line.trim().to_lowercase();
    Ok(s.is_empty() || s == "y" || s == "yes" || s == "s" || s == "si" || s == "sì")
}

fn dir_summary(path: &Path) -> (u64, u64) {
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in entries.flatten() {
            let child = entry.path();
            let Ok(md) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if md.is_dir() {
                stack.push(child);
            } else {
                files += 1;
                bytes += md.len();
            }
        }
    }
    (files, bytes)
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.1} {}", v, UNITS[i])
}

fn remove_input(input: &Path, is_dir: bool) -> Result<(), String> {
    if is_dir {
        std::fs::remove_dir_all(input).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(input).map_err(|e| e.to_string())
    }
}

/// Ask the user to confirm a destructive action. In gui_mode uses kdialog/zenity;
/// in CLI mode reads y/n from stdin. In true-headless gui_mode (no backend
/// available) returns Ok(true) — honoring the documented default.
fn confirm_destruction(gui_mode: bool, gui_body: &str, cli_prompt: &str) -> Result<bool, String> {
    if gui_mode {
        if gui::is_available() {
            gui::confirm("Aegis", gui_body)
        } else {
            Ok(true)
        }
    } else {
        cli_confirm_default_yes(cli_prompt)
    }
}

/// After a successful encrypt, decide whether to delete the plaintext input.
/// Returns Ok(true) if deleted, Ok(false) if kept. A "no" answer is not an error.
fn maybe_delete_after_encrypt(
    input: &Path,
    is_dir: bool,
    keep: bool,
    gui_mode: bool,
) -> Result<bool, String> {
    if keep {
        return Ok(false);
    }
    let (gui_body, cli_prompt) = if is_dir {
        let (files, bytes) = dir_summary(input);
        let plural = if files == 1 { "" } else { "s" };
        let size = human_bytes(bytes);
        (
            format!(
                "Delete the original directory?\n{}\n({files} file{plural}, {size})",
                input.display()
            ),
            format!(
                "Delete original directory {} ({files} file{plural}, {size})? [Y/n] ",
                input.display()
            ),
        )
    } else {
        (
            format!("Delete the original file?\n{}", input.display()),
            format!("Delete original {}? [Y/n] ", input.display()),
        )
    };
    if confirm_destruction(gui_mode, &gui_body, &cli_prompt)? {
        remove_input(input, is_dir)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// After a successful decrypt, decide whether to delete the encrypted .bml.
/// The encrypted input is always a single file (the .bml), even for directory
/// archives — the unpacked tree lives in the output path.
fn maybe_delete_after_decrypt(
    encrypted: &Path,
    keep: bool,
    gui_mode: bool,
) -> Result<bool, String> {
    if keep {
        return Ok(false);
    }
    let gui_body = format!("Delete the encrypted file?\n{}", encrypted.display());
    let cli_prompt = format!("Delete encrypted {}? [Y/n] ", encrypted.display());
    if confirm_destruction(gui_mode, &gui_body, &cli_prompt)? {
        remove_input(encrypted, false)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn do_encrypt(
    input: &Path,
    output: &Path,
    is_dir: bool,
    password: &[u8],
    extra_flags: u8,
) -> aegis::Result<()> {
    if is_dir {
        encrypt_dir(
            input,
            output,
            password,
            KdfParams::default_strong(),
            extra_flags,
        )
    } else {
        encrypt_file(
            input,
            output,
            password,
            KdfParams::default_strong(),
            extra_flags,
        )
    }
}

fn do_decrypt(input: &Path, output: &Path, is_dir: bool, password: &[u8]) -> aegis::Result<()> {
    if is_dir {
        decrypt_dir(input, output, password)
    } else {
        decrypt_file(input, output, password)
    }
}

// ---------- init / status / forget ----------

fn cmd_init(force: bool, gui_mode: bool) -> Result<(), String> {
    if !force {
        let already_set = keychain::is_set().map_err(|e| e.to_string())?;
        if already_set {
            return Err(
                "a master password is already stored; pass --force to overwrite, or run `aegis forget` first"
                    .into(),
            );
        }
    }
    let password = if gui_mode {
        match gui::password_new(
            "Aegis — Set master password",
            "Choose a master password.\nIt will be stored in your system keyring (kwallet) and used by default for `aegis encrypt`.",
        )? {
            Some(p) => p,
            None => return Err("cancelled by user".into()),
        }
    } else {
        eprintln!("Set the master password (stored in the system keyring).");
        ask_password_cli_with_confirm()?
    };
    keychain::set_master(&password).map_err(|e| e.to_string())?;
    let msg = format!(
        "Master password stored under service=\"{}\", account=\"{}\".",
        keychain::service(),
        keychain::account()
    );
    if gui_mode {
        gui::show_info(&msg);
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_status() -> Result<(), String> {
    match keychain::is_set() {
        Ok(true) => {
            println!("Master password: SET");
            println!("  service:  {}", keychain::service());
            println!("  account:  {}", keychain::account());
            println!("  backend:  system keyring (kwallet / libsecret)");
        }
        Ok(false) => {
            println!("Master password: NOT SET");
            println!("Run `aegis init` to create one.");
        }
        Err(e) => {
            return Err(format!(
                "could not query the system keyring: {e}\n(is kwalletd / a Secret Service provider running?)"
            ));
        }
    }
    Ok(())
}

fn cmd_forget(gui_mode: bool) -> Result<(), String> {
    let removed = keychain::forget_master().map_err(|e| e.to_string())?;
    let msg = if removed {
        "Master password removed from the keyring.".to_string()
    } else {
        "No master password was stored.".to_string()
    };
    if gui_mode {
        gui::show_info(&msg);
    } else {
        println!("{msg}");
    }
    Ok(())
}

// ---------- keyfile-gen ----------

fn cmd_keyfile_gen(
    output: PathBuf,
    size: Option<usize>,
    gui_mode: bool,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let size = size.unwrap_or(keyfile::DEFAULT_SIZE);
    if size == 0 || size > 1024 * 1024 {
        return Err(format!(
            "keyfile size must be between 1 and 1048576 bytes (got {size})"
        ));
    }
    if output.exists() {
        let msg = format!(
            "refusing to overwrite existing path: {}",
            output.display()
        );
        if gui_mode {
            gui::show_error(&msg);
        }
        return Err(msg);
    }
    let mut bytes = vec![0u8; size];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom failed: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&output)
        .map_err(|e| format!("cannot create keyfile: {e}"))?;
    file.write_all(&bytes)
        .map_err(|e| format!("cannot write keyfile: {e}"))?;
    file.sync_all().ok();
    // Best effort to zero our in-memory copy.
    for b in bytes.iter_mut() {
        *b = 0;
    }
    let msg = format!(
        "Keyfile created: {} ({} bytes, mode 0600).\n\
         Keep it safe — losing it means losing access to files encrypted with it.",
        output.display(),
        size
    );
    if gui_mode {
        gui::show_info(&msg);
    } else {
        println!("{msg}");
    }
    Ok(())
}

// ---------- encrypt ----------

/// Decide (effective_ask, effective_keyfile) given CLI flags and GUI menus.
/// CLI flags (--ask, --keyfile) always win; GUI fills in anything left to decide.
fn decide_encrypt_options(
    gui_mode: bool,
    ask: bool,
    keyfile_cli: Option<PathBuf>,
    kind: &str,
    input_display: &str,
) -> Result<(bool, Option<PathBuf>), String> {
    if !gui_mode {
        return Ok((ask, keyfile_cli));
    }

    let master_set = keychain::is_set().unwrap_or(false);
    let pwd_decided = ask || !master_set; // !master_set forces custom anyway
    let keyfile_decided = keyfile_cli.is_some();

    // Fast path: both already decided.
    if pwd_decided && keyfile_decided {
        return Ok((true, keyfile_cli));
    }

    if pwd_decided {
        // Only ask about keyfile.
        let body = format!(
            "Should this {kind} also require a keyfile (extra factor)?\n{input_display}"
        );
        if gui::confirm("Aegis — Keyfile?", &body)? {
            match gui::pick_file("Aegis — Pick keyfile", keyfile_start_dir().as_str())? {
                Some(p) => Ok((true, Some(p))),
                None => Err("cancelled by user (keyfile not chosen)".into()),
            }
        } else {
            Ok((true, keyfile_cli))
        }
    } else if keyfile_decided {
        // Only ask master vs custom.
        let body = format!("How do you want to encrypt this {kind}?\n{input_display}");
        let items: &[(&str, &str, bool)] = &[
            (
                "master",
                "Your master password (from the keyring)",
                true,
            ),
            (
                "custom",
                "A custom password (one-off, for sharing)",
                false,
            ),
        ];
        match gui::choose_radio("Aegis — Encrypt", &body, items)? {
            Some(s) if s == "custom" => Ok((true, keyfile_cli)),
            Some(_) => Ok((false, keyfile_cli)),
            None => Err("cancelled by user".into()),
        }
    } else {
        // Full 4-option menu.
        let body = format!("How do you want to encrypt this {kind}?\n{input_display}");
        let items: &[(&str, &str, bool)] = &[
            (
                "master",
                "Your master password (from the keyring)",
                true,
            ),
            (
                "master_kf",
                "Master password + a keyfile (extra factor)",
                false,
            ),
            (
                "custom",
                "A custom password (one-off, for sharing)",
                false,
            ),
            (
                "custom_kf",
                "Custom password + a keyfile (extra factor)",
                false,
            ),
        ];
        let choice = match gui::choose_radio("Aegis — Encrypt", &body, items)? {
            Some(s) => s,
            None => return Err("cancelled by user".into()),
        };
        let needs_keyfile = choice.ends_with("_kf");
        let use_ask = choice.starts_with("custom");
        let kf = if needs_keyfile {
            match gui::pick_file("Aegis — Pick keyfile", keyfile_start_dir().as_str())? {
                Some(p) => Some(p),
                None => return Err("cancelled by user (keyfile not chosen)".into()),
            }
        } else {
            None
        };
        Ok((use_ask, kf))
    }
}

fn keyfile_start_dir() -> String {
    // USB mount points: /media on Linux, /Volumes on macOS. Fall back to $HOME.
    #[cfg(target_os = "linux")]
    let usb_root = "/media";
    #[cfg(target_os = "macos")]
    let usb_root = "/Volumes";
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let usb_root = "/";

    if Path::new(usb_root).is_dir() {
        usb_root.to_string()
    } else if let Ok(home) = std::env::var("HOME") {
        home
    } else {
        "/".to_string()
    }
}

fn cmd_encrypt(
    input: PathBuf,
    output: Option<PathBuf>,
    ask: bool,
    keep: bool,
    keyfile: Option<PathBuf>,
    gui_mode: bool,
) -> Result<(), String> {
    if !input.exists() {
        return Err(format!("input does not exist: {}", input.display()));
    }
    let is_dir = input.is_dir();
    let output = output.unwrap_or_else(|| default_encrypt_output(&input));
    if output.exists() {
        let msg = format!("output already exists: {}", output.display());
        if gui_mode {
            gui::show_error(&msg);
        }
        return Err(msg);
    }

    let kind = if is_dir { "directory" } else { "file" };

    // Decide pwd source (master/custom) and whether to use a keyfile.
    // CLI flags (--ask, --keyfile) win in any mode. GUI mode fills in
    // anything not pre-decided via menus.
    let (effective_ask, effective_keyfile) =
        decide_encrypt_options(gui_mode, ask, keyfile, kind, &input.display().to_string())?;

    // Decide password source.
    let (password, master_flag) = if effective_ask {
        let pwd = if gui_mode {
            let title = "Aegis — Encrypt (custom password)";
            let body = format!(
                "Encrypting {kind}:\n{}\n\nChoose a password (NOT the master):",
                input.display()
            );
            match gui::password_new(title, &body)? {
                Some(p) => p,
                None => return Err("cancelled by user".into()),
            }
        } else {
            eprintln!("Encrypting {kind}: {} (custom password)", input.display());
            ask_password_cli_with_confirm()?
        };
        (pwd, 0u8)
    } else {
        // Use master from keyring.
        let master = match keychain::get_master() {
            Ok(Some(p)) => p,
            Ok(None) => {
                let msg = "no master password set; run `aegis init`, or pass --ask".to_string();
                if gui_mode {
                    gui::show_error(&msg);
                }
                return Err(msg);
            }
            Err(e) => {
                let msg = format!("{e}");
                if gui_mode {
                    gui::show_error(&msg);
                }
                return Err(msg);
            }
        };
        if !gui_mode {
            eprintln!("Encrypting {kind}: {} (master)", input.display());
        }
        (master, FLAG_MASTER_KEY)
    };

    // Read keyfile digest if a keyfile was selected.
    let keyfile_digest = match effective_keyfile.as_ref() {
        Some(p) => {
            if !gui_mode {
                eprintln!("Hashing keyfile: {}", p.display());
            }
            match keyfile::digest_file(p) {
                Ok(d) => Some(d),
                Err(e) => {
                    if gui_mode {
                        gui::show_error(&e);
                    }
                    return Err(e);
                }
            }
        }
        None => None,
    };
    let keyfile_flag = if effective_keyfile.is_some() {
        FLAG_KEYFILE
    } else {
        0
    };
    let extra_flags = master_flag | keyfile_flag;
    let combined = keyfile::combine(password.as_bytes(), keyfile_digest.as_ref());

    if !gui_mode {
        eprintln!("Deriving key with Argon2id (~1s)…");
    }
    match do_encrypt(&input, &output, is_dir, &combined, extra_flags) {
        Ok(()) => {
            let deleted = match maybe_delete_after_encrypt(&input, is_dir, keep, gui_mode) {
                Ok(d) => d,
                Err(e) => {
                    // Encrypt succeeded but delete failed — surface the error
                    // without claiming the original is gone.
                    let msg = format!(
                        "Encrypted: {}\nFailed to remove original: {e}",
                        output.display()
                    );
                    if gui_mode {
                        gui::show_error(&msg);
                    }
                    return Err(msg);
                }
            };
            let tail = if deleted {
                " (original removed)"
            } else if keep {
                " (original kept)"
            } else {
                " (original kept on user request)"
            };
            if gui_mode {
                gui::show_info(&format!("Encrypted:\n{}{}", output.display(), tail));
            } else {
                println!("Encrypted: {}{}", output.display(), tail);
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if gui_mode {
                gui::show_error(&format!("Encryption failed:\n{msg}"));
            }
            Err(msg)
        }
    }
}

// ---------- decrypt ----------

fn cmd_decrypt(
    input: PathBuf,
    output: Option<PathBuf>,
    ask: bool,
    keep: bool,
    keyfile: Option<PathBuf>,
    gui_mode: bool,
) -> Result<(), String> {
    if !input.exists() {
        let msg = format!("input does not exist: {}", input.display());
        if gui_mode {
            gui::show_error(&msg);
        }
        return Err(msg);
    }
    let header = peek_header(&input).map_err(|e| e.to_string())?;
    let is_dir = header.flags & FLAG_DIRECTORY != 0;
    let was_master = header.flags & FLAG_MASTER_KEY != 0;
    let needs_keyfile = header.flags & FLAG_KEYFILE != 0;

    // Enforce the keyfile mismatch matrix explicitly.
    if !needs_keyfile && keyfile.is_some() {
        let msg = "this file was not encrypted with a keyfile — remove --keyfile".to_string();
        if gui_mode {
            gui::show_error(&msg);
        }
        return Err(msg);
    }

    let output = match output {
        Some(p) => p,
        None => default_decrypt_output(&input).map_err(|e| {
            if gui_mode {
                gui::show_error(&e);
            }
            e
        })?,
    };

    // Obtain the keyfile path: from CLI flag, or via picker in GUI mode, or
    // error out in CLI mode.
    let keyfile_path = if needs_keyfile {
        if let Some(p) = keyfile {
            Some(p)
        } else if gui_mode {
            gui::show_info(
                "This file was encrypted with a keyfile.\nPlease select the keyfile to use for decryption.",
            );
            match gui::pick_file("Aegis — Pick keyfile", keyfile_start_dir().as_str())? {
                Some(p) => Some(p),
                None => return Err("cancelled by user (keyfile not chosen)".into()),
            }
        } else {
            let msg = "this file requires --keyfile to decrypt".to_string();
            return Err(msg);
        }
    } else {
        None
    };

    // Hash the keyfile once. Used by every decrypt attempt below.
    let keyfile_digest = match keyfile_path.as_ref() {
        Some(p) => {
            if !gui_mode {
                eprintln!("Hashing keyfile: {}", p.display());
            }
            match keyfile::digest_file(p) {
                Ok(d) => Some(d),
                Err(e) => {
                    if gui_mode {
                        gui::show_error(&e);
                    }
                    return Err(e);
                }
            }
        }
        None => None,
    };
    let digest_ref = keyfile_digest.as_ref();

    // Strategy:
    // 1. If --ask: skip master, prompt directly.
    // 2. Else if header says master: try keyring; on failure fall back to prompt.
    // 3. Else: prompt directly.
    let mut decrypted_via_master = false;
    if !ask && was_master {
        match keychain::get_master() {
            Ok(Some(master)) => {
                let combined = keyfile::combine(master.as_bytes(), digest_ref);
                match do_decrypt(&input, &output, is_dir, &combined) {
                    Ok(()) => {
                        decrypted_via_master = true;
                    }
                    Err(aegis::Error::Aead) => {
                        if !gui_mode {
                            eprintln!(
                                "Stored master did not decrypt this file; falling back to prompt."
                            );
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if gui_mode {
                            gui::show_error(&format!("Decryption failed:\n{msg}"));
                        }
                        return Err(msg);
                    }
                }
            }
            Ok(None) => {
                if !gui_mode {
                    eprintln!("File was encrypted with master, but no master is stored.");
                }
            }
            Err(e) => {
                if !gui_mode {
                    eprintln!("Keyring unavailable: {e}");
                }
            }
        }
    }

    if !decrypted_via_master {
        // Prompt-based decryption (GUI = up to 3 attempts, CLI = single attempt).
        if gui_mode {
            decrypt_gui_prompt(&input, &output, is_dir, was_master, digest_ref)?;
        } else {
            decrypt_cli_prompt(&input, &output, is_dir, was_master, digest_ref)?;
        }
    }

    finish_decrypt(&input, &output, keep, gui_mode)
}

fn finish_decrypt(
    encrypted: &Path,
    output: &Path,
    keep: bool,
    gui_mode: bool,
) -> Result<(), String> {
    let deleted = match maybe_delete_after_decrypt(encrypted, keep, gui_mode) {
        Ok(d) => d,
        Err(e) => {
            let msg = format!(
                "Decrypted: {}\nFailed to remove encrypted file: {e}",
                output.display()
            );
            if gui_mode {
                gui::show_error(&msg);
            }
            return Err(msg);
        }
    };
    let tail = if deleted {
        " (encrypted file removed)"
    } else if keep {
        " (encrypted file kept)"
    } else {
        " (encrypted file kept on user request)"
    };
    if gui_mode {
        gui::show_info(&format!("Decrypted:\n{}{}", output.display(), tail));
    } else {
        println!("Decrypted: {}{}", output.display(), tail);
    }
    Ok(())
}

fn decrypt_cli_prompt(
    input: &Path,
    output: &Path,
    is_dir: bool,
    was_master: bool,
    keyfile_digest: Option<&[u8; keyfile::DIGEST_LEN]>,
) -> Result<(), String> {
    let kind = if is_dir { "directory" } else { "file" };
    eprintln!("Decrypting {kind}: {}", input.display());
    if was_master {
        eprintln!(
            "(this file was encrypted with the sender's MASTER password — your\n local keyring doesn't have one that decrypts it)"
        );
    }
    let password = ask_password_cli()?;
    let combined = keyfile::combine(password.as_bytes(), keyfile_digest);
    eprintln!("Deriving key with Argon2id (~1s)…");
    do_decrypt(input, output, is_dir, &combined).map_err(|e| e.to_string())?;
    Ok(())
}

fn decrypt_gui_prompt(
    input: &Path,
    output: &Path,
    is_dir: bool,
    was_master: bool,
    keyfile_digest: Option<&[u8; keyfile::DIGEST_LEN]>,
) -> Result<(), String> {
    const MAX_ATTEMPTS: u32 = 3;
    let title = "Aegis — Decrypt";

    for attempt in 0..MAX_ATTEMPTS {
        let body = if attempt == 0 {
            if was_master {
                format!(
                    "This file was encrypted with the sender's MASTER password.\nYour local keyring doesn't have a master that decrypts it.\n\nEnter the sender's master password:\n{}",
                    input.display()
                )
            } else {
                format!("Decrypting:\n{}\n\nEnter the password:", input.display())
            }
        } else {
            let remaining = MAX_ATTEMPTS - attempt;
            format!(
                "WRONG PASSWORD ({attempt}/{MAX_ATTEMPTS}) — {remaining} attempt(s) left\n\nDecrypting:\n{}\n\nEnter the password:",
                input.display()
            )
        };
        let password = match gui::password_ask(title, &body)? {
            Some(p) => p,
            None => return Err("cancelled by user".into()),
        };
        let combined = keyfile::combine(password.as_bytes(), keyfile_digest);
        match do_decrypt(input, output, is_dir, &combined) {
            Ok(()) => return Ok(()),
            Err(aegis::Error::Aead) => continue,
            Err(e) => {
                let msg = e.to_string();
                gui::show_error(&format!("Decryption failed:\n{msg}"));
                return Err(msg);
            }
        }
    }
    gui::show_error(&format!(
        "Wrong password — {MAX_ATTEMPTS} attempts used.\nGiving up."
    ));
    Err(format!("max attempts ({MAX_ATTEMPTS}) exceeded"))
}

// ---------- info ----------

fn cmd_info(input: PathBuf, gui_mode: bool) -> Result<(), String> {
    let bytes = std::fs::read(&input).map_err(|e| {
        let msg = e.to_string();
        if gui_mode {
            gui::show_error(&msg);
        }
        msg
    })?;
    if bytes.len() < HEADER_LEN {
        let msg = format!(
            "file too short to be a .bml file ({} bytes, need at least {HEADER_LEN})",
            bytes.len()
        );
        if gui_mode {
            gui::show_error(&msg);
        }
        return Err(msg);
    }
    let mut header_bytes = [0u8; HEADER_LEN];
    header_bytes.copy_from_slice(&bytes[..HEADER_LEN]);
    let header = Header::parse(&header_bytes).map_err(|e| {
        let msg = e.to_string();
        if gui_mode {
            gui::show_error(&msg);
        }
        msg
    })?;
    let kind = if header.flags & FLAG_DIRECTORY != 0 {
        "directory (tar)"
    } else {
        "file"
    };
    let pwd_source = if header.flags & FLAG_MASTER_KEY != 0 {
        "master password (from keyring)"
    } else {
        "custom password (prompt)"
    };
    let needs_keyfile = if header.flags & FLAG_KEYFILE != 0 {
        "yes"
    } else {
        "no"
    };
    let payload_bytes = bytes.len().saturating_sub(HEADER_LEN);

    if gui_mode {
        let text = format!(
            "File: {}\n\
             Magic: BML1   Version: 1\n\
             Payload kind: {kind}\n\
             Password source: {pwd_source}\n\
             Keyfile required: {needs_keyfile}\n\
             Flags: 0x{:02X}\n\
             Argon2id memory: {} KiB ({:.1} MiB)\n\
             Argon2id iterations: {}\n\
             Argon2id parallelism: {}\n\
             Header size: {HEADER_LEN} B\n\
             Encrypted payload: {payload_bytes} B",
            input.display(),
            header.flags,
            header.kdf_params.memory_kib,
            header.kdf_params.memory_kib as f64 / 1024.0,
            header.kdf_params.iterations,
            header.kdf_params.parallelism,
        );
        gui::show_info(&text);
    } else {
        println!("File:                 {}", input.display());
        println!("Magic:                BML1");
        println!("Version:              1");
        println!("Payload kind:         {kind}");
        println!("Password source:      {pwd_source}");
        println!("Keyfile required:     {needs_keyfile}");
        println!("Flags:                0x{:02X}", header.flags);
        println!(
            "Argon2id memory:      {} KiB ({:.1} MiB)",
            header.kdf_params.memory_kib,
            header.kdf_params.memory_kib as f64 / 1024.0
        );
        println!("Argon2id iterations:  {}", header.kdf_params.iterations);
        println!("Argon2id parallelism: {}", header.kdf_params.parallelism);
        println!("Header size:          {HEADER_LEN} B");
        println!("Encrypted payload:    {payload_bytes} B");
    }
    Ok(())
}

// ---------- main ----------

fn main() -> ExitCode {
    let cli = Cli::parse();
    let gui_mode = resolve_gui_mode(cli.gui, cli.no_gui);
    let res = match cli.cmd {
        Cmd::Init { force } => cmd_init(force, gui_mode),
        Cmd::Status => cmd_status(),
        Cmd::Forget => cmd_forget(gui_mode),
        Cmd::Encrypt {
            input,
            output,
            ask,
            keep,
            keyfile,
        } => cmd_encrypt(input, output, ask, keep, keyfile, gui_mode),
        Cmd::Decrypt {
            input,
            output,
            ask,
            keep,
            keyfile,
        } => cmd_decrypt(input, output, ask, keep, keyfile, gui_mode),
        Cmd::Info { input } => cmd_info(input, gui_mode),
        Cmd::KeyfileGen { output, size } => cmd_keyfile_gen(output, size, gui_mode),
        Cmd::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "aegis", &mut std::io::stdout());
            Ok(())
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("aegis: error: {msg}");
            ExitCode::from(1)
        }
    }
}
