use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use clap_complete::generate;

use aegis::{
    FLAG_COMPRESSED, FLAG_DIRECTORY, FLAG_KEYFILE, FLAG_MASTER_KEY, HEADER_LEN, Header, KdfParams,
    decrypt_dir, decrypt_file, encrypt_dir, encrypt_file, peek_header,
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

// ---------- output collision handling ----------

/// Append `.tmp` to a path (mirrors the staging suffix used in `file.rs`).
fn tmp_sibling(p: &Path) -> PathBuf {
    let mut s: OsString = p.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Build a Windows-style de-duplicated name: `doc.pdf` → `doc (n).pdf`,
/// `notes` → `notes (n)`. The counter goes before the final extension.
fn insert_counter(path: &Path, n: u32) -> PathBuf {
    let parent = path.parent();
    let stem = path.file_stem().unwrap_or_default();
    let ext = path.extension();
    let mut name = stem.to_os_string();
    name.push(format!(" ({n})"));
    if let Some(e) = ext {
        name.push(".");
        name.push(e);
    }
    match parent {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// A candidate output path is free if neither it nor its `.tmp` staging
/// sibling exist (both would make `file.rs` refuse to write).
fn path_is_free(p: &Path) -> bool {
    !p.exists() && !tmp_sibling(p).exists()
}

/// Find the first free `name (n)` variant of `output`.
fn unique_path(output: &Path) -> PathBuf {
    let mut n = 1u32;
    loop {
        let cand = insert_counter(output, n);
        if path_is_free(&cand) || n >= 9999 {
            return cand;
        }
        n += 1;
    }
}

/// Whether writing `output` would collide. For a directory payload an existing
/// *empty* directory is acceptable (matches `decrypt_dir`), so it is not a
/// collision; everything else that already exists is.
fn output_collides(output: &Path, is_dir: bool) -> bool {
    match std::fs::symlink_metadata(output) {
        Err(_) => false,
        Ok(md) => {
            if is_dir && md.is_dir() {
                std::fs::read_dir(output)
                    .map(|mut e| e.next().is_some())
                    .unwrap_or(true)
            } else {
                true
            }
        }
    }
}

/// Outcome of resolving an output collision.
enum Resolution {
    /// Write the operation's output to `write_to`. If `finalize_to` is set,
    /// move `write_to` onto it once the write succeeds (Replace) — the original
    /// is destroyed only after the new content is safely written, so a failed
    /// or aborted decrypt never loses it.
    Go {
        write_to: PathBuf,
        finalize_to: Option<PathBuf>,
    },
    /// The user chose to cancel; do nothing.
    Abort,
}

/// Move a freshly-written `write_to` onto `finalize_to` (Replace semantics).
fn finalize_replace(write_to: &Path, finalize_to: &Path) -> Result<(), String> {
    // A directory destination must be removed before rename; rename atomically
    // replaces a regular-file destination.
    if let Ok(md) = std::fs::symlink_metadata(finalize_to) {
        if md.is_dir() {
            std::fs::remove_dir_all(finalize_to).map_err(|e| e.to_string())?;
        }
    }
    std::fs::rename(write_to, finalize_to).map_err(|e| e.to_string())
}

fn cli_ask_overwrite(output: &Path, alt_name: &str) -> Result<gui::Overwrite, String> {
    use std::io::Write;
    eprintln!("Output already exists: {}", output.display());
    eprint!("[R]eplace, [K]eep both (as \"{alt_name}\"), or [C]ancel? [K] ");
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    match line.trim().to_lowercase().as_str() {
        "r" | "replace" => Ok(gui::Overwrite::Replace),
        "c" | "cancel" => Ok(gui::Overwrite::Cancel),
        _ => Ok(gui::Overwrite::KeepBoth),
    }
}

/// Resolve an output-path collision. When `output` is free, proceeds with it
/// unchanged. Otherwise asks the user (GUI dialog or CLI prompt) to Replace,
/// Keep Both (auto-rename), or Cancel.
fn resolve_output_collision(
    output: &Path,
    is_dir: bool,
    gui_mode: bool,
) -> Result<Resolution, String> {
    if !output_collides(output, is_dir) {
        return Ok(Resolution::Go {
            write_to: output.to_path_buf(),
            finalize_to: None,
        });
    }
    let alt = unique_path(output);
    let alt_name = alt
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| alt.display().to_string());

    let choice = if gui_mode {
        if gui::is_available() {
            let body = format!(
                "Something already exists at:\n{}\n\n\
                 • Replace — overwrite it\n\
                 • Keep Both — save the new one as \u{201c}{}\u{201d}\n\
                 • Cancel — do nothing",
                output.display(),
                alt_name,
            );
            gui::ask_overwrite("Aegis — File exists", &body)?
        } else {
            // Not a terminal and no dialog backend: nobody to ask, so keep the
            // old conservative behavior and refuse to clobber.
            return Err(format!("output already exists: {}", output.display()));
        }
    } else {
        cli_ask_overwrite(output, &alt_name)?
    };

    match choice {
        // Replace: write to the free `alt` path, then swap onto `output` only
        // after the operation succeeds (see `finalize_replace`).
        gui::Overwrite::Replace => Ok(Resolution::Go {
            write_to: alt,
            finalize_to: Some(output.to_path_buf()),
        }),
        gui::Overwrite::KeepBoth => Ok(Resolution::Go {
            write_to: alt,
            finalize_to: None,
        }),
        gui::Overwrite::Cancel => Ok(Resolution::Abort),
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

    // First-time setup from the GUI: if no master exists yet (and the user
    // didn't force --ask), offer to create one right here, so the master mode
    // is usable from Finder/Dolphin without dropping to the terminal.
    if !ask && !master_set {
        let body = format!(
            "No master password is set yet.\nHow do you want to encrypt this {kind}?\n{input_display}"
        );
        let items: &[(&str, &str, bool)] = &[
            (
                "set",
                "Set a master password now (saved in your keyring)",
                true,
            ),
            (
                "custom",
                "Use a one-off custom password (for sharing)",
                false,
            ),
        ];
        match gui::choose_radio("Aegis — First-time setup", &body, items)? {
            Some(s) if s == "set" => {
                let pwd = match gui::password_new(
                    "Aegis — Set master password",
                    "Choose a master password.\nIt is saved in your system keyring and used by default for encryption.",
                )? {
                    Some(p) => p,
                    None => return Err("cancelled by user".into()),
                };
                keychain::set_master(&pwd).map_err(|e| e.to_string())?;
                // Master now stored → use it (CLI --keyfile still honored).
                return Ok((false, keyfile_cli));
            }
            Some(_) => return Ok((true, keyfile_cli)),
            None => return Err("cancelled by user".into()),
        }
    }

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
    compress: bool,
    gui_mode: bool,
) -> Result<(), String> {
    if !input.exists() {
        return Err(format!("input does not exist: {}", input.display()));
    }
    let is_dir = input.is_dir();
    if compress && !is_dir && !gui_mode {
        eprintln!("note: --compress only applies to directories; ignoring it for this file.");
    }
    let requested_output = output.unwrap_or_else(|| default_encrypt_output(&input));
    // The encrypted output is always a single .bml file (never a directory).
    let (write_to, finalize_to) = match resolve_output_collision(&requested_output, false, gui_mode)?
    {
        Resolution::Go {
            write_to,
            finalize_to,
        } => (write_to, finalize_to),
        Resolution::Abort => return Ok(()),
    };

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
    let compress_flag = if compress && is_dir { FLAG_COMPRESSED } else { 0 };
    let extra_flags = master_flag | keyfile_flag | compress_flag;
    let combined = keyfile::combine(password.as_bytes(), keyfile_digest.as_ref());

    if !gui_mode {
        eprintln!("Deriving key with Argon2id (~1s)…");
    }
    match do_encrypt(&input, &write_to, is_dir, &combined, extra_flags) {
        Ok(()) => {
            // Replace: the .bml is fully written, so swap it onto the existing
            // file now. No-op for the no-collision and Keep Both cases.
            if let Some(dest) = &finalize_to {
                if let Err(e) = finalize_replace(&write_to, dest) {
                    let msg = format!("Encrypted, but could not replace {}: {e}", dest.display());
                    if gui_mode {
                        gui::show_error(&msg);
                    }
                    return Err(msg);
                }
            }
            let final_output = finalize_to.as_deref().unwrap_or(&write_to);
            let deleted = match maybe_delete_after_encrypt(&input, is_dir, keep, gui_mode) {
                Ok(d) => d,
                Err(e) => {
                    // Encrypt succeeded but delete failed — surface the error
                    // without claiming the original is gone.
                    let msg = format!(
                        "Encrypted: {}\nFailed to remove original: {e}",
                        final_output.display()
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
                gui::show_info(&format!("Encrypted:\n{}{}", final_output.display(), tail));
            } else {
                println!("Encrypted: {}{}", final_output.display(), tail);
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

    // If the destination already exists, ask before clobbering it: Replace,
    // Keep Both (write to `name (n)`), or Cancel. This commonly happens after
    // `encrypt --keep`, when the plaintext is still next to the .bml. Replace
    // is staged (write to a temp name, swap on success) so a wrong-password
    // decrypt never destroys the file that was already there.
    let (write_to, finalize_to) = match resolve_output_collision(&output, is_dir, gui_mode)? {
        Resolution::Go {
            write_to,
            finalize_to,
        } => (write_to, finalize_to),
        Resolution::Abort => return Ok(()),
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
                match do_decrypt(&input, &write_to, is_dir, &combined) {
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
            decrypt_gui_prompt(&input, &write_to, is_dir, was_master, digest_ref)?;
        } else {
            decrypt_cli_prompt(&input, &write_to, is_dir, was_master, digest_ref)?;
        }
    }

    // Decryption succeeded. For Replace, swap the freshly-written output onto
    // the file that was already there (a no-op for no-collision / Keep Both).
    let output = if let Some(dest) = &finalize_to {
        finalize_replace(&write_to, dest).map_err(|e| {
            let msg = format!("Decrypted, but could not replace {}: {e}", dest.display());
            if gui_mode {
                gui::show_error(&msg);
            }
            msg
        })?;
        dest.clone()
    } else {
        write_to
    };

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
    let compressed = if header.flags & FLAG_COMPRESSED != 0 {
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
             Compressed: {compressed}\n\
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
        println!("Compressed:           {compressed}");
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
            compress,
        } => cmd_encrypt(input, output, ask, keep, keyfile, compress, gui_mode),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_inserts_before_extension() {
        assert_eq!(
            insert_counter(Path::new("/a/b/doc.pdf"), 1),
            PathBuf::from("/a/b/doc (1).pdf")
        );
        assert_eq!(
            insert_counter(Path::new("doc.pdf"), 2),
            PathBuf::from("doc (2).pdf")
        );
    }

    #[test]
    fn counter_without_extension() {
        assert_eq!(
            insert_counter(Path::new("/a/notes"), 3),
            PathBuf::from("/a/notes (3)")
        );
    }

    #[test]
    fn counter_keeps_only_last_extension() {
        // Mirrors how the .bml default output (`document.pdf`) gets numbered.
        assert_eq!(
            insert_counter(Path::new("archive.tar.gz"), 1),
            PathBuf::from("archive.tar (1).gz")
        );
    }

    #[test]
    fn unique_path_walks_until_free() {
        let dir = std::env::temp_dir().join(format!("aegis-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("file.txt");
        std::fs::write(&base, b"x").unwrap();
        // base is taken, "file (1).txt" is free.
        assert_eq!(unique_path(&base), dir.join("file (1).txt"));
        // Now occupy "file (1).txt" too → expect "file (2).txt".
        std::fs::write(dir.join("file (1).txt"), b"x").unwrap();
        assert_eq!(unique_path(&base), dir.join("file (2).txt"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
