use std::process::{Command, Stdio};

use super::Overwrite;

#[derive(Clone, Copy, Debug)]
enum Backend {
    Kdialog,
    Zenity,
}

fn cmd_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detect_backend() -> Result<Backend, String> {
    if cmd_available("kdialog") {
        Ok(Backend::Kdialog)
    } else if cmd_available("zenity") {
        Ok(Backend::Zenity)
    } else {
        Err("no GUI dialog tool found — install kdialog or zenity".into())
    }
}

pub fn is_available() -> bool {
    detect_backend().is_ok()
}

fn capture_stdout(out: std::process::Output) -> Option<String> {
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

pub fn password_new(title: &str, body: &str) -> Result<Option<String>, String> {
    match detect_backend()? {
        Backend::Kdialog => {
            let out = Command::new("kdialog")
                .args(["--title", title, "--newpassword", body])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(capture_stdout(out))
        }
        Backend::Zenity => {
            let a = match zenity_password(title)? {
                Some(s) => s,
                None => return Ok(None),
            };
            let b = match zenity_password(&format!("{title} (confirm)"))? {
                Some(s) => s,
                None => return Ok(None),
            };
            if a != b {
                return Err("passwords do not match".into());
            }
            Ok(Some(a))
        }
    }
}

pub fn password_ask(title: &str, body: &str) -> Result<Option<String>, String> {
    match detect_backend()? {
        Backend::Kdialog => {
            let out = Command::new("kdialog")
                .args(["--title", title, "--password", body])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(capture_stdout(out))
        }
        Backend::Zenity => zenity_password(title),
    }
}

/// Ask for a one-off password and whether to add a photo second factor.
///
/// `zenity --forms` can show the password field and a Yes/No selector in a
/// SINGLE dialog, so we prefer it here even when kdialog is the primary
/// backend (kdialog has no way to combine a password input with a checkbox).
/// Falls back to a two-step kdialog flow when zenity isn't installed.
/// Returns (password, wants_photo), or None if cancelled.
pub fn password_with_photo_option(
    title: &str,
    body: &str,
) -> Result<Option<(String, bool)>, String> {
    if cmd_available("zenity") {
        // Password on top, photo selector below (matches the desired layout).
        // Tab separator + rsplit keeps the password intact.
        let out = Command::new("zenity")
            .args([
                "--forms",
                "--title",
                title,
                "--text",
                body,
                "--separator",
                "\t",
                "--add-password",
                "Password",
                "--add-combo",
                "Also use a photo as a second key?",
                "--combo-values",
                "No|Yes",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Ok(None);
        }
        let raw = String::from_utf8_lossy(&out.stdout);
        let raw = raw.trim_end_matches(['\n', '\r']);
        if raw.is_empty() {
            return Ok(None);
        }
        let (pwd, choice) = raw.rsplit_once('\t').unwrap_or((raw, ""));
        if pwd.is_empty() {
            return Ok(None);
        }
        return Ok(Some((pwd.to_string(), choice == "Yes")));
    }

    // kdialog fallback: password, then a separate Yes/No.
    let pwd = match password_ask(title, body)? {
        Some(p) => p,
        None => return Ok(None),
    };
    let wants_photo = confirm(title, "Add a photo as a second key?")?;
    Ok(Some((pwd, wants_photo)))
}

pub fn show_error(text: &str) {
    if let Ok(backend) = detect_backend() {
        let _ = match backend {
            Backend::Kdialog => Command::new("kdialog").args(["--error", text]).status(),
            Backend::Zenity => Command::new("zenity")
                .args(["--error", "--text", text])
                .status(),
        };
    } else {
        eprintln!("aegis: error: {text}");
    }
}

pub fn choose_radio(
    title: &str,
    body: &str,
    items: &[(&str, &str, bool)],
) -> Result<Option<String>, String> {
    match detect_backend()? {
        Backend::Kdialog => {
            let mut cmd = Command::new("kdialog");
            cmd.args(["--title", title, "--radiolist", body]);
            for (tag, label, default) in items {
                cmd.arg(tag);
                cmd.arg(label);
                cmd.arg(if *default { "on" } else { "off" });
            }
            let out = cmd.output().map_err(|e| e.to_string())?;
            Ok(capture_stdout(out))
        }
        Backend::Zenity => {
            let mut cmd = Command::new("zenity");
            cmd.args([
                "--list",
                "--radiolist",
                "--title",
                title,
                "--text",
                body,
                "--column",
                "",
                "--column",
                "tag",
                "--column",
                "Mode",
                "--hide-column=2",
                "--print-column=2",
            ]);
            for (tag, label, default) in items {
                cmd.arg(if *default { "TRUE" } else { "FALSE" });
                cmd.arg(tag);
                cmd.arg(label);
            }
            let out = cmd.output().map_err(|e| e.to_string())?;
            Ok(capture_stdout(out))
        }
    }
}

pub fn pick_file(title: &str, start_dir: &str) -> Result<Option<std::path::PathBuf>, String> {
    match detect_backend()? {
        Backend::Kdialog => {
            let out = Command::new("kdialog")
                .args(["--title", title, "--getopenfilename", start_dir])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(capture_stdout(out).map(std::path::PathBuf::from))
        }
        Backend::Zenity => {
            let out = Command::new("zenity")
                .args(["--file-selection", "--title", title])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(capture_stdout(out).map(std::path::PathBuf::from))
        }
    }
}

/// Three-way "file exists" prompt: Replace / Keep Both / Cancel.
pub fn ask_overwrite(title: &str, body: &str) -> Result<Overwrite, String> {
    match detect_backend()? {
        Backend::Kdialog => {
            // --warningyesnocancel exit codes: 0 = Yes, 1 = No, 2 = Cancel.
            let status = Command::new("kdialog")
                .args([
                    "--title",
                    title,
                    "--warningyesnocancel",
                    body,
                    "--yes-label",
                    "Keep Both",
                    "--no-label",
                    "Replace",
                    "--cancel-label",
                    "Cancel",
                ])
                .status()
                .map_err(|e| e.to_string())?;
            match status.code() {
                Some(0) => Ok(Overwrite::KeepBoth),
                Some(1) => Ok(Overwrite::Replace),
                _ => Ok(Overwrite::Cancel),
            }
        }
        Backend::Zenity => {
            // OK = Keep Both, the extra button = Replace (printed to stdout),
            // anything else (Cancel / closed) = Cancel.
            let out = Command::new("zenity")
                .args([
                    "--question",
                    "--title",
                    title,
                    "--text",
                    body,
                    "--ok-label",
                    "Keep Both",
                    "--cancel-label",
                    "Cancel",
                    "--extra-button",
                    "Replace",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            if String::from_utf8_lossy(&out.stdout).trim() == "Replace" {
                Ok(Overwrite::Replace)
            } else if out.status.success() {
                Ok(Overwrite::KeepBoth)
            } else {
                Ok(Overwrite::Cancel)
            }
        }
    }
}

pub fn confirm(title: &str, body: &str) -> Result<bool, String> {
    match detect_backend()? {
        Backend::Kdialog => {
            let status = Command::new("kdialog")
                .args(["--title", title, "--yesno", body])
                .status()
                .map_err(|e| e.to_string())?;
            Ok(status.success())
        }
        Backend::Zenity => {
            let status = Command::new("zenity")
                .args(["--question", "--title", title, "--text", body])
                .status()
                .map_err(|e| e.to_string())?;
            Ok(status.success())
        }
    }
}

pub fn show_info(text: &str) {
    if let Ok(backend) = detect_backend() {
        let _ = match backend {
            Backend::Kdialog => Command::new("kdialog").args(["--msgbox", text]).status(),
            Backend::Zenity => Command::new("zenity")
                .args(["--info", "--text", text])
                .status(),
        };
    } else {
        eprintln!("aegis: {text}");
    }
}

fn zenity_password(title: &str) -> Result<Option<String>, String> {
    let out = Command::new("zenity")
        .args(["--password", "--title", title])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(capture_stdout(out))
}
