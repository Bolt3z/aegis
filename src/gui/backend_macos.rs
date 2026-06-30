//! macOS GUI backend: spawns `osascript` and parses its output.
//!
//! All dialogs use AppleScript primitives that ship with macOS. The script is
//! piped via stdin to avoid command-line escaping pitfalls; AppleScript
//! string literals inside the script are escaped via `as_quoted`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Escape a string for inclusion as an AppleScript string literal.
/// Wraps in double quotes and escapes `"` and `\`.
fn as_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Run an AppleScript by piping it to `osascript` on stdin. Returns the raw
/// Output (caller decides how to interpret stdout/exit-code).
fn run_script(script: &str) -> Result<Output, String> {
    let mut child = Command::new("osascript")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("osascript not available: {e}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open osascript stdin".to_string())?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    child.wait_with_output().map_err(|e| e.to_string())
}

fn trimmed_stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string()
}

/// True if `osascript` exists. Should always be true on macOS, but we still
/// probe so the calling code can fall back gracefully if PATH is broken.
pub fn is_available() -> bool {
    Command::new("osascript")
        .arg("-e")
        .arg("return 1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Ask for a new password and a confirmation (two dialogs). Returns Ok(None)
/// if the user cancels either dialog. Returns Err if the two entries differ.
pub fn password_new(title: &str, body: &str) -> Result<Option<String>, String> {
    let a = match password_dialog(title, body)? {
        Some(s) => s,
        None => return Ok(None),
    };
    let b = match password_dialog(title, &format!("{body}\n\nConfirm the password:"))? {
        Some(s) => s,
        None => return Ok(None),
    };
    if a != b {
        return Err("passwords do not match".into());
    }
    Ok(Some(a))
}

/// Ask for an existing password (single dialog).
pub fn password_ask(title: &str, body: &str) -> Result<Option<String>, String> {
    password_dialog(title, body)
}

fn password_dialog(title: &str, body: &str) -> Result<Option<String>, String> {
    let script = format!(
        r#"try
    set _r to display dialog {body} with title {title} default answer "" with hidden answer buttons {{"Cancel","OK"}} default button "OK"
    return text returned of _r
on error number -128
    return ""
end try"#,
        body = as_quoted(body),
        title = as_quoted(title),
    );
    let out = run_script(&script)?;
    if !out.status.success() {
        // AppleScript "User canceled." also surfaces as nonzero exit on some macOS versions.
        return Ok(None);
    }
    let s = trimmed_stdout(&out);
    if s.is_empty() {
        // We map cancel to empty stdout in the `try` block above.
        Ok(None)
    } else {
        Ok(Some(s))
    }
}

pub fn show_error(text: &str) {
    let script = format!(
        r#"display alert "Aegis" message {body} as critical buttons {{"OK"}} default button "OK""#,
        body = as_quoted(text),
    );
    let _ = run_script(&script);
}

pub fn show_info(text: &str) {
    let script = format!(
        r#"display alert "Aegis" message {body} as informational buttons {{"OK"}} default button "OK""#,
        body = as_quoted(text),
    );
    let _ = run_script(&script);
}

pub fn confirm(title: &str, body: &str) -> Result<bool, String> {
    // display dialog returns the button name in "button returned"; cancel
    // raises error -128 which we catch and treat as "No".
    let script = format!(
        r#"try
    set _r to display dialog {body} with title {title} buttons {{"No","Yes"}} default button "Yes" cancel button "No"
    if button returned of _r is "Yes" then
        return "yes"
    else
        return "no"
    end if
on error number -128
    return "no"
end try"#,
        body = as_quoted(body),
        title = as_quoted(title),
    );
    let out = run_script(&script)?;
    if !out.status.success() {
        return Ok(false);
    }
    Ok(trimmed_stdout(&out) == "yes")
}

/// Single-choice list. AppleScript's `choose from list` shows the LABELS
/// to the user; we map back from chosen label to its tag.
pub fn choose_radio(
    title: &str,
    body: &str,
    items: &[(&str, &str, bool)],
) -> Result<Option<String>, String> {
    if items.is_empty() {
        return Ok(None);
    }
    let labels_list = items
        .iter()
        .map(|(_, label, _)| as_quoted(label))
        .collect::<Vec<_>>()
        .join(", ");
    // Default to the first item with default=true, else the first item.
    let default_label = items
        .iter()
        .find(|(_, _, d)| *d)
        .map(|(_, l, _)| *l)
        .unwrap_or(items[0].1);

    let script = format!(
        r#"set _choice to choose from list {{{labels}}} with title {title} with prompt {body} default items {{{default}}} OK button name "OK" cancel button name "Cancel"
if _choice is false then
    return ""
else
    return item 1 of _choice
end if"#,
        labels = labels_list,
        title = as_quoted(title),
        body = as_quoted(body),
        default = as_quoted(default_label),
    );
    let out = run_script(&script)?;
    if !out.status.success() {
        return Ok(None);
    }
    let chosen_label = trimmed_stdout(&out);
    if chosen_label.is_empty() {
        return Ok(None);
    }
    // Map label back to tag.
    for (tag, label, _) in items {
        if *label == chosen_label {
            return Ok(Some((*tag).to_string()));
        }
    }
    // Shouldn't happen, but be defensive.
    Ok(Some(chosen_label))
}

pub fn pick_file(title: &str, start_dir: &str) -> Result<Option<PathBuf>, String> {
    let start = if std::path::Path::new(start_dir).is_dir() {
        start_dir
    } else {
        // POSIX file of a nonexistent path makes osascript fail; let it default.
        ""
    };
    let script = if start.is_empty() {
        format!(
            r#"try
    set _f to choose file with prompt {prompt}
    return POSIX path of _f
on error number -128
    return ""
end try"#,
            prompt = as_quoted(title),
        )
    } else {
        format!(
            r#"try
    set _f to choose file with prompt {prompt} default location (POSIX file {start})
    return POSIX path of _f
on error number -128
    return ""
end try"#,
            prompt = as_quoted(title),
            start = as_quoted(start),
        )
    };
    let out = run_script(&script)?;
    if !out.status.success() {
        return Ok(None);
    }
    let p = trimmed_stdout(&out);
    if p.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PathBuf::from(p)))
    }
}
