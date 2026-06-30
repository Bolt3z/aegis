//! Platform-agnostic facade for GUI dialogs.
//!
//! Each backend implements the same public function set; the right one is
//! chosen at compile time via `cfg(target_os = ...)`.
//!
//! - Linux: `kdialog` (preferred) / `zenity` (fallback)
//! - macOS: `osascript` (AppleScript, ships with macOS)

#[cfg(target_os = "linux")]
mod backend_linux;
#[cfg(target_os = "linux")]
pub use backend_linux::*;

#[cfg(target_os = "macos")]
mod backend_macos;
#[cfg(target_os = "macos")]
pub use backend_macos::*;
