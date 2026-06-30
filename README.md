# Aegis

Personal file and directory encryption tool, written in Rust.

```bash
aegis init                          # set a master password once
aegis encrypt notes.pdf             # encrypts then asks to remove the original
aegis encrypt --keep secrets.pdf    # keep the original (no prompt)
aegis decrypt notes.pdf.bml         # decrypts then asks to remove the .bml
aegis decrypt --keep notes.pdf.bml  # keep the encrypted file too
```

Uses **XChaCha20-Poly1305** for authenticated streaming encryption and
**Argon2id** (m=256 MiB, t=3, p=4) for password-based key derivation. The
master password lives in the system keyring (kwallet on KDE via libsecret) so
day-to-day encryption is one command, while files needing a separate password
use `--ask`.

> [!IMPORTANT]
> Aegis is **not** a replacement for full-disk encryption. For protecting your
> running system, use **LUKS**. Aegis is for files you carry around (USB
> drives, cloud sync folders, email attachments) where data-at-rest matters.

## Install

### Linux (Debian / Ubuntu / Parrot)

```bash
cargo deb
sudo dpkg -i target/debian/aegis_0.1.0-1_amd64.deb
```

> The newer `apt` (3.x) on Debian Trixie / Parrot rejects local `.deb` files
> with "Unsupported file". Use `dpkg -i` instead.

After install you have:

- `/usr/bin/aegis`
- Bash, zsh, and fish tab completions in their standard `vendor` paths
- `kdialog` recommended (already shipped on KDE); `zenity` works as a fallback
- Dolphin service menu in `/usr/share/kio/servicemenus/aegis.desktop`

Uninstall: `sudo apt purge aegis`.

### macOS (Intel + Apple Silicon, universal `.pkg`)

Requirements on the build machine: Xcode Command Line Tools and Rust via
[rustup](https://rustup.rs). The `pkgbuild` tool ships with macOS, no
Xcode app needed.

```bash
bash scripts/build-all-macos.sh
```

That builds two architectures, `lipo`-merges them into a universal binary,
and produces `target/macos/aegis-0.1.0-universal.pkg` (~5 MB).

Install:

```bash
sudo installer -pkg target/macos/aegis-0.1.0-universal.pkg -target /
```

…or simply double-click the `.pkg` in Finder and follow the Installer
wizard.

The `.pkg` installs:

- `/usr/local/bin/aegis` (already in `$PATH` on macOS)
- Finder **Quick Actions** in `/Library/Services/`:
  - `Aegis - Encrypt` — encrypt with your saved password (one click)
  - `Aegis - Encrypt with photo` — your password **+** a photo as a second key
  - `Aegis - Encrypt to share` — a one-off password to give the recipient
  - `Aegis - Encrypt (menu)` — a single entry that asks which of the above
  - `Aegis - Decrypt` — decrypt (auto-detects what the file needs)
  - `Aegis - Info` — show the header without decrypting

Right-click any file or folder in Finder → **Quick Actions** (or
**Services** on older macOS) → pick an action.

> Two styles ship side by side so you can pick what you like: the separate
> `Encrypt…` entries (one click each) and the single `Encrypt (menu)` entry
> (one entry, then a small menu). Keep whichever you prefer.

> **First-run Gatekeeper warning.** The `.pkg` is not code-signed (no Apple
> Developer ID), so macOS shows "this package can't be verified" on the
> first launch. Workaround: right-click the `.pkg` → **Open** → confirm.
> One-time only.

The master password is stored in your **login Keychain** (`aegis init`),
unlocked automatically when you log in. The Keychain backend works
exactly like kwallet on Linux from the tool's perspective. You don't have
to run `aegis init` in the terminal: the first time you encrypt something
from the Finder Quick Action with no master set, Aegis offers to create one
in a dialog.

> **Keychain prompt.** The first time Aegis reads the master from the
> Keychain, macOS asks for your login password — click **Always Allow** and
> it won't ask again. The `.pkg` ships an **ad-hoc code signature** so that
> "Always Allow" actually persists; without it an unsigned binary would
> re-prompt on every single run.

Uninstall (no automated uninstaller; manual removal is two paths):

```bash
sudo rm /usr/local/bin/aegis
sudo rm -rf "/Library/Services/Aegis - "*.workflow
# Optional: remove the master from your Keychain
aegis forget
```

## Usage

### One-time setup

```bash
aegis init      # prompts for the master password twice, stores in the keyring
aegis status    # show whether a master is set
aegis forget    # remove the master from the keyring
```

The keyring is unlocked automatically when you log in. Aegis only talks to the
secret service when invoked; it does not run as a daemon.

### Encrypting

```bash
aegis encrypt document.pdf                  # → document.pdf.bml (uses master)
aegis encrypt ~/notes/                      # → notes.bml (tar streaming)
aegis encrypt --ask important.pdf           # prompts for a one-off password
aegis encrypt -a -o /tmp/out.bml file.txt   # custom password + custom output
aegis encrypt --keep document.pdf           # keep the plaintext after encryption
aegis encrypt --compress ~/notes/           # gzip the folder before encrypting
```

**Compression (`--compress` / `-c`)** is opt-in and applies **only to
directories**: the `tar` stream is gzip-compressed before encryption. It's a no-op
for single files (most carried files — JPEG/MP4/PDF/Office — are already
compressed) and is ignored there with a note. It helps a lot for folders of
text, logs, or source. Decryption auto-detects compression from the header; no
flag needed. Note: the encrypted size reveals how compressible the content was,
a minor at-rest information leak — which is why it's off by default.

Defaults:
- Output path is `<input>.bml` for files, `<basename>.bml` (in the same parent
  directory) for directories.
- Aegis refuses to overwrite existing outputs.
- **The original is removed after a successful encrypt** unless `--keep` /
  `-k` is passed. In an interactive CLI or GUI session you'll see a
  confirmation prompt first (default = Yes); for directories the prompt
  includes file count and size. In a fully headless context (no TTY, no
  kdialog/zenity) the original is deleted silently — pass `--keep` to
  preserve it.
- The deletion is a plain `unlink` / `rm -r`, **not** a secure shred. On
  SSDs (and even HDDs without overwrite) the data remains forensically
  recoverable until the storage layer reuses the blocks. If you need
  unrecoverable deletion, use full-disk encryption (LUKS) or a
  self-encrypting drive with crypto-erase.

### Decrypting

```bash
aegis decrypt document.pdf.bml              # auto: tries master, falls back to prompt
aegis decrypt --ask document.pdf.bml        # always prompts, ignores the master
aegis decrypt -o /tmp/out notes.bml         # custom output (existing empty dir OK)
aegis decrypt --keep document.pdf.bml       # keep the encrypted file after decrypt
```

When the header marks the file as encrypted with the master, Aegis pulls the
master from the keyring without prompting. If the master has been changed or
removed, Aegis falls back to a prompt automatically — you can still recover
old files by typing the old master.

Output path defaults to the input with `.bml` stripped.

**If the destination already exists** (typical after `encrypt --keep`, when the
plaintext is still next to the `.bml`), Aegis no longer aborts. It asks what to
do: **Replace** (overwrite), **Keep Both** — saves the new file under a
Windows-style numbered name (`document (1).pdf`, `document (2).pdf`, …) — or
**Cancel**. The same prompt applies to `encrypt` when the `.bml` output already
exists. In GUI mode it's a dialog; in a terminal it's an `[R]/[K]/[C]` prompt
(default Keep Both). In a fully headless context (no terminal and no dialog
backend) there's nobody to ask, so Aegis still refuses to overwrite.

**Like `encrypt`, decrypt removes its input on success** (the encrypted
`.bml`) unless `--keep` / `-k` is passed. You get the same interactive
confirmation in CLI and GUI mode, and the same silent-delete behavior in
true-headless contexts. Same caveat about non-secure deletion (the bytes
remain forensically recoverable on SSD until the storage layer reuses
the blocks).

### Keyfile (optional second factor)

For files where the master alone isn't enough — say you want even a stolen
unlocked laptop to be unable to decrypt them — you can combine the password
with a **keyfile** (typically a random blob on a USB stick).

```bash
aegis keyfile-gen --output /media/usb/aegis-key.bin       # 64 random bytes, mode 0600
aegis encrypt --keyfile /media/usb/aegis-key.bin doc.pdf  # master + keyfile
aegis decrypt --keyfile /media/usb/aegis-key.bin doc.pdf.bml
```

How it works:
- The keyfile content is BLAKE2b-256 hashed into a 32-byte digest, then
  appended to the password before Argon2id derivation.
- The path of the keyfile is **not** stored in the .bml header — only a
  flag bit that says "this file needs a keyfile". You need to remember
  which keyfile to use.
- Losing the keyfile means losing access. Treat it like a 2FA secret —
  back it up to a second USB stick if you care about the files.

Combine with `--ask` for "custom password + keyfile" (typical for files
shared with a colleague who also has the keyfile):

```bash
aegis encrypt --ask --keyfile /media/usb/k.bin report.pdf
```

Mismatches are caught explicitly:
- `decrypt --keyfile X` on a `.bml` that doesn't use a keyfile → error.
- `decrypt` without `--keyfile` on a keyfile-flagged `.bml` → error in CLI,
  or a GUI picker shows up in GUI mode.

Check whether a `.bml` needs a keyfile without decrypting:

```bash
aegis info doc.pdf.bml | grep "Keyfile required"
```

### Inspect a file without decrypting

```bash
aegis info document.pdf.bml
```

Reads only the 64-byte header. No password needed. Reveals the cipher kind
(file vs directory archive), password source (master vs custom), and Argon2
parameters.

### CLI vs GUI

By default Aegis picks the prompt style automatically: if both stdin and
stderr point at a terminal, you get a CLI prompt (`rpassword`); otherwise you
get a desktop dialog (kdialog, falling back to zenity).

You can force either style:

```bash
aegis --gui encrypt foo.pdf
aegis --no-gui encrypt foo.pdf
```

GUI decryption gives you up to 3 attempts per launch; CLI decryption is
single-shot (re-run if you mistype — exit code is 1 on Aead failure, so it's
script-friendly).

### Dolphin right-click

The `.deb` ships a service menu at
`/usr/share/kio/servicemenus/aegis.desktop`. Right-click any file or folder
in Dolphin and the **Aegis** submenu offers, by intent:

- **Encrypt (for me)** — encrypt with your saved master password, no questions.
- **Encrypt with a photo** — master password **+** a photo as a second key (you
  pick a photo and Aegis freezes a copy of it).
- **Encrypt to share** — a one-off password to communicate to the recipient;
  the resulting `.bml` won't reach into anyone's keyring, it just asks for that
  password. With zenity installed, the password and the "add a photo?" choice
  appear in a single dialog; otherwise it's two quick prompts.
- **Decrypt** — decrypt, auto-detecting whether the file needs your master, a
  typed password, or a photo/key.
- **Show header info** — inspect without decrypting.

The actions run with `--gui` so prompts use kdialog and successes/errors show
as message boxes.

When you **Decrypt** a `.bml` that someone else encrypted with their
master password, the prompt explicitly tells you so — "Enter the sender's
master password" — instead of a generic "enter password".

Notes:

- Currently single-file: select one file at a time. Multi-select is on the
  roadmap.
- Decrypt/Info appear on any file, not just `.bml` — they fail gracefully
  on non-encrypted inputs.
- After installing the `.deb` you may need to restart Dolphin (or run
  `kbuildsycoca6` / log out and back in) for the menu to appear.

## Security model

What Aegis protects:

- **File at rest stolen.** Confidentiality and tamper-detection are both
  enforced by AEAD on every 64 KiB chunk plus the full 64-byte header as
  associated data.
- **Truncation, chunk reorder, and bit-flip attacks.** Each chunk's nonce
  encodes its position, so reordering or dropping chunks fails authentication;
  the final chunk carries a "last" flag so trailing data can't be appended.

What Aegis does **not** protect:

- **Compromised running system.** A process with shell access to your unlocked
  session can read the master from the keyring and decrypt master-flagged
  files. This is by design — the keyring is for convenience, not for defending
  against attackers who already have your session.
- **Coercion / rubber-hose attacks.** Standard password-protected tool
  caveats.
- **Cold-boot, evil-maid, sleep-mode key recovery.** Not designed for that;
  use LUKS + TPM2 if you need it.

The keyring entry is per-user-per-machine. **Treat the master like a real
password you have to remember**: if you reformat or move a `.bml` to another
device, the keyring won't help you and you'll need to type the master by hand
(`aegis decrypt --ask`).

## File format (.bml)

Each `.bml` is:

```
+--------------------+
| 64-byte header     |   (magic "BML1", version, flags, Argon2 params,
|                    |    16-byte salt, 19-byte STREAM nonce prefix)
+--------------------+
| AEAD chunk 0       |   ≤ 64 KiB plaintext + 16-byte tag
+--------------------+
| AEAD chunk 1       |
+--------------------+
| …                  |
+--------------------+
| AEAD final chunk   |   carries the "last" flag in its nonce
+--------------------+
```

The entire 64-byte header is included as AAD on every chunk, so tampering
with any field (flags, salt, Argon2 params, nonce prefix) breaks
authentication on the very first chunk.

Header flag bits in use:

| Bit | Constant            | Meaning                                       |
|-----|---------------------|-----------------------------------------------|
| 0   | `FLAG_DIRECTORY`    | Payload is a tar archive (folder encryption)  |
| 1   | `FLAG_MASTER_KEY`   | Encrypted with the master password (keyring)  |

For folder encryption, Aegis pipes a `tar` stream through the AEAD encoder
without ever materialising the plaintext archive on disk. On decrypt the
output directory is built under `<output>.tmp/` and renamed atomically once
extraction succeeds; on failure the partial directory is removed.

## Commands reference

| Command                           | What it does                                       |
|-----------------------------------|----------------------------------------------------|
| `aegis init [--force]`            | Set the master password in the system keyring     |
| `aegis status`                    | Show whether a master is currently stored         |
| `aegis forget`                    | Remove the master from the keyring                |
| `aegis encrypt <path>`            | Encrypt a file or directory using the master      |
| `aegis encrypt --ask <path>`      | Encrypt with a one-off prompt-supplied password   |
| `aegis decrypt <bml>`             | Decrypt, auto-routing master vs prompt            |
| `aegis decrypt --ask <bml>`       | Decrypt, always prompt                            |
| `aegis info <bml>`                | Inspect a `.bml` header (no password needed)      |
| `aegis completions <shell>`       | Print a shell completion script to stdout         |

Global flags: `--gui` / `--no-gui` to override the TTY auto-detect.

## Build from source

Requires `rustc` ≥ 1.85 (distro-installed on Parrot/Debian Trixie is fine).

```bash
cargo build --release
cargo test
cargo deb            # produces target/debian/aegis_0.1.0-1_amd64.deb
```

`cargo deb` requires the `cargo-deb` subcommand:

```bash
cargo install cargo-deb --version "^2" --locked
```

The `--locked` and major-version pin are workarounds for Rust 1.85 (newer
`cargo-deb` 3.x lines depend on let-chains stabilised in 1.88).

## Limitations

- File extension is `.bml` and header magic is `BML1`. These predate the
  rename from "BitlokerMeglio" and were kept for simplicity — there is no
  schema migration concern because no files were in the wild during the
  rename.
- No secure-shred of the original plaintext after encryption.
- Quick Actions / Dolphin menu are single-file at a time (multi-select is on
  the roadmap).
- A photo used as a second key must stay byte-identical; Aegis freezes a copy
  in `~/.config/aegis/keys/`, but back that copy up — losing it (or the keyfile)
  means losing access even with the right password.

## License

MIT. See `LICENSE` (or the auto-generated `/usr/share/doc/aegis/copyright`
once installed).
