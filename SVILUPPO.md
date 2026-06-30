# Aegis — guida di sviluppo

Questo file racconta esattamente cosa abbiamo costruito, fase per fase, con il
"perché" dietro le scelte tecniche. È pensato per quando ci torni sopra fra un
mese e ti chiedi "ma perché avevamo fatto così?".

Il progetto è nato come `BitlokerMeglio` con l'obiettivo iniziale di scrivere
un Full Disk Encryption da zero. Dopo la prima discussione di scoping abbiamo
ristretto a uno strumento per file/cartelle (chiamato poi `aegis`), lasciando
l'FDE a **LUKS** — perché reinventare LUKS è il modo più veloce di perdere
tutti i propri dati.

## Sommario del prodotto finale

- Binario Rust `aegis` (~3.9 MB strippato), installabile via pacchetto `.deb`
- Crittografia: **XChaCha20-Poly1305** in modalità STREAM su chunk da 64 KiB
- Derivazione chiave: **Argon2id** (m=256 MiB, t=3, p=4 di default)
- Una "master password" salvata nel **keyring KDE (kwallet via libsecret)** →
  `aegis encrypt` istantaneo, senza prompt
- Flag `--ask`/`-a` per password custom una-tantum
- Modalità CLI (`rpassword`) e GUI (`kdialog`/`zenity`) con auto-detect TTY
- Completamento tab per bash/zsh/fish generato da `build.rs` e shippato nel `.deb`
- 56 test, build pulita con `-D warnings`

## File del progetto

```
src/
├── lib.rs         # esporta la libreria `aegis` (re-export pubblici)
├── error.rs       # tipo Error unificato
├── key.rs         # Key con auto-zeroize a Drop
├── kdf.rs         # Argon2id wrapper, KdfParams (default_strong + fast_for_tests)
├── aead.rs        # XChaCha20-Poly1305 encrypt/decrypt su buffer
├── stream.rs      # StreamEncoder<W: Write> + StreamDecoder<R: Read> per la STREAM construction
├── header.rs      # parse/serialize header 64-byte con magic BML1, flag, params, salt, nonce prefix
├── file.rs        # API alto-livello: encrypt_file, encrypt_dir, decrypt_file, decrypt_dir, peek_header
├── keyfile.rs     # digest_file (BLAKE2b-256 streaming) + combine(password, digest)
├── cli.rs         # definizione clap di Cli e Cmd (condivisa con build.rs)
├── gui/
│   ├── mod.rs               # facade compile-time-switched via cfg(target_os)
│   ├── backend_linux.rs     # kdialog/zenity
│   └── backend_macos.rs     # osascript / AppleScript
├── keychain.rs    # wrapper sul crate `keyring` (kwallet su Linux, Keychain su macOS)
└── main.rs        # entry point: TTY detection, routing CLI/GUI, dispatch dei subcommand

build.rs           # genera gli script di completion in target/completions/

packaging/
├── aegis.desktop                       # KDE/Dolphin service menu (Linux)
└── macos/
    └── services/
        ├── Aegis - Encrypt.workflow/   # Finder Quick Action
        ├── Aegis - Decrypt.workflow/
        └── Aegis - Info.workflow/

scripts/                                # macOS build helpers
├── build-macos-universal.sh
├── build-pkg.sh
└── build-all-macos.sh

tests/
├── integration.rs          # 14 test su KDF + AEAD primitivi
├── file_streaming.rs       # 22 test su encrypt/decrypt file (sizes, tamper, mode 0600, master flag)
├── folder_encryption.rs    # 11 test su encrypt/decrypt directory + tar streaming
└── keyfile.rs              # 9 test su digest BLAKE2b, combine, round-trip con keyfile

examples/
└── make_test_bml.rs        # genera file .bml di prova in /tmp per smoke testing
```

## Fase per fase

### Fase 0 — Scoping
Discussione iniziale. L'utente chiedeva FDE da zero su ParrotOS. Abbiamo
deciso che l'FDE = LUKS (battle-tested) e che questo progetto si occupa solo
di file/cartelle.

### Fase 1 — Core crypto
Wrapper minimali e testati su:
- **XChaCha20-Poly1305** (`chacha20poly1305` crate): AEAD con nonce a 192 bit
  → safe random nonce, niente problemi di riuso. Constant-time per design.
- **Argon2id** (`argon2` crate): memory-hard, resistente a GPU/ASIC. Due
  profili: `default_strong` per uso reale, `fast_for_tests` (m=8 MiB, t=1, p=1)
  per non bruciare 1s per test.
- Tipo `Key` di 32 byte con `Zeroize + ZeroizeOnDrop` per cancellare la chiave
  dalla memoria al drop.

14 test che coprono round-trip, salt diversi → chiavi diverse, password
diverse → chiavi diverse, tamper di byte/tag/AAD → fallimento di
autenticazione, troncamento, randomness di salt/nonce.

### Fase 2 — Streaming su file con STREAM construction
Per file più grandi di un singolo buffer serve cifrare a chunk. Implementata
la **STREAM construction** (Hoang-Reyhanitabar-Rogaway-Vizár, 2015, usata
anche da `age`):

- Chunk di 64 KiB plaintext + 16 byte di tag = 65552 byte di ciphertext.
- Nonce di ogni chunk: `19B prefix random || 4B counter BE || 1B last-flag`.
  Il prefisso è nell'header, il counter incrementa, l'ultimo chunk ha il bit
  "last" = 1.
- Garanzie: riordino di chunk, troncamento o append di dati extra rompono
  l'autenticazione AEAD.

L'header da 64 byte è passato come **AAD** su OGNI chunk → manomettere
qualsiasi byte dell'header rompe l'autenticazione del primo chunk. Quindi
salt/params/flags sono tutti autenticati senza un MAC separato.

L'API `encrypt_file`/`decrypt_file` scrive su un file temporaneo (`<output>.tmp`
con `O_EXCL` e mode `0600`), fa `fsync`, poi `rename` atomico. `PathGuard` con
`Drop` pulisce il tmp se qualcosa va storto. Mai uno stato half-written.

19 test su round-trip a varie taglie (0 B, 1 B, ±CHUNK_SIZE, 1 MB),
overwrite rifiutato, password sbagliata pulita, header/payload/tag tampered,
chunk swap, troncamento, mode 0600.

### Fase 3 — CLI con TUI WannaCry-style (rimossa)
Inizialmente avevamo una **TUI fullscreen** in ratatui con sfondo rosso, ASCII
del teschio e ciclo di 3 tentativi per decrypt. Era stilosa ma alla fine
l'utente ha preferito la semplicità: ora la CLI è solo `rpassword` con un
prompt una-tantum, nessun retry (riprovi tu con freccia su + invio).

Il file `src/tui.rs` è stato eliminato e la dipendenza `ratatui` rimossa,
dimezzando il binary size pre-keyring.

### Fase 4 — Cifratura cartelle via tar streaming
Per cifrare una directory non vogliamo materializzare un tar in chiaro su
disco (lasciamo tracce su SSD, occupa spazio doppio). Soluzione: refactor di
`stream.rs` per esporre `StreamEncoder<W: Write>` e `StreamDecoder<R: Read>`.
Così possiamo piazzare un `tar::Builder` SOPRA l'encoder e l'output del tar
viene cifrato in-memory man mano che viene generato. Stesso trucco
all'inverso per la decifrazione (un `tar::Archive` sopra il decoder).

Header acquisisce un flag `FLAG_DIRECTORY` (bit 0) per distinguere file da
archivio. La decifrazione directory estrae in `<output>.tmp/` e fa `rename`
solo a successo (atomic-ish — non davvero atomico perché la dir può contenere
N file, ma il vantaggio è che `output` non esiste prima del rename finale,
quindi un fallimento a metà non lascia mezza cartella in giro col nome
finale).

`tar::Archive::set_overwrite(false)` per non clobberare file esistenti
durante l'estrazione, e tar previene già di default i path traversal
attacks (`../`).

11 test su round-trip nested/large/empty-subdir, flag corretto in header,
decrypt_file rifiuta dir e viceversa, output dir non-empty rifiutata, tamper
e password sbagliata su archivio.

### Fase 5 — Prompt GUI (kdialog/zenity) e auto-detect TTY
Il modello "stesso binario, contesti diversi": se sei in un terminale vero
(stdin AND stderr sono TTY) usi `rpassword`/output testuale; altrimenti
(es. lanciato da Dolphin) usi i dialog grafici.

`src/gui.rs` rileva runtime se è disponibile `kdialog` (preferito su KDE) o
`zenity` (fallback) e usa il primo che funziona. Per encrypt usa
`kdialog --newpassword` (dialog singolo con conferma integrata); per decrypt
usa `kdialog --password` in loop fino a 3 tentativi.

Flag globali `--gui` / `--no-gui` per forzare manualmente.

### Fase 6 — Pacchettizzazione .deb
Setup di `cargo-deb` con metadata in `Cargo.toml`:

```toml
[package.metadata.deb]
maintainer = "..."
recommends = "kdialog | zenity"
assets = [
    ["target/release/aegis", "usr/bin/", "755"],
    ...
]
```

`cargo deb` produce `target/debian/aegis_0.1.0-1_amd64.deb` (~1.2 MB).
Installazione: **`sudo dpkg -i target/debian/aegis_0.1.0-1_amd64.deb`**. Su
`apt 3.x` di Parrot/Trixie, `sudo apt install ./...deb` viene rifiutato come
"Unsupported file" → usare `dpkg -i` direttamente.

Per installare `cargo-deb` stesso su Rust 1.85 abbiamo dovuto fare:
```bash
cargo install cargo-deb --version "^2" --locked
```
perché le versioni recenti usano let-chains (stabilizzato in 1.88) e la
risoluzione "fresca" di transitivi rompe contro un `toml` recente che non
implementa più `Display`.

Stesso problema con `rpassword` (pinned a `=7.3.1`) e `keyring` (pinned a
`"2"` invece di v3.x).

### Fase 7 — Rename BitlokerMeglio → Aegis
Decisione di branding. Aegis = scudo di Zeus/Atena nella mitologia greca,
inglese 5 caratteri, vibe "protezione" coerente con il tool.

Rinominati: crate, lib, binary, package Debian. **Mantenuti deliberatamente**:
- Estensione file: `.bml`
- Magic bytes nell'header: `BML1`

Motivo: niente file `.bml` "in giro" da migrare, ma anche niente motivo per
forzare un cambio che richiederebbe gestire compat tra versioni. Se in
futuro vuoi una rinominazione anche di estensione/magic, il codice è
parametrizzato in `header.rs` e basta cambiare due costanti — ma allora
quei file vecchi non si leggono più.

### Fase 8 — Master password nel keyring
La feature "non voglio digitare la pwd ogni volta" risolta nel modo standard
e sicuro:

- `aegis init` salva la master in **kwallet** via il crate `keyring`
  (che parla libsecret D-Bus).
- Nuovo flag header `FLAG_MASTER_KEY` (bit 1) marca i file cifrati con la
  master.
- `aegis encrypt` di default usa la master, niente prompt.
- `aegis encrypt --ask` per pwd custom una-tantum.
- `aegis decrypt` ispeziona il flag: se è master → keyring; se la master non
  c'è / è cambiata / la decifrazione fallisce → fallback automatico a
  prompt. Se il flag non c'è → prompt diretto.
- `aegis decrypt --ask` salta sempre il keyring.

**Trade-off documentato e accettato dall'utente:** chiunque abbia accesso
alla sessione sbloccata può decifrare i file master-flagged senza sapere la
password. È lo stesso modello di Firefox/git/Bitwarden quando sono "logged
in". Comodo per laptop personale tenuto bloccato, NON un sostituto della
disciplina di sicurezza.

**Vincolo importante:** la master vive nel kwallet di QUESTO PC. Se sposti
un .bml su un altro PC dovrai digitare la master a mano via `--ask`. Quindi
sceglila come una pwd vera da ricordare, non come "tanto c'è il keyring".

Esplicitamente **scartato**: usare la password di login Linux direttamente.
`/etc/shadow` ha solo l'hash, non si può "leggere" la pwd indietro. Catturarla
al login richiede PAM hook invasivi (`pam_mount`). Se mai cambi la pwd di
login, i file diventano irrecuperabili. Tutto questo per nulla, visto che
il keyring ottiene lo stesso effetto pratico ("non doverla digitare ogni
volta") in modo molto più pulito.

3 nuovi test sul flag (set/non-set/round-trip).

### Fase 9 — Tab completion
`clap_complete` genera script per bash/zsh/fish a build-time tramite
`build.rs`. La `Cli` di clap è stata estratta in `src/cli.rs` così che sia
`src/main.rs` sia `build.rs` la possano importare (il secondo via
`#[path = "src/cli.rs"] mod cli;`).

`build.rs` scrive i file in `target/completions/`. `Cargo.toml` li
referenzia negli `assets` del .deb e li installa ai path standard Debian:
- `/usr/share/bash-completion/completions/aegis`
- `/usr/share/zsh/vendor-completions/_aegis`
- `/usr/share/fish/vendor_completions.d/aegis.fish`

Queste directory sono auto-loaded dalle rispettive shell senza che l'utente
debba aggiungere niente a `~/.bashrc`/`~/.zshrc`. La shell carica il
completer la prima volta che digiti `aegis` e premi tab.

In più c'è un subcommand nascosto `aegis completions <shell>` per generare
gli script al volo (per shell esotiche o per installare in `~/.local/...`).

## Decisioni che potrebbero sorprendere e perché

**Perché XChaCha20-Poly1305 e non AES-GCM?**
XChaCha20 ha un nonce di 192 bit → posso usare nonce random a 24 byte senza
preoccuparmi di collisioni (il birthday bound è a 2^96, irraggiungibile).
AES-GCM ha nonce a 96 bit → con 2^32 cifrature stesso key cominciano i
problemi. XChaCha20 è anche più veloce su CPU senza AES-NI e constant-time
per design (no cache-timing attacks).

**Perché STREAM e non un singolo grande AEAD?**
Un AEAD su un buffer richiede di tenere tutto in memoria. STREAM lavora a
chunk → file da 5 GB cifrati con 64 KiB di buffer. Più: STREAM autentica
l'ordine dei chunk (no chunk reorder attack) e la fine dello stream (no
truncation attack) — un singolo AEAD sull'intero file non protegge da
questi se l'attacker può alterare il file dopo la cifratura.

**Perché Argon2id e non bcrypt/scrypt/PBKDF2?**
Argon2id ha vinto la Password Hashing Competition (2015). È memory-hard
(costa GiB di RAM per derivazione) → un attacker con GPU/ASIC ha un cost
ratio molto più alto rispetto a PBKDF2. È sia ID che D resistente, quindi
contro side-channel + tempo.

**Perché il keyring per la master e non un file di config?**
Un file `~/.config/aegis/master` con la pwd in chiaro è ovviamente no.
Cifrarlo richiederebbe... un'altra pwd per decifrarlo, e siamo punto a capo.
Hashed-then-stored non funziona perché Argon2id non è reversibile, e tu hai
bisogno della pwd plaintext per cifrare. Il keyring di sistema risolve:
storage cifrato + decifrazione automatica al login + standard
(libsecret/kwallet/gnome-keyring sono UNA api per tutti i DE).

**Perché tar e non zip per le cartelle?**
Tar è streaming-friendly: produce output byte-per-byte da un input
filesystem, senza dover prima costruire un index. Zip ha un central
directory in fondo che richiede seek (per scrivere e per leggere). Su
streaming AEAD lo zip non si presta.

**Perché niente compressione prima della cifratura?**
CRIME/BREACH-style attacks: se il plaintext include dati controllati
dall'attacker E un segreto, la compressione + cifratura insieme può leakare
il segreto via length-side-channel. Sicuro NON comprimere. Tu puoi
gzippare prima esternamente se vuoi, ma il tool non lo fa di default.

**Perché il binary è 3.9 MB?**
Il crate `keyring` tira dentro `zbus` (D-Bus async runtime) e
`secret-service` che da soli pesano. È il prezzo del "salva la pwd dove la
sblocca il DE". Pre-keyring il binary era 1.1 MB. Acceptable per un tool
personale; se ti rode si possono sostituire con un client D-Bus minimale a
mano.

## Quirks della toolchain Rust 1.85

Su distro-Rust (no rustup, no clippy), molti crate recenti rompono perché
usano `let`-chains stabilizzati in 1.88. Workaround applicati:

- `rpassword = "=7.3.1"` (pin)
- `keyring = "2"` (non v3.x)
- `cargo install cargo-deb --version "^2" --locked` (anche il `--locked`
  serve, perché senza, transitive deps drift a un `toml` che non implementa
  più `Display` e cargo-deb 2.x non compila)

Quando aggiorni Rust questi pin si possono rilassare.

### Fase 14 — Porting macOS (Universal Binary + .pkg)

Estensione di Aegis a macOS mantenendo Linux pienamente supportato.
Scope: CLI + GUI nativi su macOS, distribuzione via `.pkg`, niente App
Store, niente code-signing (utenti accettano warning Gatekeeper al primo
lancio).

**Refactor `src/gui.rs` → directory module:**
- `src/gui/mod.rs` — facade compile-time-switched via `cfg(target_os)`
- `src/gui/backend_linux.rs` — codice esistente (kdialog/zenity)
- `src/gui/backend_macos.rs` — nuovo (osascript / AppleScript)

Selezione del backend è a compile time, quindi binary Linux NON include
codice macOS e viceversa. Build Linux completamente insensibile al
refactor (56/56 test verde, .deb dimensione invariata).

**Backend macOS via `osascript`:** AppleScript ships con macOS, zero
dipendenze nuove. Per ogni dialog Aegis genera uno script AppleScript
come stringa e lo pipa via stdin di `osascript -` (evita escaping di
shell sui parametri). Le primitive usate:

- `display dialog ... default answer "" with hidden answer` → prompt
  password (campo nascosto). Per "new password" eseguo due dialog (uno
  per "set", uno per "confirm") e confronto i risultati. Identico
  pattern di zenity su Linux.
- `display alert ... as critical|informational` → show_error / show_info
- `display dialog ... buttons {"No","Yes"} default button "Yes"` →
  confirm (yesno). Cancel raises error -128 che cattusisco e mappo a No.
- `choose from list {...} default items {...}` → radio menu. Mostra
  i LABEL all'utente, mappo dal label scelto al tag tramite la lookup
  table passata. Funziona per i menu a 2 e a 4 voci di Fase 12+13.
- `choose file with prompt ... default location (POSIX file ...)` →
  file picker. Restituisce `POSIX path` del file scelto.

L'escape AppleScript è gestito da `as_quoted()` che fa `"` → `\\"` e
`\` → `\\\\`. Sicuro su path con quote/backslash, accenti, spazi.

**`keyfile_start_dir()` cfg-based:**
- Linux: `/media` se esiste, fallback `$HOME`
- macOS: `/Volumes` se esiste, fallback `$HOME`

**Build scripts macOS** (`scripts/`):
- `build-macos-universal.sh` — `rustup target add` per Apple Silicon
  e Intel, build per entrambi i target, `lipo -create` per fondere in
  un solo Mach-O fat binary (~8 MB). Verifica finale con `file(1)`.
- `build-pkg.sh` — staging dir + `pkgbuild`. Identifier
  `ch.c41.aegis`. Installa:
  - `usr/local/bin/aegis` (universal binary)
  - `Library/Services/Aegis - Encrypt.workflow`
  - `Library/Services/Aegis - Decrypt.workflow`
  - `Library/Services/Aegis - Info.workflow`
- `build-all-macos.sh` — wrapper che fa entrambi in sequenza.

**Quick Actions Finder** (in `packaging/macos/services/`):
Tre `.workflow` bundle (= directory con `Contents/document.wflow`).
Il `document.wflow` è un plist XML in cui le chiavi critiche sono:

- `workflowTypeIdentifier` = `com.apple.Automator.servicesMenu`
- `serviceInputTypeIdentifier` = `com.apple.Automator.fileSystemObject`
  (riceve sia file sia directory)
- `serviceApplicationBundleID` = `com.apple.finder`
  (limita l'azione al menu di Finder; rimuoverla la mostra in tutte le
  app che producono fileSystemObject — Mail, TextEdit ecc.)
- `inputMethod` = 1 (passa i path come `$@` allo shell script)
- `COMMAND_STRING` = `for f in "$@"; do /usr/local/bin/aegis --gui {encrypt|decrypt|info} "$f"; done`

I tre file differiscono SOLO per la subcommand `encrypt`/`decrypt`/`info`.
Identica struttura, copiata tre volte. Volutamente NO action separata
"Encrypt and keep" — Fase 11 ha già il confirmation dialog sufficiente.

**Distribuzione `.pkg`:**
- `pkgbuild` (ships con macOS, no Xcode richiesto) costruisce il pkg
  da uno staging directory
- Output: `target/macos/aegis-0.1.0-universal.pkg`, ~5 MB
- Installazione: doppio-click → Apple Installer Wizard → password admin
  → fatto
- Prima del primo lancio dei comandi/quick action, l'utente potrebbe
  dover fare destro → Apri per bypassare Gatekeeper (no signing).
  Una sola volta. Volontariamente accettato come trade-off per non
  pagare $99/anno Apple Developer.

**Cosa funziona out-of-the-box su macOS senza codice nuovo:**
- `keyring` crate v2 → Keychain Services / login keychain (vedi
  Decisione: l'`aegis init` salva nel **login** keychain corrente,
  unlock automatico al login Mac, comportamento simmetrico a kwallet
  su Linux)
- `chacha20poly1305`, `argon2`, `blake2`, `zeroize`, `getrandom`,
  `clap`, `rpassword`, `tar` → tutte pure Rust, cross-platform
- `OpenOptionsExt::mode(0o600)` → BSD-equivalent su macOS, funziona
- `rpassword` → legge da `/dev/tty`, funziona
- Tutti i 47 (file/dir/integration) + 9 (keyfile) test della libreria

**Cosa NON è ancora testato** (verifica quando si compila sul Mac):
- AppleScript edge cases con caratteri Unicode strani nei path/body
- Performance del file picker macOS su NFS / iCloud Drive
- Comportamento Keychain quando il keychain è bloccato (richiede
  unlock interattivo via dialog di sistema — `keyring` crate lo
  gestisce ma UX non testata)

**Lavoro escluso volontariamente** (out of scope per questa fase):
- Code signing (Apple Developer Program $99/anno)
- Notarization (richiede signing)
- App bundle `.app` (Aegis è CLI + integration, non una GUI app standalone)
- Windows (deciso a parte, non vale lo sforzo per ora)

### Fase 13 — Keyfile opzionale (chiavetta USB)

Aggiunta di un secondo fattore di cifratura: un file qualunque (tipicamente
su chiavetta USB) la cui presenza è necessaria per decifrare i `.bml`
flaggati. Il keyfile è **opt-in**: il default (`aegis encrypt foo.pdf`)
resta master nel keyring, niente keyfile.

**Combinazione cripto:** `BLAKE2b-256` streaming sul keyfile → digest a
32 byte → concatenato dopo la password → Argon2id sul tutto. Stessi
parametri Argon2id di prima (m=256 MiB, t=3, p=4). Nessun cambio a
XChaCha20-Poly1305 / STREAM. Backwards-compat totale: senza keyfile la
concatenazione degenera in `password.to_vec()` byte-per-byte, quindi i
`.bml` vecchi continuano a decifrare con la stessa chiave.

**Perché concatenazione e non HKDF:** Argon2id è memory-hard sull'input
intero, e BLAKE2b-256 produce un digest a lunghezza fissa, quindi non
c'è ambiguità su dove finisce la password e inizia il keyfile (no
length-extension funny business). Pattern standard usato da
VeraCrypt/KeePass.

**Nuovo flag header:** `FLAG_KEYFILE = 0b0000_0100` (bit 2). I bit erano
già riservati nel formato 64-byte, zero cambio al layout. La path del
keyfile **non** è salvata nell'header (zero info leak — l'utente sa
quale chiavetta serve).

**CLI:**
- `aegis encrypt --keyfile <path>` (short `-K`, maiuscolo per non
  confondere con `-k`/keep)
- `aegis decrypt --keyfile <path>`
- `aegis keyfile-gen --output <path> [--size N]` (default 64 byte da
  `getrandom`, mode 0600, rifiuta sovrascrittura)

**Matrice di comportamento decrypt:**
| Header flag | `--keyfile` passato? | Comportamento |
|-------------|----------------------|---------------|
| 0 | no | come oggi |
| 0 | sì | **errore esplicito** "this file was not encrypted with a keyfile" |
| 1 | no | errore "this file requires --keyfile" in CLI; **file picker** in GUI |
| 1 | sì | OK |

**GUI encrypt — radio a 4 voci:** estensione del menu master/custom di
Fase 12. Le voci ora sono:

- Master password (dal keyring) — default
- Master password + keyfile
- Custom password
- Custom password + keyfile

Se l'utente sceglie una voce "+ keyfile" → parte `kdialog
--getopenfilename` (o `zenity --file-selection`) con `start_dir = /media`
se esiste (per intercettare chiavette montate), altrimenti `$HOME`.
Cancel del picker = errore "cancelled by user".

I flag CLI (`--ask`, `--keyfile`) **pre-decidono** le scelte: se uno è
passato, il menu salta la domanda corrispondente. Se entrambi passati →
no menu (full CLI control in GUI mode).

**GUI decrypt:** se header dice FLAG_KEYFILE=1 e non c'è `--keyfile`,
parte `gui::show_info` con avviso + `pick_file` per scegliere il
keyfile, prima del prompt password. Il digest è calcolato una volta sola
e riusato in tutti i 3 path di decifrazione (master, CLI prompt, GUI
prompt) tramite parametro `keyfile_digest: Option<&[u8; 32]>`.

**Helper `aegis keyfile-gen`:** subcommand dedicato. Default 64 byte
da `getrandom` (più che sufficiente, 512 bit di entropia), cap a 1 MiB
per evitare uso accidentale come "salva qui questo file enorme". Mode
0600. Refuse-to-overwrite. Stampa avviso "Keep it safe — losing it
means losing access" (intenzionale: ricorda all'utente che la perdita
del keyfile = file irrecuperabili).

**`aegis info`:** nuova riga `Keyfile required: yes/no` letta dal flag
header. Utile per capire "se questo `.bml` mi è stato mandato, mi
servirà anche un file?".

**Test nuovi (9):** in `tests/keyfile.rs` — `combine` con e senza
digest, `digest_file` deterministico / differente su contenuti diversi /
gestisce file vuoto / stabile su chiamate ripetute, round-trip con
keyfile, decrypt con keyfile sbagliato (Aead error), decrypt con
password sbagliata su keyfile giusto (Aead error). Per testare la
parte CLI ho dovuto spostare `keyfile.rs` da `src/main.rs` (modulo del
binary) a `src/lib.rs` (modulo della libreria) — è solo cripto pura
quindi è naturale che viva nella lib comunque.

**Refactor:** `decide_encrypt_options(gui_mode, ask, keyfile_cli, kind,
input_display)` centralizza tutta la decisione master/custom + keyfile
in una funzione separata. Vale tre rami CLI flag-only / GUI sub-menu /
GUI full-menu, ma è leggibile top-to-bottom.

### Fase 12 — Scelta master/custom in GUI + UX file ricevuti

Due aggiunte legate al caso "ricevo un `.bml` da un'altra persona":

**1. Menu radio in GUI per encrypt.** Quando l'utente lancia
`aegis encrypt foo.pdf` da Dolphin / GUI senza `-a`, prima parte un
`kdialog --radiolist` (o `zenity --list --radiolist`) con due voci:

- *"Your master password (from the keyring)"* — preselezionato
- *"A custom password (one-off, for sharing)"*

L'utente può decidere a runtime senza dover ricordare il flag. Il
risultato del menu è una `effective_ask: bool` che sostituisce
internamente il flag `-a`. Se il menu è cancellato → errore "cancelled
by user". Se il keyring non ha una master configurata → niente menu,
si va direttamente al path custom (più utile dell'errore "no master
set; run init" che si vede solo in CLI). Helper nuovo
`gui::choose_radio(title, body, items: &[(tag, label, default)])`.

In CLI il comportamento è invariato: il flag `-a` resta l'unico modo
di scegliere il path custom. Niente menu interattivo CLI per ora —
chi è in terminale può semplicemente scrivere `-a`.

**2. Prompt decrypt che chiarisce file ricevuti.** Quando si decifra
un `.bml` con `FLAG_MASTER_KEY=1` ma il keyring locale non ha una
master che funziona (perché non c'è, o è un'altra, o AEAD fallisce),
il fall-through al prompt password mostra un body specifico:

> This file was encrypted with the sender's MASTER password.
> Your local keyring doesn't have a master that decrypts it.
> Enter the sender's master password:

Sia in GUI (`kdialog --password`) sia in CLI (stderr line prima di
`rpassword`). Distingue chiaramente "password che dovevi sapere"
(master di chi te l'ha mandato) da "password una-tantum che ti hanno
detto" (custom). Per implementarlo `was_master` è ora passato anche a
`decrypt_gui_prompt` / `decrypt_cli_prompt`.

**Anti-pattern documentato:** per file destinati alla condivisione la
strada giusta è `aegis encrypt --ask` (oppure scegliere "Custom
password" nel menu): il `.bml` risultante ha `FLAG_MASTER_KEY=0`,
quindi su qualsiasi macchina destinataria Aegis salta direttamente al
prompt senza tentare il keyring locale, e la password si comunica
out-of-band (Signal, telefonata).

### Fase 11 — Cancellazione dell'originale (default)

Cambio di default **simmetrico** su `encrypt` e `decrypt`: dopo
un'operazione riuscita l'input "vecchio formato" viene rimosso.

- Dopo `encrypt`: l'originale in chiaro viene cancellato.
- Dopo `decrypt`: il `.bml` cifrato viene cancellato.

Per mantenerlo in entrambi i casi: `--keep` / `-k`.

In modalità interattiva c'è sempre una conferma esplicita prima della
cancellazione:

- **CLI con TTY:** prompt `Delete original foo.pdf? [Y/n] ` (default Yes,
  accetta `y/yes/s/si/sì` e stringa vuota come conferma).
- **GUI (kdialog/zenity):** `--yesno` con titolo "Aegis" e testo che
  include path + size (per le directory anche numero file).
- **Headless reale** (no TTY E nessun backend GUI disponibile): cancella
  senza chiedere, coerente col default dichiarato. Caso pensato per
  automazione / cron — chi vuole esplicitamente mantenere l'originale
  in quel contesto passa `--keep`.

Per le **directory** il prompt di `encrypt` è più informativo: include
conteggio file e dimensione totale (helper `dir_summary` + `human_bytes`
in `main.rs`). Volutamente NON c'è type-to-confirm: l'attrito è già nel
messaggio. Per `decrypt` non serve l'analogo: l'input è sempre un singolo
`.bml`, anche quando l'output è una directory (il tar streaming è
incapsulato nel `.bml` stesso).

**Refactor lato codice (decrypt):** la cancellazione del `.bml` deve
avvenire indipendentemente da quale dei tre path di decifrazione abbia
avuto successo (master via keyring, prompt CLI, prompt GUI a 3
tentativi). Soluzione: ognuno dei sotto-path ora ritorna `Ok(())` in
silenzio (niente più `println!`/`show_info` interni), e `cmd_decrypt`
chiama un unico `finish_decrypt(...)` finale che decide se cancellare e
stampa il messaggio. Niente duplicazione, comportamento garantito
uniforme.

**Helper estratto:** `confirm_destruction(gui_mode, gui_body, cli_prompt)`
centralizza la logica "dialog vs CLI Y/n vs headless = sì". Usato da
`maybe_delete_after_encrypt` e `maybe_delete_after_decrypt`.

**Note importanti sulla sicurezza:**

- È un `std::fs::remove_file` / `remove_dir_all` normale, **non** shred.
  Su SSD i dati restano forensicamente recuperabili finché il garbage
  collector del controller non riusa le celle NAND (può richiedere
  giorni o settimane). Su HDD `unlink` non sovrascrive i settori,
  quindi anche lì sono recuperabili con strumenti standard.
- Per cancellazione "vera" servirebbe un secure-erase del disco (LUKS+
  discard al deprovisioning, oppure dischi self-encrypting con crypto
  erase). Aegis non ha pretese in questo senso.
- Se encrypt **fallisce** in qualsiasi punto, l'originale NON viene mai
  toccato. Garantito dal fatto che la cancellazione avviene solo nel
  ramo `Ok(())` di `do_encrypt(...)`. Idem se il rename atomico del
  `.tmp` fallisce — `PathGuard` pulisce solo il tmp.
- Se encrypt riesce ma `remove_file` fallisce (es. permessi cambiati
  in mezzo, FS read-only), il messaggio finale rende esplicito che
  l'originale è ancora lì.

**Service menu di Dolphin:** beneficia "gratis" del nuovo default —
tasto destro → Encrypt → (Argon2 ~1s) → dialog di conferma cancellazione
→ Yes/No. Non sono state aggiunte azioni separate per "Encrypt and keep"
nel `.desktop`: chi vuole quel flow usa il CLI con `-k`.

### Fase 10 — Service menu di Dolphin

Integrazione col file manager KDE in modo che tasto destro su un file
qualunque mostri `Aegis ▸ Encrypt / Decrypt / Show header info`.

Implementazione scelta (volutamente minimale per v1):

- **Un solo file** `packaging/aegis.desktop`, installato in
  `/usr/share/kio/servicemenus/aegis.desktop` via `cargo deb`.
- `Type=Service` + `ServiceTypes=KonqPopupMenu/Plugin` per compat sia con
  Plasma 5 sia con Plasma 6 (Plasma 6 ignora `ServiceTypes` e legge
  direttamente `MimeType`/`Actions`).
- `MimeType=all/all;inode/directory;` → l'azione appare su file e cartelle.
  Volutamente NON filtra solo `.bml` per Decrypt/Info: l'utente vede tre
  voci sempre e sceglie. Filtrare richiedeva registrare un MIME custom
  `application/x-aegis-bml` con XML in `/usr/share/mime/packages/` + un
  `update-mime-database` in postinst — complessità rimandata.
- `X-KDE-Submenu=Aegis` raggruppa le tre azioni sotto un submenu unico
  invece di sporcare il top-level del context menu.
- Icone freedesktop stock (`document-encrypt`, `document-decrypt`,
  `dialog-information`) — niente icona custom da shippare.
- `Exec=aegis --gui {encrypt|decrypt|info} %f`. Il `--gui` è
  belt-and-suspenders: gui_mode si auto-attiva già perché Dolphin lancia
  senza TTY, ma esplicitare l'intento è più robusto. `%f` (single file)
  significa che multi-select da Dolphin non funziona per v1 — limite
  accettato.
- Localizzazione `Name[it]` per i tre nomi.

**Refactor lato codice:** `cmd_info` accettava implicitamente uno stdout
visibile (faceva `println!`). Sotto Dolphin non c'è terminale → output
perso. Aggiunto parametro `gui_mode` e branch che compone una stringa
unica e la passa a `gui::show_info` (kdialog `--msgbox`/zenity `--info`).

**Decisioni scartate / da riconsiderare:**
- Registrare il MIME `application/x-aegis-bml` per avere doppio-click =
  apri-con-Aegis. Richiede file XML + postinst. Lo si fa quando serve.
- Notifiche via `notify-send` dopo encrypt/decrypt riusciti. Oggi
  riusiamo `gui::show_info` che è un dialog modale: meno discreto di
  una notifica D-Bus ma già implementato e zero dipendenze nuove.
- Azione "Encrypt and shred" (dipende dalla feature `--shred` ancora da
  scrivere).
- Multi-select (`%F` con shell loop). Complica l'Exec e l'UX dei
  prompt password; rimandato a quando serve davvero.

## Cose ancora aperte (roadmap implicita)

- **Multi-select da Dolphin:** wrappare l'`Exec` con un loop shell
  (`sh -c 'for f in "$@"; do aegis --gui encrypt "$f"; done' _ %F`)
  per permettere di cifrare più file in batch dal context menu.
- **Registrazione MIME `.bml`:** XML in `/usr/share/mime/packages/` +
  `update-mime-database` in postinst, così Dolphin riconosce `.bml`
  come tipo proprio e si può limitare Decrypt/Info solo a quel MIME.
- **Keyfile:** flag `--keyfile <path>` per derivare la chiave da pwd + file
  esterno (es. chiavetta USB). Per file critici servirebbero entrambi.
- **Secure shred opzionale:** flag `--shred` (separato da `--keep`) che
  sovrascrive prima di unlink. Utile su HDD; documentare esplicitamente
  che su SSD è teatro (wear-leveling). Non è priorità — Fase 11 copre
  già il caso d'uso comune ("non voglio l'originale in giro").
- **Rotate master:** quando cambi la master, oggi i file vecchi non sono
  più decifrabili dal keyring. Una feature "rotate" che ri-cifra tutti i
  `.bml` di una cartella sarebbe utile.

## Come riprodurre tutto da zero

```bash
# 1. clona o ricrea la directory progetto
cargo new --name aegis aegis
cd aegis

# 2. installa cargo-deb (versione vincolata)
cargo install cargo-deb --version "^2" --locked

# 3. build + test
cargo build --release
cargo test

# 4. pacchetto .deb
cargo deb
# output: target/debian/aegis_0.1.0-1_amd64.deb

# 5. installa
sudo dpkg -i target/debian/aegis_0.1.0-1_amd64.deb

# 6. setup
aegis init

# 7. usa
aegis encrypt foo.pdf
aegis decrypt foo.pdf.bml
aegis info foo.pdf.bml
```
