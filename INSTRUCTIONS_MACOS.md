# Aegis — istruzioni primo build su macOS

Questo file è la guida rapida per quando arrivi sul Mac con la cartella
copiata dal Linux di sviluppo. Segui in ordine.

## 1. Prerequisiti (una sola volta per Mac)

Apri Terminale e installa:

```bash
# Xcode Command Line Tools (compilatore C, lipo, pkgbuild)
xcode-select --install
```

Una finestra grafica chiederà di installare. Premi Install e aspetta
(~5-10 minuti la prima volta).

```bash
# Rust (rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Segui le istruzioni a schermo (default `1`). Alla fine apri un nuovo
terminale (oppure `source "$HOME/.cargo/env"`) e verifica:

```bash
cargo --version
rustc --version
```

## 2. Compila + crea il .pkg

Dalla cartella del progetto (quella che hai copiato dal Linux):

```bash
bash scripts/build-all-macos.sh
```

Lo script fa in sequenza:
1. `rustup target add aarch64-apple-darwin x86_64-apple-darwin` (prima volta)
2. `cargo build --release` per Apple Silicon
3. `cargo build --release` per Intel
4. `lipo -create ...` per il binary universale
5. `pkgbuild` per il `.pkg`

Tempo totale al primo giro: ~5-10 minuti (rust compila tutte le dipendenze).
Successivi: ~1-2 minuti (cache).

Risultato: `target/macos/aegis-0.1.0-universal.pkg`.

## 3. Installa

Doppio-click sul `.pkg` in Finder, oppure da terminale:

```bash
sudo installer -pkg target/macos/aegis-0.1.0-universal.pkg -target /
```

**Warning Gatekeeper al primo lancio.** Il `.pkg` non è firmato (non
abbiamo cert Apple Developer). macOS dirà "this package can't be
verified". Workaround:

1. Tasto destro sul `.pkg` in Finder → **Apri**
2. Conferma con **Apri** nel dialog
3. Inserisci password admin
4. Una sola volta per .pkg

Da terminale invece il warning non c'è, è specifico del Finder.

## 4. Primo setup di Aegis

```bash
# Setta la master password (verrà salvata nel Keychain)
aegis init

# Verifica
aegis status
```

Test rapido:

```bash
echo "ciao" > /tmp/test.txt
aegis encrypt /tmp/test.txt
ls -l /tmp/test.txt /tmp/test.txt.bml   # originale rimosso (con conferma), bml creato
aegis decrypt /tmp/test.txt.bml
cat /tmp/test.txt                        # "ciao"
```

## 5. Quick Actions in Finder

Dovrebbero essere già visibili al primo log-in dopo l'install. Se non
appaiono:

```bash
/System/Library/CoreServices/pbs -update
```

Oppure log-out + log-in.

Test: in Finder, tasto destro su un file qualunque dentro `~/Documenti`
→ menu **Quick Actions** (o **Services** su macOS più vecchi) → trovi
`Aegis - Protect`, `Aegis - Protect with photo`, `Aegis - Protect to share`,
`Aegis - Protect (menu)`, `Aegis - Open`, `Aegis - Info`.

(Le due voci "Protect…" separate e la singola "Protect (menu)" sono due
versioni alternative dello stesso flusso: provale e teniamo quella che
preferisci.)

## 6. Cosa fare se qualcosa non compila

Su macOS specifico, alcuni potenziali punti di rottura:

- **Errore `osascript: command not found`**: improbabile (ships con macOS),
  ma verifica che `/usr/bin/osascript` esista
- **Errore di link in `cargo build`**: di solito mancano gli Xcode CLT.
  Ripeti `xcode-select --install`
- **`keyring` crate fallisce alla build**: dovrebbe scaricare e compilare
  `security-framework` automaticamente. Se fallisce, dimmi l'errore
- **Quick Actions non appaiono**: prova `pbs -update`, poi log-out/in.
  Se ancora no, controlla che `/Library/Services/Aegis - Encrypt.workflow`
  esista come directory

## 7. Disinstalla

```bash
sudo rm /usr/local/bin/aegis
sudo rm -rf "/Library/Services/Aegis - "*.workflow
aegis forget   # opzionale, rimuove la master dal Keychain (ma 'aegis' sarà già stato cancellato!)
                # quindi se vuoi farlo, esegui PRIMA del rm /usr/local/bin/aegis
```

---

In caso di qualsiasi errore, copia il messaggio e mandalo via — itero
sul Linux di sviluppo e ti rifornisco una versione aggiornata della
cartella.
