# PassM3nage

**PassM3nage** is a portable, offline, terminal-based password manager built for local use.

No cloud, no telemetry, no network services, and no background daemons.

## Download

Get the latest release assets from GitHub Releases:

- Windows x64: `passm3nage-windows-x64.zip`
- Linux x64: `passm3nage-linux-x64.tar.gz`
- macOS Intel: `passm3nage-macos-intel.tar.gz`
- macOS Apple Silicon: `passm3nage-macos-arm.tar.gz`

Unpack the archive and run the executable:

- Windows: `passm3nage.exe`
- Linux/macOS: `./passm3nage`

Show version:

```bash
passm3nage --version
```

Show help:

```bash
passm3nage --help
```

## Highlights

## Eseguire il programma (per Sistema Operativo)

### Windows

- Estrai `passm3nage-windows-x64.zip` con Esplora risorse.
- Esegui con un doppio click su `passm3nage.exe` oppure apri PowerShell nella cartella e lancia:

```powershell
.\passm3nage.exe
```

### Linux

- Estrai l'archivio `passm3nage-linux-x64.tar.gz`:

```bash
tar -xzf passm3nage-linux-x64.tar.gz
```

- Rendi eseguibile il binario (se necessario) e avvialo:

```bash
chmod +x passm3nage
./passm3nage
```

### macOS (Intel / Apple Silicon)

- Estrai l'archivio corrispondente (`passm3nage-macos-intel.tar.gz` o `passm3nage-macos-arm.tar.gz`):

```bash
tar -xzf passm3nage-macos-intel.tar.gz
# oppure per ARM: tar -xzf passm3nage-macos-arm.tar.gz
```

- Rendi eseguibile e avvia:

```bash
chmod +x passm3nage
./passm3nage
```

- Nota (Gatekeeper): se macOS blocca l'esecuzione, apri Finder, Ctrl+clic sull'app e scegli "Apri" per autorizzare. In alternativa, da Terminale puoi rimuovere la quarantine così:

```bash
xattr -d com.apple.quarantine ./passm3nage
```

Queste istruzioni presuppongono che tu abbia scaricato e decompresso l'archivio nella cartella in cui vuoi eseguire l'applicazione.

- **Offline by design**: no cloud, no networking, no telemetry.
- **Portable**: runs as a local terminal app and stores vault files beside the executable.
- **Rust + TUI**: built with `ratatui` and `crossterm` for a lightweight terminal interface.
- **Encrypted records**: usernames and passwords are encrypted before being written to `vault.json`.
- **User-seeded encryption**: the initial password plus the random salt in `tech.json` derives the key used to encrypt and decrypt vault records.
- **Startup password**: first launch creates a protected `tech.json` login check.
- **Search-first workflow**: filter services, reveal credentials, edit entries, or delete records from one screen.
- **Bypass detection**: if a protected vault exists but `tech.json` is missing, the app stops with a recovery-risk warning.
- **Encrypted backups**: copy `vault.json` to a user-selected local directory without decrypting its contents.

## What It Does

PassM3nage currently supports:

- Creating an initial login password.
- Adding service credentials.
- Detecting duplicate service names.
- Overwriting existing credentials or saving numbered copies such as `github1`, `github2`.
- Searching by service name.
- Viewing a selected password.
- Editing username/password after re-entering the login password.
- Deleting a selected credential after confirmation.
- Creating an encrypted local backup copy of `vault.json`.
- Restoring an encrypted backup into `vault.json`.
- Showing a runtime status bar with saved password count and `OK`/`ERROR` state.

## Build from source

If you want to build PassM3nage from source, first install Rust and Cargo.

Then build the release binary:

```bash
cargo build --release
```

Run the app locally:

```bash
cargo run
```

Or launch the compiled binary:

```bash
./target/release/passm3nage
```

On Windows:

```powershell
.\target\release\passm3nage.exe
```

On first launch, PassM3nage asks you to create an initial password. The password must contain:

- at least 8 characters
- at least 1 number
- at least 1 special symbol

Press `Tab` on the login/setup screen to show or hide the password while typing.

## Files Created

PassM3nage stores its local state in:

- `tech.json`: encrypted login-password check and random salt used for key derivation
- `vault.json`: encrypted credential records and vault metadata

New vault files include a `log: true` flag. If `vault.json` has `log: true` but `tech.json` is missing, PassM3nage blocks startup with:

```text
secury recovery risk
```

The user can then:

- press `1` to exit
- press `2` to destroy saved passwords and start again

## TUI Controls

### Login / Setup

| Key | Action |
| --- | --- |
| `Tab` | Show/hide password |
| `Enter` | Confirm |
| `Backspace` | Delete character |
| `Esc` | Exit |

### Main Menu

| Key | Action |
| --- | --- |
| `A` | Add entry |
| `S` | Search password |
| `B` | Backup encrypted vault |
| `U` | Upload/restore backup |
| `Q` / `Esc` | Quit |

The status bar shows:

```text
Passwords saved: N | Program status: OK | OK
```

If the latest save/load/runtime operation fails, it shows `ERROR` with a short reason.

### Add Entry

| Key | Action |
| --- | --- |
| `Tab` | Next field |
| `Enter` | Confirm field / save on final field |
| `Esc` | Cancel |

If the service already exists:

- `Y` overwrites the existing entry.
- `N` opens a second prompt.
- In the second prompt, `Y` saves a numbered copy like `lua1`, `lua2`, `lua3`.
- `N` or `Esc` cancels.

### Backup

Choose `B` from the main menu, type a destination directory, and press `Enter`.

PassM3nage copies the encrypted vault to:

```text
vault.backup.json
```

The backup is still encrypted. If someone copies that file without the user's login password and matching `tech.json` salt, usernames and passwords remain unreadable ciphertext.

### Upload Backup

Choose `U` from the main menu, type the full path to an encrypted backup file, and press `Enter`.

PassM3nage copies that file back into `vault.json` and immediately tries to decrypt it with the current login password and `tech.json` salt. If the backup does not belong to the current user/password context, the status bar reports `ERROR`.

### Search

Start typing a service name to filter results.

| Key | Action |
| --- | --- |
| `Tab` / `Enter` | Move from search field to results |
| `W` | Move up |
| `S` | Move down |
| `Enter` | Show selected password |
| `E` | Edit selected username/password |
| `C` | Delete selected entry |
| `Esc` | Back to main menu |

Editing requires re-entering the initial login password in a centered popup before username/password fields can be changed.

## Security Model

PassM3nage is intentionally narrow:

- It protects against someone reading the vault file offline.
- It does not protect against malware, keyloggers, screen capture, or an already-compromised operating system.
- It does not use cloud sync, browser integration, or network requests.

Cryptographic building blocks:

- **Argon2id** for password-based key derivation.
- **XChaCha20-Poly1305** for authenticated encryption.
- **libsodium / sodiumoxide** as the crypto backend.
- **serde_json** for the current on-disk prototype format.

The user password is never stored directly. On setup, PassM3nage generates a random salt and stores it in `tech.json`; that salt plus the password derives the encryption key for vault records. Older vaults encrypted with the previous fixed-salt prototype are migrated automatically after a successful login.

For deeper details, see:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [SECURITY.md](SECURITY.md)
- [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)

## Tech Stack

- Rust 2021
- `ratatui`
- `crossterm`
- `sodiumoxide`
- `serde` / `serde_json`
- `secrecy`
- `zeroize`

## Development

Build:

```bash
cargo build
```

Run:

```bash
cargo run
```

Format:

```bash
cargo fmt
```

Check:

```bash
cargo check
```

Test:

```bash
cargo test --all
```

## Roadmap

Near-term improvements:

- Replace prototype JSON storage with a stricter binary vault format.
- Improve password masking and input handling across terminals.
- Add stronger tests for TUI state transitions.
- Add atomic writes for all vault updates.
- Add a proper password-change flow.
- Add export/import safeguards.

## Non-Goals

PassM3nage is not trying to be:

- a cloud password manager
- a browser extension
- a shared/team vault
- a mobile app
- a background daemon
- a replacement for host OS security

## Disclaimer

This is an early-stage security project. Do not store irreplaceable production passwords in it yet.

Use strong passwords, keep backups, and only run password-management tools on computers you trust.

## License

Dual-licensed under MIT or Apache 2.0.
