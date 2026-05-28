# HOW PassM3nage

## Overview

PassM3nage is an offline, portable password manager written in Rust. It is designed to run in a local terminal without cloud services, network access, browser extensions, or telemetry. The project manages an encrypted vault of credentials and provides secure encrypted file backup and restore.

## What it does

PassM3nage supports the following features:

- Create an initial protected password on first launch.
- Add service entries with username and password.
- Search saved services using a live filter.
- Display the password for a selected entry.
- Edit username and password after verifying the initial password.
- Delete a selected entry with confirmation.
- Create a local encrypted backup of the vault.
- Restore an encrypted backup into `vault.json`.
- Automatically handle legacy vault format renewal when needed.
- Show `OK` / `ERROR` status in a status bar.

## How the project works

### Startup and login

- On first run, the app asks the user to create an initial password.
- The password must contain at least 8 characters, one number, and one special symbol.
- A `tech.json` file is generated with a random salt and an encrypted check payload.
- `tech.json` is used to verify the password on subsequent login attempts.
- If `vault.json` exists but `tech.json` is missing, the app enters a security risk screen (`secury recovery risk`) and blocks access until the user exits or destroys the vault.

### Main files created

- `tech.json`: contains the random salt and a small encrypted check value for verifying the initial password.
- `vault.json`: contains the encrypted vault entries and a log flag.

### Application structure

- `src/main.rs`: main app logic, backup flows, login, save and load operations.
- `src/crypto/kdf.rs`: key derivation from the password using Argon2id.
- `src/crypto/cipher.rs`: authenticated encryption with XChaCha20-Poly1305.
- `src/vault/format.rs`: vault binary format and authenticated header.
- `src/vault/entry.rs`: vault entry structure and serialization handling.
- `src/vault/storage.rs`: atomic vault storage on disk.
- `src/tui/*`: terminal user interface.

## Main features

### Adding an entry

- `A` opens the entry input screen.
- `Tab` moves between service, username, and password fields.
- `Enter` confirms the current field.
- If the service already exists, the app offers to overwrite it or create a numbered copy.
- Entries are saved encrypted in `vault.json`.

### Search and display

- `S` opens the search field.
- Search filters the services stored in the vault.
- `W` and `S` move selection inside the results.
- `Enter` displays the selected password.
- `E` starts editing after entering the initial password.
- `C` deletes the selected entry.

### Encrypted backup

- `B` starts the backup process.
- The user provides a destination directory.
- `vault.json` is copied as `vault.backup.json` into that directory.
- If `tech.json` exists, it is also copied as `tech.backup.json`.
- The backup remains encrypted and is not decrypted during the operation.

### Backup restore

- `U` starts the upload/restore process.
- The user provides the full path of an encrypted backup file.
- The selected file is copied to `vault.json`.
- If `tech.backup.json` exists in the same directory, it is also copied to `tech.json`.
- The program reloads the vault and attempts to decrypt it with the current password.
- If the current password does not match the backup, the status shows an error.

## How the encryption works

### Key derivation (KDF)

PassM3nage uses Argon2id to derive a 32-byte key from the user's password.

Parameters used:

- `memory_kb`: 65536 (64 MiB)
- `time_cost`: 3
- `parallelism`: 4
- `salt`: 16 random bytes generated in `tech.json`

The result is a 32-byte secret key used for all vault encryption.

### Authenticated encryption

The project uses XChaCha20-Poly1305 with the following elements:

- `key`: 32 bytes derived from Argon2id
- `nonce`: 24 random bytes generated for each encryption operation
- `AAD`: additional authenticated data that is authenticated but not encrypted

### Why the same password generates different ciphertexts

It is normal for the same password to produce different ciphertexts. This happens because:

- `tech.json` contains a random salt generated when the vault is created;
- each encryption uses a different random nonce;
- the result is a unique ciphertext even for the same plaintext.

This behavior is correct and improves security.

### Password verification

- `tech.json` contains:
  - `salt`: the salt used for key derivation
  - `check_ciphertext`: the encrypted check value
  - `check_nonce`: the nonce used for that value
- The decrypted content must match the internal control secret exactly.
- If decryption fails, the password is wrong or `tech.json` has been tampered with.

## Backup system

### Backup

- `vault.json` is copied to `vault.backup.json` in the chosen directory.
- If `tech.json` exists, it is also copied to `tech.backup.json` in the same directory.
- The backup consists of encrypted files, so usernames and passwords are not exposed in plaintext.

### Restore

- The user provides the path to `vault.backup.json`.
- If `tech.backup.json` exists in the same directory, it is also restored.
- After copying, the program reloads the vault and verifies that the current password can decrypt the data.
- Restore fails safely if the password does not match.

## Quick use

Build:

```powershell
cargo build --release
```

Run:

```powershell
cargo run
```

On the compiled binary:

```powershell
.\target\release\passm3nage.exe
```

## Security notes

- PassM3nage protects data from unauthorized offline access.
- It does not protect against malware, keyloggers, screen scraping, or a compromised operating system.
- Keys and passwords are derived and handled using secure types.
- Standard cryptographic primitives are used, not custom algorithms.

## File structure

- `src/crypto/kdf.rs`: Argon2id key derivation.
- `src/crypto/cipher.rs`: XChaCha20-Poly1305 authenticated encryption.
- `src/vault/format.rs`: vault format serialization.
- `src/vault/storage.rs`: atomic disk writing.
- `src/main.rs`: main flow, backup, restore, login, and TUI.
- `src/tui/`: screens and input control.
- `src/clipboard/`: secure clipboard copying.

## Limitations

- The implementation is a prototype and should not be used for critical production passwords yet.
- The vault remains decrypted in memory during the session.
- There is no cloud synchronization or remote sharing.
- Security depends on the quality of the initial password and device integrity.
