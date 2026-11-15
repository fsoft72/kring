# kring

kring is a standalone Linux app (Rust + egui) to manage Secret Service keyrings
(gnome-keyring and compatible providers). It links no Qt, GTK, GNOME or KDE
libraries.

## Features

- **Secret Service management**: list, create, rename, unlock and delete keyrings; change the master password; browse, search, create, edit and delete items; copy secrets with a 30 s clipboard auto-clear.
- **Offline files**: browse the `*.keyring` files in `~/.local/share/keyrings` without the daemon. Binary (encrypted) files open with their password; plaintext files are read directly, including ones the daemon rejects because of multi-line `secret=` values (recovered by a tolerant parser). Items can be imported into an unlocked keyring (duplicates skipped, conflicts listed, nothing overwritten).
- **Backups and restore**: every destructive action first writes a backup; the Backups area lists them and restores selected files.
- **Encrypted export**: export a keyring to an age passphrase-encrypted `.kring.age` file and import it back.

## Run

Isolated, seeded session for trying things out (private D-Bus session, throwaway
gnome-keyring, temp `HOME`; your real keyrings are never touched):

```sh
scripts/dev-session.sh
```

Real use, against your actual keyrings:

```sh
cargo run -p kring --release
```

Tests: `cargo test --workspace`. Integration tests run only inside `scripts/it-session.sh`.

To check a keyrings directory read-only (prints counts only, never labels, attributes or secrets):

```sh
cargo run -p kring-core --example scan_report -- ~/.local/share/keyrings
```

## Safety notes

- Backups live in `$XDG_DATA_HOME/kring/backups` (default `~/.local/share/kring/backups`), mode 0700, newest 20 kept. Plaintext keyring files are stored in backups encrypted with age and a passphrase you choose.
- Textual `.keyring` files are **plaintext on disk**: anyone who can read the file can read the secrets. "Retire file" deletes one only after an encrypted backup is verified, and never for a file the daemon has loaded.
- Restoring overwrites files in the keyrings directory (after backing up the current ones). The daemon keeps its own in-memory copy, so restart it afterwards: `systemctl --user restart gnome-keyring-daemon`. kring shows this command and does not run it.
- Secrets are never logged and are zeroized in memory when dropped.
