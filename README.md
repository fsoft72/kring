# kring

kring is a standalone Linux app (Rust + egui) to manage Secret Service keyrings
(gnome-keyring and compatible providers). It links no Qt, GTK, GNOME or KDE
libraries.

## Features

- **Secret Service management**: list, create, rename, unlock and delete keyrings; change the master password; browse, search, create, edit and delete items; copy secrets with a 30 s clipboard auto-clear.
- **Offline files**: browse the `*.keyring` files in `~/.local/share/keyrings` without the daemon. Binary (encrypted) files open with their password; plaintext files are read directly, including ones the daemon rejects because of multi-line `secret=` values (recovered by a tolerant parser). Items can be imported into an unlocked keyring (duplicates skipped, conflicts listed, nothing overwritten).
- **Backups and restore**: every destructive action first writes a backup; the Backups area lists them and restores selected files.
- **Copy, move and consolidate**: move items between keyrings with a conflict preview, or merge all orphan keyrings into `login` in one step (see below).
- **Encrypted export**: export a keyring to an age passphrase-encrypted `.kring.age` file and import it back.

## Copy / Move and Consolidate

**Copy / Move**: select items in a keyring (or in an offline file) and copy or move them into another unlocked keyring. A preview lists what will be created, which items are already there (identical, skipped) and which conflict (same attributes, different secret). Each conflict gets a choice, "Keep target" or "Use incoming", preselected to the newer side. Move deletes the originals only after the copy succeeded; items you kept in conflicts stay in the source.

**Consolidate**: merges every readable orphan keyring into one target (normally `login`) in a single operation. The preview shows, per source keyring, the items to create, duplicates and conflicts, plus the empty keyrings that will be deleted and the keyrings that are skipped. Sources that end up empty are deleted, and the `default` alias is pointed at the target. The `login` and `session` collections and aliases are never consolidated. Locked keyrings are skipped and left untouched: unlock them first to include them. Optionally, "retire empty plaintext orphan files" also removes the empty plaintext `*.keyring` files the daemon does not serve (after an encrypted backup).

Every apply first writes a backup of the target and of each keyring it touches, under `$XDG_DATA_HOME/kring/backups` (default `~/.local/share/kring/backups`), so the Backups area can restore it.

### Recommended order for a real cleanup

1. **Offline files**: import the items of the unreadable `*.keyring` files into `login`, then retire those files.
2. **Consolidate** into `login`, with "retire empty plaintext orphan files" enabled.
3. Restart the daemon so it drops its in-memory copy of the removed keyrings: `systemctl --user restart gnome-keyring-daemon`.

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
