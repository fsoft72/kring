# kring

kring is a standalone Linux app (Rust + egui) to manage Secret Service keyrings
(gnome-keyring and compatible providers). It links no Qt, GTK, GNOME or KDE
libraries.

## Features

- **Secret Service management**: list, create, rename, unlock and delete keyrings; change the master password; browse, search, create, edit and delete items; copy secrets with a 30 s clipboard auto-clear.
- **Offline files**: browse the `*.keyring` files in `~/.local/share/keyrings` without the daemon. Binary (encrypted) files open with their password; plaintext files are read directly, including ones the daemon rejects because of multi-line `secret=` values (recovered by a tolerant parser). Items can be imported into an unlocked keyring (duplicates skipped, conflicts listed, nothing overwritten). "Delete file" removes any file the daemon has not loaded (binary, plaintext or unrecognized): "Back up the file before deleting" is checked by default (a plaintext file's backup is encrypted with a passphrase you choose); unchecked, the deletion is permanent and the button is enabled only after typing the exact file name. A file loaded by gnome-keyring (the note shows its keyring id and label, e.g. `Default_10 (label "Default")`) is deleted as a keyring through gnome-keyring, with the usual backup of all keyring files (encrypted when any of them is plaintext); the backup can be skipped only when that keyring is unlocked and holds no items (a locked keyring never counts as empty). This needs a provider that allows writes, and works on locked keyrings too (no prompt).
- **KWallet migration**: read KDE wallets (`~/.local/share/kwalletd/*.kwl`) without KWallet running, browse their folders and entries, and import them into a gnome-keyring keyring so apps keep finding their secrets (see below).
- **Same-named keyrings**: when two or more keyrings share a label (gnome-keyring names many orphans "Default"), every list, header and keyring picker shows `<label> · <keyring id>` for each of them.
- **Backups and restore**: every destructive action first writes a backup; the Backups area lists them and restores selected files.
- **Copy, move and consolidate**: move items between keyrings with a conflict preview, or merge all orphan keyrings into `login` in one step (see below).
- **Encrypted export**: export a keyring to an age passphrase-encrypted `.kring.age` file and import it back.
- **Progress of destructive actions**: deleting an item, keyring or file, retiring a file, restoring a backup and applying a move (or a "use incoming" choice) open a "Working..." window listing the backup step and the operation, then the result (or the error). It closes only once the operation finished, and every other destructive action stays disabled meanwhile, so the same keyring cannot be deleted twice.
- **Remember a passphrase for the session**: passphrase dialogs (unlock, backup, restore, retire, export/import archive, consolidation) offer "Remember for this session". The remembered value then answers passphrase requests by itself (once per request; the dialog opens if it is wrong), is tried first when you click Unlock, and fills new-backup passphrases without the confirmation field. A key tile in the rail shows that one is remembered; click it to forget it.

## Copy / Move and Consolidate

**Copy / Move**: select items in a keyring (or in an offline file) and copy or move them into another unlocked keyring. A preview lists what will be created, which items are already there (identical, skipped) and which conflict (same attributes, different secret). Each conflict gets a choice, "Keep target" or "Use incoming", preselected to the newer side. Move deletes the originals only after the copy succeeded. On Move, "Keep target" deletes the source item when the target is at least as new: its value then survives only in the pre-apply backup. When the target is older, "Keep target" leaves the source item in place. A plain Copy (no conflict resolved with "Use incoming") only adds items and takes no backup; Move and "Use incoming" take one first. Before applying, kring re-reads the target and, for items from a keyring, the source items: if they changed since the preview, nothing is applied and you are asked to preview again (offline files and archives are read once, at preview time).

**Consolidate**: merges every readable orphan keyring into one target (normally `login`) in a single operation. The preview shows, per source keyring, the items to create, duplicates and conflicts, plus the empty keyrings that will be deleted and the keyrings that are skipped. The apply runs in this order: the moves, then the `default` alias is pointed at the target, then the sources that ended up empty and the empty keyrings are deleted (so a failed deletion never leaves `default` on a keyring about to go). The `login` and `session` collections and aliases are never consolidated. Locked keyrings are skipped and left untouched: unlock them before previewing to include them (unlocking discards a preview). Keyrings that cannot be read are skipped too and listed as unreadable. Optionally, "retire empty plaintext orphan files" also removes the empty plaintext `*.keyring` files the daemon does not serve (after an encrypted backup).

Every consolidation, Move or "Use incoming" first writes one backup of all keyring files, under `$XDG_DATA_HOME/kring/backups` (default `~/.local/share/kring/backups`), so the Backups area can restore it.

Do not consolidate while other applications write to the keyrings (for example a job that rewrites a keyring every hour: pick a moment well away from it). kring re-checks every item right before it moves it, but it cannot stop another writer between its steps.

Preview and apply read every item and secret over D-Bus, so with many keyrings and items they can take a while; each plaintext keyring in a backup is encrypted with age, about 1 s per file.

### Recommended order for a real cleanup

1. **Offline files**: import the items of the unreadable `*.keyring` files into `login`, then retire those files.
2. **Consolidate** into `login`, with "retire empty plaintext orphan files" enabled.
3. Restart the daemon so it drops its in-memory copy of the removed keyrings: `systemctl --user restart gnome-keyring-daemon`.

## KWallet migration

The KWallet area lists the wallets in `$XDG_DATA_HOME/kwalletd` (default
`~/.local/share/kwalletd`, usually just `kdewallet`). kring reads the wallet
files itself: KWallet does not need to run, and the files are never changed.
Supported format: Blowfish CBC wallets with a PBKDF2-SHA512 key (what current
KWallet writes); older Blowfish ECB / SHA-1 and GPG wallets are listed as
unsupported.

**Open** asks for the wallet password and shows the entries grouped by folder,
read only, each with its type (PASSWORD, MAP, STREAM), the attributes it will
get, and Show / Copy for its secret. The password stays in memory only while the
wallet is open (switching wallet or leaving the area drops it with the entries).

**What is migrated**: every password, map and stream entry of every folder.
Passwords become text secrets, maps a JSON object (`application/json`, keys
sorted) and streams raw bytes (`application/octet-stream`).

**How attributes are restored**:

- Entries an app stored through KWallet's Secret Service layer ("app entry"
  chip) get back their original label, attributes and dates from
  `<wallet>_attributes.json`, so those apps find them in gnome-keyring exactly as
  before.
- Native KWallet entries (written through the KWallet API) are labelled
  `<folder>/<key>` and get `server=<folder>`, `user=<key>`,
  `type=plaintext|map|binary` (what the `kwalletd6` compatibility shim searches
  when a KWallet-API app asks for an entry), plus `kwallet-folder`,
  `kwallet-key`, `kwallet-type` and `xdg:schema=org.kde.KWallet.Entry`.

**Import into...** uses the same preview as Copy: identical items are skipped,
so importing twice changes nothing, and conflicts (same attributes, another
secret) are shown for review before anything is written.

**Which keyring**: the `kwalletd6` shim looks for a keyring labelled like the
wallet, so for `kdewallet` import into a keyring named `kdewallet`. If one
exists it is preselected; otherwise the dialog offers "Create keyring
'kdewallet'" (with its password, which can be remembered for the session), then
choose Import into... again to fill it. Importing into `login` keeps every secret,
but apps using the KWallet API will not find them there.

**After migrating, disable KWallet's Secret Service integration**, otherwise
KWallet (`ksecretd`, `org.kde.secretservicecompat`) may claim
`org.freedesktop.secrets` again and apps would keep using the wallet: in System
Settings > KDE Wallet uncheck "Use KWallet for the Secret Service interface"
(or set `apiEnabled=false` in the `[org.freedesktop.secrets]` group of
`~/.config/kwalletrc`), then log out and back in. kring shows a reminder in the KWallet
area while a KWallet daemon is on the bus, and again after each import. Keep the wallet files until
you have checked that your apps work; kring never deletes them.

## Run

Isolated, seeded session for trying things out (private D-Bus session, throwaway
gnome-keyring, temp `HOME`; your real keyrings and wallets are never touched; the
KWallet area shows two copies of the test wallet, `kdewallet` and `fixture`,
password `fixture-pw`):

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
- A backup holding a file that no longer exists (a retired file, the file of a deleted or consolidated keyring) is pinned: it is never pruned, because it may be the only copy. Pinned backups therefore add up beyond the newest 20; remove the ones you no longer need by hand from the backups directory.
- Textual `.keyring` files are **plaintext on disk**: anyone who can read the file can read the secrets. "Retire file" deletes one only after an encrypted backup is verified, and never for a file the daemon has loaded. "Delete file" removes a file the daemon has not loaded only after the backup manifest lists it with the expected checksum (when the backup is chosen); a loaded one goes through the daemon's own delete, after a backup unless the keyring is unlocked and empty.
- Restoring overwrites files in the keyrings directory (after backing up the current ones). The daemon keeps its own in-memory copy, so restart it afterwards: `systemctl --user restart gnome-keyring-daemon`. kring shows this command and does not run it.
- Secrets are never logged and are zeroized in memory when dropped.
- KWallet wallets are only read: kring never writes, deletes or locks the files in `~/.local/share/kwalletd`, and never talks to KWallet. Symlinked wallet, salt or attributes files are refused.
- **Remembered passphrase warning**: "Remember for this session" keeps the passphrase in memory only (never on disk, in logs or in debug output) until kring closes or you forget it from the rail. While it is remembered, anyone using your session can unlock keyrings and decrypt or write backups with it without typing it. Use it only on a machine you control, and forget it when you are done.
