# kring - Design

Date: 2026-11-15
Status: draft (builder check done), pending approval

## 1. Intent

kring is a standalone Linux desktop app, written in Rust with egui, to fully manage the
user's secrets: Secret Service keyrings, offline keyring files, SSH keys, GPG keys and
legacy KWallet wallets.

Why: the user's system shows the classic broken-keyring pattern (about 70
`Default_N.keyring` / `Default_keyring_N.keyring` files, most of them empty, created by
apps that could not find an unlocked default collection), plus a KWallet wallet
(`~/.local/share/kwalletd/kdewallet.kwl`) whose content is not reachable through Secret
Service. Existing tools (Seahorse, KWalletManager, Kleopatra) are tied to GTK/GNOME or
Qt/KDE and none of them can consolidate keyrings or migrate KWallet into gnome-keyring.

Reference system (the user's machine):
- Secret Service provider: `gnome-keyring-daemon --components=pkcs11,secrets`
- `~/.local/share/keyrings/default` contains `login`
- PAM: `pam_gnome_keyring.so` in `/etc/pam.d/sddm` (auth, session auto_start) and
  `/etc/pam.d/common-password`
- GnuPG 2.4.8, `~/.ssh` with `id_ed25519` and `id_rsa`
- KWallet files: `kdewallet.kwl`, `kdewallet.salt`, `kdewallet_attributes.json`

## 2. Goals

1. **Secret Service (live, via D-Bus)**
   - List collections (keyrings) with label, locked state, item count, aliases.
   - Mark which collection is the **login** keyring (unlocked by PAM at login) and which
     holds the **default** alias; change the default alias.
   - Create, rename, delete, lock, unlock collections; change a collection password.
   - List, search, view, create, edit (label, attributes, secret), delete items.
   - Copy and move items between collections.
2. **Offline keyring files** (`~/.local/share/keyrings/*.keyring`), daemon not required
   - Open a file with its password, browse items, reveal secrets.
   - Export items, import items into a live collection (recovery and migration).
   - Backup and restore keyring files.
3. **Consolidate**
   - Detect empty and duplicate collections (same label pattern `Default*`, identical
     items by attributes + secret).
   - Preview plan: which items move where, which collections get deleted, final value
     of the `default` alias.
   - Apply plan after an automatic backup; set `default` alias so new orphans stop
     being created.
4. **KWallet migration** (offline, no kwalletd required)
   - Parse `kdewallet.kwl` (+ `.salt`) with the wallet password.
   - Browse folders and entries (passwords, maps, binary).
   - Migrate selected entries into a Secret Service collection with a defined
     attribute mapping (see 6.5).
5. **SSH keys** (`~/.ssh`)
   - List key pairs (type, bits, fingerprint SHA256, comment, encrypted or not).
   - Create (ed25519, ecdsa, rsa), import, export (public and private), delete,
     change passphrase.
   - Show keys loaded in `ssh-agent`, add and remove keys from the agent.
6. **GPG keys** (via the `gpg` binary)
   - List public and secret keys with subkeys, uids, validity, expiry, trust.
   - Create, import, export (public, secret armored), delete, change passphrase.

## 3. Non-goals

- No dependency on Qt, GTK, GNOME or KDE libraries (linked or required at runtime).
  `gpg`, `ssh-agent` and the Secret Service daemon are external processes / services,
  not linked libraries, and are allowed.
- No implementation of a Secret Service provider (kring is a client, not a daemon).
- No PKCS#11 / certificate management.
- No kernel keyring (`keyctl`).
- No GPG web-of-trust editing beyond what is listed (key signing, trust editing are out
  for v1).
- No writing of KWallet files (read only, migration source).
- No Windows / macOS support.

## 4. Anti-goals (failure even if it "works")

- Any data loss: a destructive operation (delete, consolidate, move, restore) without a
  backup and a preview.
- Secrets written in clear to disk, logs, crash reports or left in the clipboard.
- A GTK/Qt system prompt popping up during normal use when kring could ask for the
  password itself.
- UI freezing during D-Bus calls, `gpg` runs or KDF work.

## 5. Constraints

- Rust stable (system has cargo 1.98), Linux only.
- GUI: `eframe` / `egui` (winit + glow or wgpu). No GTK through transitive deps:
  - user session is X11 with xdg portals available.
  - file dialogs: `rfd` with `default-features = false, features = ["xdg-portal"]`
    plus its required async runtime feature (`tokio`), or
    an egui file picker if the portal is missing. Check `cargo tree` in CI for
    `gtk`, `glib`, `qt`.
- D-Bus: `zbus` (pure Rust), no libdbus.
- Secret Service client and gnome-keyring file format: `oo7`.
- Secrets in memory: `zeroize` / `secrecy` types; never `Debug`-print secrets.
- Package manager note: user prefers pnpm for JS; not relevant here, Cargo only.

## 6. Design

### 6.1 Architecture (approach A, chosen)

Cargo workspace:

```
kring/
  Cargo.toml              (workspace)
  crates/
    kring-core/           (library, no UI)
      src/
        secret_service/   (oo7 + zbus, gnome-keyring private interface)
        keyring_file/     (offline .keyring read/write, via oo7 file API)
        kwallet_file/     (offline .kwl parser)
        ssh/              (ssh-key crate + ssh-agent protocol)
        gpg/              (gpg binary driver, --with-colons parser)
        ops/              (copy, move, consolidate planner, backup/restore)
        model.rs          (shared types: Collection, Item, Attributes, KeyInfo...)
        error.rs
    kring/                (egui app binary)
      src/
        main.rs
        app.rs            (top-level state, navigation)
        worker.rs         (background thread, command/event channels)
        views/            (one module per area)
        widgets/          (secret field, confirm dialog, preview list...)
```

Threading: the UI thread never blocks. A worker thread owns a tokio (or async-io)
runtime and all backends. UI sends `Command` enums over a channel, worker replies with
`Event` enums; UI calls `ctx.request_repaint()` on event arrival. Long operations
report progress events.

All backends expose plain Rust traits in `kring-core` so they can be tested with fakes
(no D-Bus or `gpg` needed for most unit tests).

### 6.2 Secret Service backend

- Standard API (`org.freedesktop.Secret.Service`): collections, items, search,
  `ReadAlias` / `SetAlias` for `default`, `Lock`, `Delete`, item `SetSecret`.
- gnome-keyring private interface
  `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` (not wrapped by oo7:
  call it with raw zbus and own Secret Service session / DH key code if oo7 does not
  expose the session key):
  `CreateWithMasterPassword`, `UnlockWithMasterPassword`, `ChangeWithMasterPassword`.
  Used so kring asks passwords in its own egui dialogs instead of triggering the
  gnome-keyring (GTK) prompter.
  - Detect support at startup (introspection). If missing (other provider such as
    KeePassXC), fall back to the standard `Prompt` flow and label the action
    "system prompt" in the UI. Change password is unavailable on such providers.
  - Secrets passed to these methods use the Secret Service session encryption
    (dh-ietf1024-sha256-aes128-cbc-pkcs7), never plain.
- **Login keyring detection**: the collection whose object path is
  `/org/freedesktop/secrets/collection/login`, cross-checked with the presence of
  `pam_gnome_keyring.so` in `/etc/pam.d/*`. UI shows a badge "login keyring" and,
  if PAM integration is missing, a warning explaining why it will not auto-unlock.
  PAM presence alone does not prove auto-unlock: the keyring password must equal the
  user's login password. UI states this and offers "change password" as the fix.
- **Competing providers**: detect other services that may claim
  `org.freedesktop.secrets` (on the user's system `kwalletd6` and
  `org.kde.secretservicecompat` are running). Show which process owns the name and
  warn after KWallet migration if KWallet could still take over the name.
- **Provider scope (Claude's call)**: write and destructive operations (delete,
  move, consolidate, change password) only when the provider is gnome-keyring, where
  file backups are possible. Other providers: read, and copy items into them.
- **Default keyring**: `ReadAlias("default")`; set with `SetAlias`. Also show the
  content of `~/.local/share/keyrings/default` for transparency.

### 6.3 Offline keyring files

- gnome-keyring writes two on-disk formats, both must be read:
  - binary v0 (`GnomeKeyring\n\r\0\n`, AES-128-CBC, iterated salted SHA-256) for
    password-protected collections;
  - plaintext "textual" INI format (`gkm-secret-textual`) for collections with an
    empty password. Many `Default_N` orphans are likely this kind.
  The "v1" format of oo7 / libsecret file backend is never written by gnome-keyring;
  supporting it is optional. **Builder spike first**: check what oo7 reads (its legacy
  v0 support) against the user's real files; implement in `keyring_file` whatever is
  missing (textual format almost certainly).
- Read only by default. Writing offline files only for restore from backup (file copy,
  not re-encryption) in v1.
- Import offline items into a live collection uses the same copy pipeline as 6.6.

### 6.4 Backups

- Location: `~/.local/share/kring/backups/<timestamp>-<reason>/`, directory mode
  0700. Retention: keep last 20 backups, older ones deleted with a notice (Claude's
  call, configurable).
- Backups that would contain plaintext (textual keyring files, unencrypted SSH
  private keys) are stored `age`-encrypted with a passphrase asked at backup time
  (Claude's call).
- Content: raw copies of the affected files (`.keyring`, `default`, KWallet files when
  relevant) plus `manifest.json` (what, when, why, sha256 of each file).
- Taken automatically before: delete collection, delete item(s), move, consolidate,
  restore. Restore requires stopping use of the daemon; v1 restore = copy files back
  and tell the user to log out / restart `gnome-keyring-daemon` (show the exact
  command).
- Secret export (items, offline or live): single file encrypted with a passphrase
  using `age` (scrypt recipient). Format inside: JSON list of
  `{collection, label, attributes, secret (base64), content_type, created, modified}`.
  Never plain.

### 6.5 KWallet migration

- Parser in `kwallet_file`: header `KWALLET\n\r\0\r\n`, version, cipher byte, hash
  byte. Support:
  - cipher Blowfish (KWallet's CBC variant) with hash PBKDF2-SHA512 using the
    `.salt` file (modern default, matches the user's files);
  - legacy SHA1 hash variant if cheap; GPG-encrypted wallets out of v1 (show a clear
    message).
- Decrypted structure: folders -> entries, entry types Password, Map, Stream.
- **Goal (user decision): apps must keep working after migration**, not an archive.
  - Entries created by apps through KWallet's Secret Service compat layer have their
    original Secret Service attributes, label, created/modified in
    `kdewallet_attributes.json` (JSON keyed by folder/entry, with `attributes`,
    `$fdo_created`, `$fdo_modified`, e.g. Brave: `server`, `user`, `type`). Migrate
    them with those exact attributes (including `xdg:schema` when present) and label,
    so the apps find them again in gnome-keyring.
  - Folder of a compat entry maps to a target collection (default: the target chosen
    by the user, normally `login`).
  - Native KWallet entries (no fdo attributes) get a fallback mapping:
    label `<folder>/<entry key>`, attributes `kwallet-folder`, `kwallet-key`,
    `kwallet-type`, `xdg:schema = org.kde.KWallet.Entry`. The builder adds per-folder
    rules for well-known native users if found in the user's wallet (inspect folders
    during the spike, e.g. Network Management, browsers), listed in the doc of the
    mapping module.
  - Password -> secret as UTF-8 text; Map -> JSON serialized; Stream -> raw bytes with
    content type `application/octet-stream`.
  - Idempotent: re-running migration detects already migrated items (same
    attributes) and skips or routes them into the conflict flow of 6.6.
- Tests: build fixture wallets. Builder may generate them once with a real kwalletd in
  a throwaway container and commit the fixtures (with known test passwords).

### 6.6 Copy, move, consolidate (`ops`)

- Copy item = read label, attributes, secret, content type from source; create in
  target with `replace = false`. Duplicate detection: same attributes and same secret
  -> skip and report. Move = copy then delete source, only after copy success.
- **Conflict (user decision: option b)**: same attributes, different secret. The
  preview lists every conflict side by side (label, collection, modified date, secret
  masked with "show"), with the newest (by `modified`) preselected. The user can
  switch the choice per conflict. The loser is kept only in the backup. Applies to
  copy, move, consolidate and KWallet migration.
- Consolidate planner (pure function, unit tested):
  1. Inputs: all collections with items (locked ones need unlocking first; the UI lists
     them and asks passwords, or lets the user skip them).
  2. Target: user chooses (default proposal: `login`).
  3. Empty collections -> delete.
  4. Non-empty -> move items to target, dedupe, collect conflicts, then delete
     source.
  5. Ensure `default` alias points to target.
  6. Output: a `Plan` shown as a preview list; nothing runs until confirm.
- Apply: backup, execute step by step, report per-step result; stop on first error
  and show what was done so far.

### 6.7 SSH

- `ssh-key` crate: parse OpenSSH-format private/public keys (user's keys are
  OpenSSH format; legacy PEM / PKCS#8 private keys: show as "legacy format",
  offer conversion later, out of v1), decrypt/encrypt (passphrase
  change), generate ed25519 / ecdsa p256/p384 / rsa 3072/4096.
- Files written with mode 0600 (private) and 0644 (public). Delete moves files to the
  backup folder instead of unlinking.
- ssh-agent: talk to `$SSH_AUTH_SOCK` with the agent protocol (crate `ssh-agent-lib`
  or a small own implementation): list identities, add key (asks passphrase in egui),
  remove key.

### 6.8 GPG

- Driver runs `gpg --batch --with-colons --fixed-list-mode` for listing; parse colon
  format into `GpgKey { fpr, uids, subkeys, validity, expiry, trust, secret }`.
- Operations: `--quick-gen-key`, `--import`, `--export` / `--export-secret-keys
  --armor`, `--delete-secret-and-public-key` (with `--yes` after kring's own
  confirmation; batch mode requires the full fingerprint), `--passwd`.
- `--passwd` asks old and new passphrase: drive it with `--command-fd` /
  `--status-fd` answering each `GET_HIDDEN` prompt, not a single `--passphrase-fd`.
- Passphrase entry: gpg-agent's pinentry would open a GTK/Qt window. kring asks the
  passphrase in egui and passes it with `--pinentry-mode loopback --passphrase-fd`.
  Requires `allow-loopback-pinentry` (default on in GnuPG 2.4); detect and explain if
  disabled.
- Respect `GNUPGHOME`.

### 6.9 UI (egui)

```
+------------------------------------------------------------------+
| kring                                         [search........]   |
+----------------+-------------------------------------------------+
| SECRETS        |  login   [default] [unlocked at login] [locked?]|
|  * login       |  -------------------------------------------    |
|    Default_3   |  Label            Attributes        Modified    |
|    ...         |  GitHub token     service=gh ...    2026-10-02  |
| OFFLINE FILES  |  ...                                            |
| KWALLET        |  [New item] [Copy to...] [Move to...] [Delete]  |
| SSH KEYS       |  ---------- item detail -----------------------  |
| GPG KEYS       |  Secret: ******** [show] [copy]                 |
| TOOLS          |  Attributes: editable key/value table           |
|  Consolidate   |                                                 |
|  Backups       |                                                 |
+----------------+-------------------------------------------------+
| status: 74 collections, 2 locked            worker: idle         |
+------------------------------------------------------------------+
```

- Secrets hidden by default, "show" toggles, "copy" puts into clipboard (`arboard`,
  Wayland + X11) and clears it after 30 s if it still holds the copied value.
- Every destructive action: confirmation dialog listing exactly what changes.
- Password dialogs are egui modals; buffers zeroized on close.

## 7. Approaches considered

- **Architecture**: A) workspace with `kring-core` + `kring` UI and a worker thread
  (chosen: testable core, non-blocking UI, a CLI can be added later); B) single crate
  (faster start, logic tangled with UI, hard to test destructive ops). Chosen: A.
- **KWallet**: A) offline `.kwl` parser (chosen: works without kwalletd, matches the
  offline goal, no Qt prompt); B) `kwalletd6` over D-Bus (less code, needs running
  daemon and its Qt prompt). Chosen: A.
- **GPG**: drive the `gpg` binary (chosen by user) vs Sequoia (pure Rust, but still
  needs gpg-agent for GnuPG's key store, heavier build).

## 8. Decided by the user

- Standalone, no Qt/GTK/GNOME/KDE libs.
- Scopes: Secret Service, SSH + GPG full management (create, import, export, delete,
  change passphrase), offline keyring files, keyring management (login / default),
  copy items between keyrings, consolidate, KWallet migration.
- GPG via binary. Architecture A, KWallet offline parser A.
- Conflicts: show side by side, newest preselected, user decides per item.
- KWallet migration must keep apps working (restore original fdo attributes).

## 9. Proposed defaults (made by Claude, user may override)

- Secrets hidden until "show"; clipboard cleared after 30 s.
- `zeroize` for secret memory.
- Automatic backup before every destructive op, preview before consolidate.
- Exports always `age`-encrypted with passphrase.
- Consolidate default target: `login`.
- Use gnome-keyring private interface to avoid system prompts.

## 10. Left to the builder

- tokio vs async-io runtime for the worker (whatever oo7/zbus integrate best with).
- glow vs wgpu renderer.
- Exact crate choices for ssh-agent protocol and age.
- Internal module layout below the level shown in 6.1.
- Visual styling, icons, theme (follow system dark/light).
- Test fixture generation strategy for keyring and KWallet files.
