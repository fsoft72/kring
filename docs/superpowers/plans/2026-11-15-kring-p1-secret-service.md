# kring Plan 1: Foundation + Secret Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working egui app that lists, inspects and fully manages Secret Service collections and items (login/default badges, set default, create/unlock/lock/rename/delete/change password, item CRUD), with automatic backups before destructive operations.

**Architecture:** Cargo workspace with `kring-core` (no UI, backends behind traits, tested with fakes and with an isolated gnome-keyring daemon) and `kring` (eframe app). A worker thread owns a tokio runtime and the backend; UI and worker talk through `Command` / `Event` channels; UI state is a pure reducer over events.

**Tech Stack:** Rust stable (1.98), eframe/egui 0.37, oo7 0.7.1 (`tokio`, `native_crypto`, `unstable`), zbus (re-exported by oo7), tokio 1, async-trait 0.1, thiserror 2, zeroize 1.9, age 0.12, arboard 3.7, tempfile 3 (dev).

**Spec:** `docs/superpowers/specs/2026-11-15-kring-design.md` (sections 6.1, 6.2, 6.4, 6.9 for this plan).

## Roadmap (one plan each, written when the previous one is done)

1. **This plan**: workspace, model, Secret Service backend, gnome-keyring private interface, provider and PAM detection, backups, worker, egui UI for secrets.
2. Offline keyring files: v0 binary (via oo7 legacy) + textual format reader, browse, import into live collection, restore from backup, age export/import of items (spec 6.3, 6.4).
3. Copy / move / conflict preview / consolidate planner and UI (spec 6.6).
4. KWallet `.kwl` parser + `kdewallet_attributes.json` mapping + migration UI (spec 6.5).
5. SSH keys and ssh-agent (spec 6.7).
6. GPG via `gpg` binary (spec 6.8).

## Global Constraints

- No Qt, GTK, GNOME or KDE libraries linked: `cargo tree -e normal` must not contain `gtk`, `gdk`, `glib`, `qt` (enforced by `scripts/check-no-gui-toolkits.sh`, run in every task's verification).
- oo7 dependency exactly: `oo7 = { version = "0.7.1", default-features = false, features = ["tokio", "native_crypto", "unstable"] }`.
- Secrets live in `SecretValue` (zeroized on drop, `Debug` prints `SecretValue(<redacted, N bytes>)`); never log or `format!` secret bytes.
- Login collection object path: `/org/freedesktop/secrets/collection/login`.
- gnome-keyring private interface: name `org.gnome.keyring`, path `/org/freedesktop/secrets`, interface `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface`, methods `CreateWithMasterPassword(a{sv} properties, (oayays) master) -> o`, `UnlockWithMasterPassword(o collection, (oayays) master)`, `ChangeWithMasterPassword(o collection, (oayays) original, (oayays) master)`. Called on bus name `org.freedesktop.secrets`.
- Write and destructive operations (delete item/collection, change password, rename) only when provider kind is `GnomeKeyring`; otherwise `KringError::Unsupported`.
- Backups: root `$XDG_DATA_HOME/kring/backups` (fallback `$HOME/.local/share/kring/backups`), dir mode 0700, dir name `<YYYYmmdd-HHMMSS>-<reason>`, `manifest.json` with sha256 per file, keep last 20.
- Binary keyring magic: `b"GnomeKeyring\n\r\0\n"`; any `.keyring` not starting with it is plaintext and must be stored as `<name>.age` (age scrypt passphrase).
- Clipboard auto-clear after 30 s, only if clipboard still holds the copied text.
- Integration tests never touch the user's real keyring: they run only inside `scripts/it-session.sh` (private `dbus-run-session`, temp `HOME`/`XDG_DATA_HOME`, `gnome-keyring-daemon --unlock --components=secrets` fed password `test`) and are `#[ignore]` unless `KRING_IT=1`.
- Code style (user rules): English identifiers and comments, doc comment on every function, early-return guards at top, constants UPPER_SNAKE_CASE, files end with newline, never the `—` character. Update `CHANGES.md` and commit at the end of each task (no AI attribution, no `--no-verify`, no push).

## Review Focus

1. **Locked collection**: items of a locked collection are listed with `locked: true`; revealing a secret returns `KringError::Locked`, UI shows "Collection locked, unlock first", never panics. Test in Task 3 (fake), Task 5 (backend) and Task 10 (UI state).
2. **Binary / non-UTF-8 secret**: shown as `binary (N bytes)`, "show" displays hex, "copy" disabled. Test in Task 10 (`secret_display`).
3. **No Secret Service provider** (name not owned, daemon dead): app starts, shows banner "No Secret Service provider running", no worker panic. Test in Task 9 (`no_provider_emits_unavailable`).
4. **Object vanished between list and action** (deleted by another app): backend maps D-Bus `UnknownObject` to `KringError::NotFound`; worker follows with a `Refresh`. Test in Task 5 (`deleted_item_is_not_found`) and Task 9 (`not_found_triggers_refresh`).
5. **Bad user input**: empty collection label, empty attribute key, duplicate attribute key, new/confirm password mismatch are rejected before any D-Bus call with `KringError::InvalidInput`. Test in Task 2 (`validate_*`).

---

### Task 1: Workspace scaffold and toolkit guard

**Files:**
- Create: `Cargo.toml` (workspace, `resolver = "3"`, members `crates/kring-core`, `crates/kring`)
- Create: `crates/kring-core/Cargo.toml`, `crates/kring-core/src/lib.rs`
- Create: `crates/kring/Cargo.toml`, `crates/kring/src/main.rs`
- Create: `scripts/check-no-gui-toolkits.sh`, `.gitignore` (`/target`), `.editorconfig` (utf-8, lf, final newline, 4 spaces for rs)
- Modify: `CHANGES.md`

**Interfaces:**
- Produces: crate names `kring_core`, binary `kring`; script exit code 0 = clean, 1 = forbidden crate found (prints it).

- [ ] **Step 1:** Write `scripts/check-no-gui-toolkits.sh`: runs `cargo tree -e normal --workspace --prefix none`, greps `-iE '^(gtk|gdk|glib|gio|qt|cairo|pango|atk)[-_ ]'`, prints matches and exits 1 if any.
- [ ] **Step 2:** Create workspace, `kring-core` lib with dependencies from Tech Stack (oo7 exactly as in Global Constraints), `kring` bin depending on `kring-core`, `eframe = "0.37"`, `tokio`, `arboard = "3.7"`. `main.rs` opens an empty eframe window titled `kring`.
- [ ] **Step 3:** Run `cargo build --workspace` -> builds. Run `bash scripts/check-no-gui-toolkits.sh` -> exit 0.
- [ ] **Step 4:** `git init` already done; `git add` the files above, update `CHANGES.md`, commit `chore: scaffold kring workspace with toolkit guard`.

### Task 2: Core model, errors, input validation

**Files:**
- Create: `crates/kring-core/src/model.rs`, `crates/kring-core/src/error.rs`, `crates/kring-core/src/validate.rs`
- Test: inline `#[cfg(test)] mod tests` in each file

**Interfaces:**
- Produces:
  - `pub struct CollectionId(pub String)`, `pub struct ItemId(pub String)` (D-Bus object paths; derive `Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord`).
  - `pub type Attributes = std::collections::BTreeMap<String, String>;`
  - `pub struct SecretValue { bytes: zeroize::Zeroizing<Vec<u8>>, pub content_type: String }` with `new(bytes: Vec<u8>, content_type: &str)`, `from_text(&str)` (content type `text/plain`), `as_bytes(&self) -> &[u8]`, `as_text(&self) -> Option<&str>`, `len()`; manual `Debug`; `Clone`.
  - `pub struct CollectionInfo { pub id, pub label: String, pub locked: bool, pub item_count: usize, pub aliases: Vec<String>, pub is_login: bool, pub created: u64, pub modified: u64 }` (unix seconds).
  - `pub struct ItemInfo { pub id: ItemId, pub collection: CollectionId, pub label: String, pub attributes: Attributes, pub locked: bool, pub created: u64, pub modified: u64 }`
  - `pub struct NewItem { pub label: String, pub attributes: Attributes, pub secret: SecretValue, pub replace: bool }`
  - `pub struct ItemUpdate { pub label: Option<String>, pub attributes: Option<Attributes>, pub secret: Option<SecretValue> }`
  - `pub const LOGIN_COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/login";` and `pub fn is_login_collection(id: &CollectionId) -> bool`
  - `pub enum KringError` (thiserror): `Dbus { context: String, message: String }`, `Locked(String)`, `NotFound(String)`, `Unsupported(String)`, `InvalidInput(String)`, `Io { path: PathBuf, message: String }`, `PassphraseRequired`, `NoProvider`. `pub type Result<T> = std::result::Result<T, KringError>;`
  - `validate::collection_label(&str) -> Result<()>`, `validate::attributes(&[(String, String)]) -> Result<Attributes>` (input as edited rows), `validate::new_password(new: &SecretValue, confirm: &SecretValue) -> Result<()>`.

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn secret_debug_is_redacted() {
    let s = SecretValue::from_text("hunter2");
    assert_eq!(format!("{s:?}"), "SecretValue(<redacted, 7 bytes>)");
}
#[test]
fn login_path_detected() {
    assert!(is_login_collection(&CollectionId(LOGIN_COLLECTION_PATH.into())));
    assert!(!is_login_collection(&CollectionId("/org/freedesktop/secrets/collection/Default_3".into())));
}
#[test]
fn rejects_empty_label() { assert!(matches!(validate::collection_label("  "), Err(KringError::InvalidInput(_)))); }
#[test]
fn rejects_empty_and_duplicate_attribute_keys() {
    assert!(validate::attributes(&[("".into(), "x".into())]).is_err());
    assert!(validate::attributes(&[("a".into(), "1".into()), ("a".into(), "2".into())]).is_err());
    assert_eq!(validate::attributes(&[("a".into(), "1".into())]).unwrap().get("a").unwrap(), "1");
}
#[test]
fn rejects_password_mismatch_and_empty() {
    assert!(validate::new_password(&SecretValue::from_text("a"), &SecretValue::from_text("b")).is_err());
    assert!(validate::new_password(&SecretValue::from_text(""), &SecretValue::from_text("")).is_err());
}
```

- [ ] **Step 2:** `cargo test -p kring-core` -> FAIL (missing items).
- [ ] **Step 3:** Implement the types and functions above. Attribute keys are trimmed and must not be empty. Labels are trimmed and must not be empty.
- [ ] **Step 4:** `cargo test -p kring-core` -> PASS.
- [ ] **Step 5:** Update `CHANGES.md`, commit `feat(core): add model, errors and input validation`.

### Task 3: Store traits and in-memory fake

**Files:**
- Create: `crates/kring-core/src/store.rs`, `crates/kring-core/src/fake_store.rs` (public behind feature `fake`, also enabled for tests)

**Interfaces:**
- Consumes: Task 2 types.
- Produces (`#[async_trait::async_trait]`, `Send + Sync`):

```rust
pub trait SecretStore: Send + Sync {
    async fn list_collections(&self) -> Result<Vec<CollectionInfo>>;
    async fn list_items(&self, collection: &CollectionId) -> Result<Vec<ItemInfo>>;
    async fn read_secret(&self, item: &ItemId) -> Result<SecretValue>;
    async fn create_item(&self, collection: &CollectionId, item: NewItem) -> Result<ItemId>;
    async fn update_item(&self, item: &ItemId, update: ItemUpdate) -> Result<()>;
    async fn delete_item(&self, item: &ItemId) -> Result<()>;
    async fn read_alias(&self, alias: &str) -> Result<Option<CollectionId>>;
    async fn set_alias(&self, alias: &str, collection: &CollectionId) -> Result<()>;
    async fn lock(&self, collection: &CollectionId) -> Result<()>;
    async fn rename_collection(&self, collection: &CollectionId, label: &str) -> Result<()>;
    async fn delete_collection(&self, collection: &CollectionId) -> Result<()>;
}
pub trait MasterPasswordStore: Send + Sync {
    async fn create_with_password(&self, label: &str, password: &SecretValue) -> Result<CollectionId>;
    async fn unlock_with_password(&self, collection: &CollectionId, password: &SecretValue) -> Result<()>;
    async fn change_password(&self, collection: &CollectionId, old: &SecretValue, new: &SecretValue) -> Result<()>;
}
```

  - `pub struct FakeStore` (`Mutex` inside) with `FakeStore::new()`, `add_collection(label, password: &str, locked: bool) -> CollectionId` (path `/org/freedesktop/secrets/collection/<label>`), implementing both traits. Wrong password -> `KringError::Dbus { context: "unlock", .. }`. `read_secret` on locked collection -> `Locked`. Unknown id -> `NotFound`. `CollectionInfo.aliases` filled from alias map.

- [ ] **Step 1: Failing tests** (`#[tokio::test]` in `fake_store.rs`): `locked_collection_hides_secret` (create item while unlocked, `lock`, `read_secret` -> `Locked`), `unlock_with_wrong_password_fails`, `set_alias_moves_default` (`set_alias("default", b)` then `read_alias("default") == Some(b)` and `a` no longer lists `"default"` in aliases), `delete_unknown_item_is_not_found`.
- [ ] **Step 2:** `cargo test -p kring-core --features fake` -> FAIL.
- [ ] **Step 3:** Implement traits and fake.
- [ ] **Step 4:** Tests -> PASS.
- [ ] **Step 5:** Commit `feat(core): add store traits and in-memory fake`.

### Task 4: Isolated integration test session

**Files:**
- Create: `scripts/it-session.sh`
- Create: `crates/kring-core/tests/it_smoke.rs`

**Interfaces:**
- Produces: `scripts/it-session.sh <command...>`: creates temp dir, exports `HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR` (mode 0700) into it, runs `dbus-run-session -- bash -c 'echo -n test | gnome-keyring-daemon --unlock --components=secrets --daemonize >/dev/null; KRING_IT=1 "$@"'`, deletes temp dir on exit (trap). In this session the `login` collection exists, unlocked, password `test`, alias `default`.

- [ ] **Step 1:** Test `it_smoke::service_reachable` (`#[ignore]`, skip early if `KRING_IT` unset): `oo7::dbus::Service::new().await` succeeds and `collections()` contains a path ending `/login`.
- [ ] **Step 2:** `bash scripts/it-session.sh cargo test -p kring-core --test it_smoke -- --ignored` -> PASS. Also assert the real `~/.local/share/keyrings` mtime is unchanged before/after (manual check: `stat -c %Y ~/.local/share/keyrings`).
- [ ] **Step 3:** Commit `test: add isolated gnome-keyring integration session`.

### Task 5: Secret Service backend (standard API)

**Files:**
- Create: `crates/kring-core/src/secret_service/mod.rs`, `crates/kring-core/src/secret_service/backend.rs`, `crates/kring-core/src/secret_service/errors.rs`
- Test: `crates/kring-core/tests/it_secret_service.rs`

**Interfaces:**
- Consumes: Task 3 `SecretStore`.
- Produces: `pub struct SecretServiceBackend` with `pub async fn connect() -> Result<Self>` (opens `zbus::Connection::session()`, `oo7::dbus::Service::encrypted_with_connection`, keeps the `Connection` and an `oo7::dbus::api::Service` for alias calls), `pub fn connection(&self) -> &zbus::Connection`, implements `SecretStore`. `errors::map_dbus(context: &str, e: oo7::dbus::Error) -> KringError` maps `org.freedesktop.DBus.Error.UnknownObject` / `NoSuchObject` -> `NotFound`, `org.freedesktop.Secret.Error.IsLocked` -> `Locked`, `ServiceUnknown`/name has no owner -> `NoProvider`, rest -> `Dbus`.

Notes: aliases per collection are computed by calling `read_alias` for `"default"`, `"session"`, `"login"` once per `list_collections`. Times from oo7 `Duration` -> `as_secs()`. `read_secret` on a locked item returns `Locked` without prompting (check `is_locked` first). Collection lookup by path: match `Collection::path()` among `collections()`.

- [ ] **Step 1: Failing integration tests** (all `#[ignore]` + `KRING_IT` guard): `lists_login_with_default_alias` (login has `is_login: true`, aliases contains `"default"`), `item_crud_roundtrip` (create `NewItem{label:"t", attributes:{"service":"kring-test"}, secret: from_text("s3")}`, list shows it, `read_secret` == `"s3"`, update label + secret, delete, list no longer has it), `locked_secret_returns_locked` (`lock(login)`, `read_secret` -> `Locked`), `deleted_item_is_not_found` (delete then `delete_item` again -> `NotFound`).
- [ ] **Step 2:** Run under `scripts/it-session.sh` -> FAIL.
- [ ] **Step 3:** Implement backend and error mapping. Unit-test `map_dbus` with constructed `zbus::Error::MethodError` names.
- [ ] **Step 4:** `cargo test -p kring-core` and the it-session run -> PASS.
- [ ] **Step 5:** Commit `feat(core): add Secret Service backend`.

### Task 6: Provider and PAM detection

**Files:**
- Create: `crates/kring-core/src/provider.rs`, `crates/kring-core/src/pam.rs`

**Interfaces:**
- Produces:
  - `pub enum ProviderKind { GnomeKeyring, KWallet, KeePassXC, Oo7Daemon, Other(String) }`, `pub fn classify(process_name: &str) -> ProviderKind` (`gnome-keyring-d*` -> GnomeKeyring, `kwalletd*`/`ksecretd` -> KWallet, `keepassxc*` -> KeePassXC, `oo7-daemon` -> Oo7Daemon).
  - `pub struct ProviderInfo { pub kind: ProviderKind, pub pid: Option<u32>, pub process_name: Option<String>, pub competitors: Vec<String>, pub has_master_password_iface: bool }` and `pub fn allows_writes(&self) -> bool` (true only for GnomeKeyring).
  - `pub const COMPETITOR_NAMES: [&str; 4] = ["org.kde.kwalletd6", "org.kde.kwalletd5", "org.kde.secretservicecompat", "org.keepassxc.KeePassXC.MainWindow"];`
  - `pub async fn detect(conn: &zbus::Connection) -> Result<ProviderInfo>`: `org.freedesktop.DBus.GetConnectionUnixProcessID("org.freedesktop.secrets")` (no owner -> `NoProvider`), read `/proc/<pid>/comm`, `NameHasOwner` for each competitor, introspect `/org/freedesktop/secrets` and look for the private interface name.
  - `pub struct PamStatus { pub configured: bool, pub files: Vec<PathBuf> }`, `pub fn pam_status(pam_dir: &Path) -> PamStatus`: a file counts when a non-comment line (after trimming, not starting with `#`) contains `pam_gnome_keyring.so`.

- [ ] **Step 1: Failing unit tests:** `classify("gnome-keyring-d") == GnomeKeyring`, `classify("kwalletd6") == KWallet`, `classify("foo") == Other("foo")`; `allows_writes` false for KWallet; `pam_status` on a tempdir with `sddm` containing `-auth optional pam_gnome_keyring.so` and `other` containing `# pam_gnome_keyring.so` -> `configured: true`, files == `[sddm]`; empty dir -> `configured: false`.
- [ ] **Step 2:** `cargo test -p kring-core` -> FAIL.
- [ ] **Step 3:** Implement. Integration test `detect_in_session` (`#[ignore]`): kind `GnomeKeyring`, `has_master_password_iface: true`.
- [ ] **Step 4:** Unit + it-session -> PASS.
- [ ] **Step 5:** Commit `feat(core): detect Secret Service provider and PAM integration`.

### Task 7: gnome-keyring master password interface

**Files:**
- Create: `crates/kring-core/src/secret_service/master_password.rs`
- Test: `crates/kring-core/tests/it_master_password.rs`

**Interfaces:**
- Consumes: Task 5 backend connection; Global Constraints method signatures.
- Produces: `impl MasterPasswordStore for SecretServiceBackend`.

Approach: open a dedicated encrypted session with `oo7::dbus::api::Service::open_session(Some(public_key))` (`Key::generate_private_key`, `Key::generate_public_key`, `Key::generate_aes_key(&private, &server_public)`), build each secret with `DBusSecret::new_encrypted(session, value, &aes_key)` and send its `(o ay ay s)` inner value via a `zbus::Proxy` on the private interface. Property for create: `org.freedesktop.Secret.Collection.Label` -> label. Return value for create is the collection path. Close the session after the call.

- [ ] **Step 1: Failing integration tests:** `create_unlock_change_roundtrip`: `create_with_password("kring-it", "pw1")` returns a path listed by `list_collections`; `lock`; `unlock_with_password(.., "wrong")` -> `Err`; `unlock_with_password(.., "pw1")` -> Ok and `locked == false`; `change_password(.., "pw1", "pw2")`; lock; unlock with `"pw2"` -> Ok.
- [ ] **Step 2:** Run under it-session -> FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** -> PASS. Confirm no prompter window appeared (none can in the headless session; a prompt would make the call hang, so add `tokio::time::timeout(10s)` in tests).
- [ ] **Step 5:** Commit `feat(core): create, unlock and change password without system prompts`.

### Task 8: Backups

**Files:**
- Create: `crates/kring-core/src/paths.rs`, `crates/kring-core/src/backup.rs`

**Interfaces:**
- Produces:
  - `paths::data_home() -> PathBuf` (`XDG_DATA_HOME` or `$HOME/.local/share`), `paths::keyrings_dir() -> PathBuf`, `paths::backups_dir() -> PathBuf`.
  - `pub const KEYRING_MAGIC: &[u8] = b"GnomeKeyring\n\r\0\n"; pub const BACKUP_KEEP: usize = 20;`
  - `pub fn is_plaintext_keyring(bytes: &[u8]) -> bool`
  - `pub struct BackupManager { pub root: PathBuf, pub keep: usize }`, `pub fn create(&self, reason: &str, files: &[PathBuf], passphrase: Option<&SecretValue>) -> Result<BackupInfo>`, `pub fn list(&self) -> Result<Vec<BackupInfo>>`.
  - `pub struct BackupInfo { pub dir: PathBuf, pub reason: String, pub created: String, pub files: Vec<BackupFile> }`, `pub struct BackupFile { pub original: PathBuf, pub stored: PathBuf, pub sha256: String, pub encrypted: bool }` (serde, written to `manifest.json`).
  - `pub fn keyring_backup_set(dir: &Path) -> Result<Vec<PathBuf>>`: all `*.keyring` plus `default` in `dir`.

Rules: `.keyring` files that are plaintext are age-encrypted (`age::Encryptor::with_user_passphrase`) to `<name>.age`; if any is plaintext and `passphrase` is `None` -> `PassphraseRequired` and nothing is written. sha256 is of the original bytes. After create, prune oldest dirs beyond `keep`. Reason sanitized to `[a-z0-9-]`.

- [ ] **Step 1: Failing tests** (tempdir): `backup_dir_is_0700`; `binary_keyring_copied_verbatim` (file starting with `KEYRING_MAGIC` stored as-is, sha256 matches); `plaintext_requires_passphrase` (`[keyring]\ndisplay-name=x` file, no passphrase -> `PassphraseRequired`, backups root empty); `plaintext_encrypted_with_age` (with passphrase -> stored `<name>.age`, decrypts back to original with same passphrase); `prunes_to_keep` (keep=2, create 3 -> 2 dirs remain, oldest removed).
- [ ] **Step 2:** FAIL. **Step 3:** Implement (`sha2`, `serde_json`, `age` deps; timestamps via `std::time` formatted manually or `jiff`/`time` crate, builder's choice). **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(core): add backups with age encryption for plaintext keyrings`.

### Task 9: Worker thread

**Files:**
- Create: `crates/kring/src/worker.rs`

**Interfaces:**
- Consumes: `SecretStore`, `MasterPasswordStore`, `ProviderInfo`, `PamStatus`, `BackupManager`.
- Produces:

```rust
pub enum Command {
    Refresh,
    LoadItems(CollectionId),
    RevealSecret(ItemId),
    CreateItem { collection: CollectionId, item: NewItem },
    UpdateItem { item: ItemId, update: ItemUpdate },
    DeleteItem { item: ItemId, backup_passphrase: Option<SecretValue> },
    SetDefault(CollectionId),
    Lock(CollectionId),
    Unlock { collection: CollectionId, password: SecretValue },
    CreateCollection { label: String, password: SecretValue },
    RenameCollection { collection: CollectionId, label: String },
    ChangePassword { collection: CollectionId, old: SecretValue, new: SecretValue },
    DeleteCollection { collection: CollectionId, backup_passphrase: Option<SecretValue> },
}
pub enum Event {
    Provider(ProviderInfo),
    ProviderUnavailable,
    Pam(PamStatus),
    Collections(Vec<CollectionInfo>),
    Items(CollectionId, Vec<ItemInfo>),
    Secret(ItemId, SecretValue),
    BackupCreated(BackupInfo),
    PassphraseNeeded(Box<Command>),
    Done(String),
    Error(String),
}
pub struct WorkerHandle { pub tx: std::sync::mpsc::Sender<Command>, pub rx: std::sync::mpsc::Receiver<Event> }
pub fn spawn<S>(store: Option<Arc<S>>, provider: Option<ProviderInfo>, backups: BackupManager, notify: impl Fn() + Send + 'static) -> WorkerHandle
where S: SecretStore + MasterPasswordStore + 'static;
```

Rules: on start emit `Provider` or `ProviderUnavailable`, then `Pam(pam_status("/etc/pam.d"))`, then `Collections`. Destructive commands (DeleteItem, DeleteCollection, ChangePassword, RenameCollection) first check `provider.allows_writes()` (else `Error("Not supported on this provider")`), then for deletes create a backup of `keyring_backup_set(keyrings_dir)` with reason `delete-item` / `delete-collection`; `PassphraseRequired` -> emit `PassphraseNeeded(cmd)` and do nothing. Every mutating command is followed by `Collections` (and `Items` for the affected collection). `NotFound` -> `Error(..)` then automatic `Refresh`. Call `notify()` after each event. A `std::thread` owns a current-thread tokio runtime.

- [ ] **Step 1: Failing tests** with `FakeStore` (tests make `BackupManager` point to tempdirs and override keyrings dir via a `spawn_with_keyrings_dir` test constructor or a field): `starts_with_provider_and_collections`, `no_provider_emits_unavailable` (store `None` -> `ProviderUnavailable`, no panic, other commands answer `Error("No Secret Service provider running")`), `delete_creates_backup_first` (event order: `BackupCreated` before `Collections`), `delete_blocked_on_kwallet_provider`, `not_found_triggers_refresh`, `plaintext_keyring_asks_passphrase` (keyrings dir has a textual file -> `PassphraseNeeded`, item still exists).
- [ ] **Step 2:** `cargo test -p kring` -> FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(app): add background worker with command/event channels`.

### Task 10: App state, clipboard guard, secret display

**Files:**
- Create: `crates/kring/src/app_state.rs`, `crates/kring/src/clipboard.rs`, `crates/kring/src/secret_display.rs`

**Interfaces:**
- Produces:
  - `pub struct AppState { pub provider: Option<ProviderInfo>, pub provider_unavailable: bool, pub pam: Option<PamStatus>, pub collections: Vec<CollectionInfo>, pub selected: Option<CollectionId>, pub items: Vec<ItemInfo>, pub selected_item: Option<ItemId>, pub revealed: Option<(ItemId, SecretValue)>, pub status: String, pub errors: Vec<String>, pub pending_passphrase: Option<Command> }` with `pub fn apply(&mut self, event: Event)`. Collections sorted: login first, then default alias, then label. `Items` for a non-selected collection are ignored. Selecting another item clears `revealed`.
  - `pub trait ClipboardBackend { fn set_text(&mut self, text: &str) -> Result<(), String>; fn get_text(&mut self) -> Result<String, String>; fn clear(&mut self) -> Result<(), String>; }`, `pub struct ArboardClipboard` impl, `pub struct ClipboardGuard<C> { backend: C, pending: Option<(Zeroizing<String>, Instant)> }`, `pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);`, `copy(&mut self, text: &str, now: Instant) -> Result<(), String>`, `tick(&mut self, now: Instant)`.
  - `pub enum SecretView { Text(String), Binary { len: usize, hex: String } }`, `pub fn secret_display(s: &SecretValue) -> SecretView`, `pub fn can_copy(view: &SecretView) -> bool` (false for Binary).

- [ ] **Step 1: Failing tests:** `login_sorted_first`; `items_for_other_collection_ignored`; `select_item_clears_revealed`; clipboard with a fake backend: `clears_after_30s` (copy at t0, tick at t0+29s -> still set, t0+30s -> cleared), `does_not_clear_if_user_copied_something_else` (fake `get_text` returns other text -> not cleared); `binary_secret_shown_as_hex` (`[0xff, 0x00]` -> `Binary { len: 2, hex: "ff00" }`, `can_copy` false); `utf8_secret_is_text`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(app): add app state reducer, clipboard guard and secret display`.

### Task 11: egui UI for secrets

**Files:**
- Create: `crates/kring/src/app.rs`, `crates/kring/src/views/mod.rs`, `views/sidebar.rs`, `views/collection.rs`, `views/item_detail.rs`, `views/dialogs.rs`, `crates/kring/src/widgets/mod.rs`, `widgets/password_field.rs`
- Modify: `crates/kring/src/main.rs`
- Create: `scripts/dev-session.sh` (same isolation as `it-session.sh`, seeds 3 collections `login`, `Default_1` (empty), `Work` and some items via `secret-tool`, then runs `cargo run -p kring`)

**Interfaces:**
- Consumes: `WorkerHandle`, `AppState`, `ClipboardGuard`, `secret_display`, `validate::*`.
- Produces: `pub struct KringApp` implementing `eframe::App`; layout as spec 6.9 (left panel sections: SECRETS with collections; OFFLINE FILES, KWALLET, SSH KEYS, GPG KEYS, TOOLS shown disabled with "coming soon"; bottom status bar `"{n} collections, {m} locked"` + worker state).

Behavior:
- Collection header shows badges `[default]`, `[login keyring]`, `[locked]`; warning row when `is_login` and `!pam.configured`: "PAM does not unlock this keyring at login"; info row always on login: "Auto-unlock works only if this keyring password equals your login password".
- Banner when `provider_unavailable`: "No Secret Service provider running". Banner listing `competitors` when non-empty: "Other services may claim org.freedesktop.secrets: ...".
- Buttons: New collection, Unlock (password modal), Lock, Set as default, Rename, Change password (old/new/confirm, `validate::new_password`), Delete (confirm modal naming the collection and its item count). Item table: label, attributes summary, modified; New item, Edit, Delete (confirm). Item detail: secret masked, Show/Hide, Copy (disabled when `can_copy` false), editable attribute rows validated with `validate::attributes`.
- Write actions disabled with tooltip "Read only: provider is not gnome-keyring" when `!allows_writes()`.
- `PassphraseNeeded` opens a modal "Backup contains plaintext keyrings, choose a passphrase" (password + confirm) and resends the command with `backup_passphrase` set.
- Password buffers are `Zeroizing<String>` and cleared when modals close. `ctx.request_repaint_after(1s)` while a clipboard clear is pending; call `ClipboardGuard::tick` each frame.

- [ ] **Step 1:** Implement views; `cargo build -p kring`; `cargo clippy --workspace -- -D warnings` -> clean.
- [ ] **Step 2: Manual verification** with `bash scripts/dev-session.sh`: login listed first with `[default] [login keyring]`; unlock/lock `Work` with its password from the seed script; create collection; set `Work` default (badge moves); create/edit/reveal/copy (clipboard cleared after 30 s, check with `xclip -o -selection clipboard`) /delete item; delete `Default_1` creates a dir under the temp `XDG_DATA_HOME/kring/backups`. Real `~/.local/share/keyrings` mtime unchanged.
- [ ] **Step 3:** Run `bash scripts/check-no-gui-toolkits.sh` -> exit 0, `cargo test --workspace` -> PASS, it-session suite -> PASS.
- [ ] **Step 4:** Update `CHANGES.md`, commit `feat(app): egui UI for Secret Service collections and items`.
