# kring Plan 2: Offline keyring files, recovery, backups UI, encrypted export

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read every `~/.local/share/keyrings/*.keyring` file without the daemon (binary v0 with password, textual plaintext, and textual files gnome-keyring rejects), browse their items, import them into a live collection, retire plaintext files safely, restore backups, and export/import items as age-encrypted files.

**Architecture:** New `kring-core` modules `keyring_file` (scan + tolerant textual parser + binary reader via oo7) and `transfer` (import planning, age item export/import), extending `backup` with restore. App side: new worker command handlers in a separate module, new rail areas "Offline files" and "Backups" (Tools) in the Obsidian UI.

**Tech Stack:** as Plan 1 (Rust 1.98, eframe/egui 0.37, oo7 0.7.1 `unstable`, age 0.12, zeroize, serde_json, time). No new GUI toolkit.

**Spec:** `docs/superpowers/specs/2026-11-15-kring-design.md` sections 2.2, 6.3, 6.4. UI style: Obsidian (`crates/kring/src/ui/`), see Plan 1 restyle.

## Findings that shape this plan (user's real system, 2026-11-15, read-only inspection)

- 64 `.keyring` files: 40 binary v0 (`GnomeKeyring\n\r\0\n`), 24 textual (`[keyring]` INI, plaintext on disk).
- 20 textual files are empty orphans (only the `[keyring]` group).
- 4 textual files hold secrets and are rejected by gnome-keyring ("keyring was in an invalid or unrecognized format") and by oo7 (`invalid key file line N`): `Default.keyring`, `Default_keyring.keyring` (22 KB), `Default_keyring_1.keyring`, `Default_keyring_2.keyring`. Cause: a `secret=` value containing raw newlines (multi-line JSON); the following lines have no `=` and are not group headers. Apps cannot see these secrets, which is why they keep creating new `Default_*` keyrings.
- oo7 0.7.1 public API: `oo7::file::UnlockedKeyring::load_from_v0(source, target_path, Option<Secret>)` loads binary or textual v0 in memory (nothing written until `write()`), `items()` returns items. Its textual parser is strict, so kring needs its own tolerant textual parser; binary v0 goes through oo7.

## Global Constraints

- All Plan 1 constraints still apply (`.superpowers/sdd/2026-11-15-kring-p1-secret-service/constraints.md` content is copied into this plan's workspace `constraints.md`): no Qt/GTK/GNOME/KDE libs, oo7 pinned, `SecretValue` for secrets with redacted Debug, never log secret bytes, English, rustdoc everywhere, early returns, UPPER_SNAKE constants, no long dash, rustfmt, commits without AI attribution.
- **Never write to a real keyring file** except through the explicit "Retire plaintext file" action (Task 7), always after an age backup. Reading is allowed.
- **Tests never read the user's real `~/.local/share/keyrings`.** Fixtures live in `crates/kring-core/tests/fixtures/keyrings/` and are synthetic (fake secrets like `fixture-secret-1`). Never copy the user's real files into the repo.
- Textual magic: a file is textual when it does not start with `b"GnomeKeyring\n\r\0\n"` and its first non-empty line is `[keyring]`. Anything else is `Unknown`.
- Strict-compat check (`daemon_readable`): emulate GLib key-file rules that gnome-keyring applies: every non-empty, non-comment line is either `[group]` or `key=value`; otherwise the file is not daemon-readable.
- Tolerant parse rules: a line that is neither a group header nor `key=value` is appended to the previous key's value with `\n`, and a `ParseWarning { line, kind: ContinuationLine }` is recorded. GLib escapes in values are decoded: `\n`, `\t`, `\r`, `\\`, `\s` (space at start). Unknown escape: keep literally and warn.
- Textual item model (gnome-keyring `gkm-secret-textual`): groups `[N]` with `display-name`, `secret` or `binary-secret` (hex), `item-type`, `mtime`, `ctime`; attribute groups `[N:attributeM]` with `name`, `type` (`string` or `uint32`), `value`. `[keyring]` has `display-name`, `ctime`, `mtime`, `lock-on-idle`, `lock-after`.
- Import conflict policy for this plan (Plan 3 builds the full conflict preview): same attributes + same secret in target -> skip as duplicate; same attributes + different secret -> skip and list as conflict (never overwrite); otherwise create with `replace = false`.
- Item export format (spec 6.4): age scrypt-passphrase file, plaintext JSON inside: `{"format":"kring-items","version":1,"items":[{"collection","label","attributes","secret_b64","content_type","created","modified"}]}`; JSON buffer held in `Zeroizing`.
- Restore writes into the keyrings dir only after creating a backup of the files it overwrites; the UI then tells the user to restart the daemon: `systemctl --user restart gnome-keyring-daemon` (show it, do not run it).

## Review Focus

1. **Multi-line secret recovery**: the user's actual failure mode. A fixture reproducing `secret=` + raw JSON continuation lines must parse to one item with the full multi-line secret, `daemon_readable == false`, one `ContinuationLine` warning per continuation line. Test in Task 2.
2. **Binary file with wrong password**: returns `KringError::InvalidInput("Wrong password ...")`-class error, no panic, no partial items. Test in Task 3 (fixture created by a real throwaway gnome-keyring in it-session).
3. **Retiring a file that the daemon has loaded**: must go through Secret Service `delete_collection` (with Plan 1 backup), never unlink a file of a live collection. Test in Task 7.
4. **Restore over an existing file**: current file backed up first; restore aborted if that backup fails. Test in Task 6.
5. **Wrong export passphrase / corrupted age file / wrong JSON format**: clear error, nothing imported. Test in Task 5.

---

### Task 1: Fixtures and file scan

**Files:**
- Create: `crates/kring-core/src/keyring_file/mod.rs`, `crates/kring-core/src/keyring_file/scan.rs`
- Create: `crates/kring-core/tests/fixtures/keyrings/` with synthetic files: `empty_textual.keyring` (only `[keyring]`), `textual_two_items.keyring`, `textual_multiline_secret.keyring` (secret value with raw newline JSON continuation, like the real failure), `textual_binary_secret.keyring` (`binary-secret=` hex), `garbage.keyring` (random text). Binary fixtures come in Task 3.

**Interfaces:**
- Produces:
  - `pub enum KeyringFormat { BinaryV0, Textual, Unknown }`
  - `pub struct KeyringFileInfo { pub path: PathBuf, pub name: String /* file stem */, pub format: KeyringFormat, pub size: u64, pub modified: u64, pub display_name: Option<String>, pub item_count: Option<usize> /* textual only */, pub daemon_readable: Option<bool> /* textual only */, pub plaintext: bool }`
  - `pub fn detect_format(bytes: &[u8]) -> KeyringFormat`
  - `pub fn scan_dir(dir: &Path) -> Result<Vec<KeyringFileInfo>>`: `*.keyring` only, sorted by name; missing dir -> empty; unreadable file -> entry with `format: Unknown`.

- [ ] Step 1: failing tests: `detect_binary_magic`, `detect_textual`, `detect_garbage_unknown`, `scan_fixture_dir` (asserts per-file format, item_count for textual (0, 2, 1, 1), daemon_readable (true, true, false, true), plaintext true for textual).
- [ ] Step 2: implement (scan uses the Task 2 parser for textual counts; to keep Task 1 independent, implement `scan` after Task 2's parser exists: do Tasks 1 and 2 in one implementer dispatch).
- [ ] Step 3: tests pass, commit `feat(core): scan keyring files and detect formats`.

### Task 2: Tolerant textual parser

**Files:**
- Create: `crates/kring-core/src/keyring_file/textual.rs`

**Interfaces:**
- Produces:
  - `pub struct OfflineItem { pub label: String, pub attributes: Attributes, pub secret: SecretValue, pub created: u64, pub modified: u64 }` (no Debug of secret: derive Debug is fine because SecretValue is redacted)
  - `pub enum WarningKind { ContinuationLine, UnknownEscape, BadBinarySecret, MissingSecret, BadNumber }`
  - `pub struct ParseWarning { pub line: usize, pub kind: WarningKind }`
  - `pub struct TextualKeyring { pub display_name: Option<String>, pub items: Vec<OfflineItem>, pub warnings: Vec<ParseWarning>, pub daemon_readable: bool }`
  - `pub fn parse_textual(bytes: &[u8]) -> Result<TextualKeyring>` (non-UTF-8 -> `InvalidInput`).
- Rules: Global Constraints "Tolerant parse rules" and "Textual item model". `uint32` attributes: parse as u64, truncate to u32, string it (like oo7/gnome-keyring). If no `xdg:schema` attribute, add schema from `item-type` exactly like oo7 `item_type_schema` (0 -> `org.freedesktop.Secret.Generic`, 1 -> `org.gnome.keyring.NetworkPassword`, 2 -> `org.gnome.keyring.Note`, 3 -> `org.gnome.keyring.ChainedKeyring`, 4 -> `org.gnome.keyring.EncryptionKey`, 0x100 -> `org.gnome.keyring.PkStorage`). Secret content type `text/plain` for `secret=`, `application/octet-stream` for `binary-secret`. Parsing buffers holding secrets use `Zeroizing<String>`.

- [ ] Failing tests: `parses_two_items_with_attributes`, `multiline_secret_recovered` (Review Focus 1: exact multi-line secret bytes, warnings lines, daemon_readable false), `glib_escapes_decoded`, `binary_secret_hex`, `uint32_attribute_truncated`, `schema_from_item_type`, `non_utf8_rejected`.
- [ ] Implement, pass, commit `feat(core): tolerant parser for textual gnome-keyring files`.

### Task 3: Binary v0 reader

**Files:**
- Create: `crates/kring-core/src/keyring_file/binary.rs`
- Create: `crates/kring-core/examples/make_binary_fixture.rs` (runs only inside it-session via `dev_guard`; creates collection `fixture` with password `fixture-pw` and 2 items via `MasterPasswordStore` + `SecretStore`, then copies `$XDG_DATA_HOME/keyrings/fixture.keyring` to `crates/kring-core/tests/fixtures/keyrings/binary_two_items.keyring`). Commit the generated fixture.

**Interfaces:**
- Produces: `pub async fn read_binary(path: &Path, password: &SecretValue) -> Result<Vec<OfflineItem>>` using `oo7::file::UnlockedKeyring::load_from_v0(path, <scratch path under std::env::temp_dir that is never written>, Some(secret))` then `items()`; map oo7 errors: wrong password / MAC mismatch -> `KringError::InvalidInput("Wrong password for <name>")`, other -> `Io`/`Dbus`-free `InvalidInput` with message. Convert oo7 items to `OfflineItem` (label, attributes, secret with its content type, created/modified secs).

- [ ] Failing tests: `reads_binary_fixture` (2 items, known labels/attributes, secrets `fixture-secret-1/2`), `wrong_password_is_clean_error` (Review Focus 2).
- [ ] Implement, pass, commit `feat(core): read binary v0 keyring files offline`.

### Task 4: Import planning and execution

**Files:**
- Create: `crates/kring-core/src/transfer/mod.rs`, `crates/kring-core/src/transfer/import.rs`

**Interfaces:**
- Produces:
  - `pub enum ImportDecision { Create, SkipDuplicate, SkipConflict }`
  - `pub struct ImportPlanEntry { pub label: String, pub attributes: Attributes, pub decision: ImportDecision }`
  - `pub fn plan_import(incoming: &[OfflineItem], existing: &[(ItemInfo, SecretValue)]) -> Vec<ImportPlanEntry>` (pure; equality: attributes map equal; duplicate when secret bytes also equal).
  - `pub struct ImportReport { pub created: usize, pub duplicates: usize, pub conflicts: Vec<String> /* labels */, pub failed: Vec<(String, String)> }`
  - `pub async fn import_items<S: SecretStore + ?Sized>(store: &S, target: &CollectionId, incoming: Vec<OfflineItem>) -> Result<ImportReport>`: target must be unlocked (else `Locked`); reads existing items + secrets of target, plans, creates `Create` entries with `replace: false`, continues on per-item failure (recorded in `failed`).

- [ ] Failing tests with `FakeStore`: `plan_marks_duplicates_and_conflicts`, `import_creates_only_new`, `import_into_locked_fails`, `import_continues_after_item_failure` (fake store wrapper failing one create).
- [ ] Implement, pass, commit `feat(core): plan and import offline items into a collection`.

### Task 5: Encrypted item export/import

**Files:**
- Create: `crates/kring-core/src/transfer/archive.rs`

**Interfaces:**
- Produces:
  - `pub const EXPORT_FORMAT: &str = "kring-items"; pub const EXPORT_VERSION: u32 = 1;`
  - `pub struct ExportedItem { pub collection: String, pub item: OfflineItem }`
  - `pub fn write_archive(path: &Path, items: &[ExportedItem], passphrase: &SecretValue) -> Result<()>` (file mode 0600, written via temp + rename, refuses to overwrite an existing file -> `InvalidInput`).
  - `pub fn read_archive(path: &Path, passphrase: &SecretValue) -> Result<Vec<ExportedItem>>`.
  - Format per Global Constraints; secrets base64 in JSON; all plaintext JSON buffers `Zeroizing`.

- [ ] Failing tests: `roundtrip_text_and_binary_secrets`, `wrong_passphrase_fails`, `corrupted_file_fails`, `wrong_format_tag_fails`, `refuses_overwrite`, `file_mode_0600` (Review Focus 5).
- [ ] Implement (add `base64` dep), pass, commit `feat(core): age-encrypted item export and import`.

### Task 6: Backup restore

**Files:**
- Modify: `crates/kring-core/src/backup.rs` (or create `crates/kring-core/src/backup/restore.rs` if backup.rs exceeds ~300 non-test lines; move to a `backup/` module then)

**Interfaces:**
- Produces:
  - `pub fn read_backup_file(info: &BackupInfo, file: &BackupFile, passphrase: Option<&SecretValue>) -> Result<Zeroizing<Vec<u8>>>` (decrypts `.age` entries; verifies sha256 against manifest -> mismatch is `InvalidInput("Backup file corrupted ...")`).
  - `pub fn restore(manager: &BackupManager, info: &BackupInfo, files: &[BackupFile], keyrings_dir: &Path, passphrase: Option<&SecretValue>) -> Result<RestoreReport>`: first backs up the current versions of the files it will overwrite (reason `pre-restore`; abort on failure, Review Focus 4), then writes each file via temp + rename with mode 0600. `pub struct RestoreReport { pub restored: Vec<PathBuf>, pub pre_restore_backup: Option<BackupInfo> }`.
  - `pub const RESTART_HINT: &str = "systemctl --user restart gnome-keyring-daemon";`

- [ ] Failing tests (tempdirs): `restore_binary_file`, `restore_encrypted_plaintext_file_needs_passphrase`, `restore_backs_up_current_first`, `restore_aborts_when_pre_backup_fails`, `sha_mismatch_detected`.
- [ ] Implement, pass, commit `feat(core): restore keyring files from backups`.

### Task 7: Retire plaintext file

**Files:**
- Create: `crates/kring-core/src/keyring_file/retire.rs`

**Interfaces:**
- Consumes: `BackupManager`, `SecretStore`, `paths`, the object-path decoding helper from Plan 1 (`decode_path_segment` in `model.rs`) and its inverse (add `pub fn encode_path_segment(name: &str) -> String`: every byte not `[A-Za-z0-9]` -> `_xx` lowercase hex; unit test round-trips with `decode_path_segment`).
- Produces:
  - `pub enum RetireMode { DeleteFile, DeleteLiveCollection(CollectionId) }`
  - `pub fn retire_mode(info: &KeyringFileInfo, live: &[CollectionInfo]) -> RetireMode` (pure: live when a collection path segment decodes to `info.name`).
  - `pub fn retire_file(manager: &BackupManager, info: &KeyringFileInfo, passphrase: &SecretValue) -> Result<BackupInfo>`: only for `RetireMode::DeleteFile` and `info.plaintext`; creates an age-encrypted backup (reason `retire-plaintext`) and only then removes the file. Non-plaintext or live -> `InvalidInput`.
- The worker (Task 8) uses `DeleteLiveCollection` through the existing Plan 1 `DeleteCollection` command path (which already backs up), never `retire_file`.

- [ ] Failing tests: `retire_mode_detects_live_collection` (Review Focus 3, include an escaped name like `Default_keyring` <-> `Default_5fkeyring`), `retire_backs_up_then_deletes`, `retire_refuses_binary`, `retire_keeps_file_when_backup_fails`, `encode_decode_roundtrip`.
- [ ] Implement, pass, commit `feat(core): retire plaintext keyring files safely`.

### Task 8: Worker commands for offline features

**Files:**
- Create: `crates/kring/src/worker_offline.rs` (handlers; keep `worker.rs` changes to dispatch only)
- Modify: `crates/kring/src/worker.rs` (new Command/Event variants and dispatch), `crates/kring/src/app_state.rs` (new state + reducer cases)

**Interfaces:**
- Commands: `ScanFiles`, `OpenFile { name: String, password: Option<SecretValue> }`, `ImportFile { name: String, password: Option<SecretValue>, target: CollectionId }`, `RetireFile { name: String, backup_passphrase: SecretValue }`, `ListBackups`, `RestoreBackup { dir: PathBuf, files: Vec<PathBuf>, passphrase: Option<SecretValue> }`, `ExportCollection { collection: CollectionId, path: PathBuf, passphrase: SecretValue }`, `ImportArchive { path: PathBuf, passphrase: SecretValue, target: CollectionId }`.
- Events: `Files(Vec<KeyringFileInfo>)`, `FileItems { name: String, items: Vec<OfflineItem>, warnings: Vec<ParseWarning> }`, `ImportDone(ImportReport)`, `Backups(Vec<BackupInfo>)`, `RestoreDone(RestoreReport)`, plus existing `Done`/`Error`/`PassphraseNeeded`.
- Gating: `ImportFile`, `ImportArchive` need a store (any provider; copy-into is allowed by spec). `RetireFile` for a live collection maps to the existing `DeleteCollection` flow (needs `allows_writes()`); for a non-live plaintext file it needs no provider. `RestoreBackup` needs no provider. File names are resolved only inside `WorkerConfig.keyrings_dir` (reject names with `/` or `..`).
- AppState: `files`, `selected_file`, `file_items` (+ warnings), `backups`, `last_import`. Selecting another file clears `file_items` (secrets).

- [ ] Failing tests (FakeStore + tempdir fixtures copied from `tests/fixtures/keyrings`): `scan_emits_files`, `open_textual_without_password`, `open_binary_needs_password`, `import_file_reports_counts`, `retire_live_file_uses_delete_collection_with_backup`, `retire_plaintext_file_backs_up_then_removes`, `restore_emits_report`, `export_then_import_archive_roundtrip`, `rejects_path_traversal_names`.
- [ ] Implement, pass, commit `feat(app): worker commands for offline files, backups and archives`.

### Task 9: UI: Offline files area

**Files:**
- Create: `crates/kring/src/views/files_list.rs`, `crates/kring/src/views/file_detail.rs`
- Modify: `crates/kring/src/views/rail.rs` (enable Offline files tile), `crates/kring/src/app.rs` (area switch), dialogs for password / import target / retire confirm.

**Behavior (Obsidian style, reuse `ui/` widgets):**
- List panel "Keyring files": search, summary "N files - M plaintext - K unreadable by gnome-keyring", rows with name + chips `BINARY` / `PLAINTEXT` (TERTIARY tint) / `UNREADABLE` (ERROR tint) / `EMPTY`, size muted.
- Detail: header (file name, chips, path muted, size, modified), notes card: plaintext warning (TERTIARY) "Secrets in this file are stored unencrypted on disk"; unreadable explanation (ERROR) "gnome-keyring cannot read this file, so apps cannot see these N secrets. Import them into a keyring to recover them." with warnings count; live/not-live info.
- Binary: "Open" button -> password dialog -> items. Textual: items shown directly.
- Items: read-only cards like the Secrets view (expand, reveal, copy via existing copy flow; no edit).
- Actions: `Import into...` (primary; dialog with target collection combo, default `login`; result toast with created/duplicates/conflicts and a conflicts list card), `Retire file` (danger; only plaintext; confirm dialog stating backup + delete, or "will delete the live keyring '<name>' with backup" for live; passphrase for the age backup).
- Empty-orphan quick action: when a file is textual, empty and not live, show "Retire" directly.

- [ ] Implement with pure helpers tested (`file_chips(info)`, `files_summary(files)`, `retire_dialog_text(mode, info)`), screenshots via the scratchpad `shot-kring.sh` + dev presets (extend `dev_preset` with `KRING_DEV_AREA=files`, same guard). Seed: extend `scripts/dev-session.sh` to copy the synthetic fixtures into the temp keyrings dir BEFORE starting the daemon (so the daemon reports the multiline one as unreadable, like on the user's machine).
- [ ] Commit `feat(ui): offline keyring files area`.

### Task 10: UI: Backups area and export/import

**Files:**
- Create: `crates/kring/src/views/backups.rs`
- Modify: rail (Tools tile -> Backups), collection header (Export icon button -> dialog: path + passphrase+confirm; Import archive button in item toolbar -> dialog: file path + passphrase, target = current collection).

**Behavior:**
- Backups list (newest first): reason, created, file count, size; detail shows files (encrypted chip for `.age`), `Restore selected` (danger; confirm lists files that will be overwritten; passphrase when any `.age`), then a card with `RESTART_HINT` and a copy button.
- File paths typed in an input (Paranoid uses `clean_path` for typed paths; port it), optionally `rfd` with `xdg-portal` if it does not add GTK (verify with the toolkit guard; if it does, skip rfd).

- [ ] Implement with pure helpers tested, screenshots, commit `feat(ui): backups area, collection export and archive import`.

### Task 11: Real-data dry run (read-only) and docs

- [ ] Add example `crates/kring-core/examples/scan_report.rs`: scans a directory given as argument and prints, per file, ONLY: name, format, size, item_count, daemon_readable, warnings count by kind. Never labels, attributes or secrets.
- [ ] Run it on the user's real `~/.local/share/keyrings` (read-only) and record the summary in the report: expected 40 binary, 24 textual, 4 unreadable with continuation warnings. Confirm all 4 unreadable files parse with the tolerant parser (item counts > 0).
- [ ] Update `CHANGES.md` and the README usage section (create a short `README.md` if missing: what kring is, dev-session, safety notes). Commit `docs: offline files usage and real-data dry run`.
