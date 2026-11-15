# kring Plan 4: KWallet migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read the user's KWallet wallet offline (`~/.local/share/kwalletd/kdewallet.kwl` + `.salt` + `kdewallet_attributes.json`), browse its folders and entries, and migrate entries into a Secret Service collection so apps find them again (original fdo attributes restored), reusing the Plan 3 transfer preview (duplicates, conflicts, idempotent re-runs).

**Architecture:** `kring-core::kwallet_file` (pure-Rust parser: header, PBKDF2-SHA512 key, KWallet Blowfish-CBC, integrity check, QDataStream folder/entry decoding; attributes JSON reader; mapping to `Incoming` items). Worker commands open a wallet with a password and plan an import through the existing transfer machinery. UI: KWallet rail area in the Obsidian style.

**Tech Stack:** as before, plus `blowfish` (RustCrypto, `cipher` traits), `pbkdf2` + `sha2` (already in tree via oo7), `sha1` for the integrity hash if needed. No Qt/KDE libraries (kwalletd6 is only used as an external process to generate test fixtures in an isolated session).

**Spec:** `docs/superpowers/specs/2026-11-15-kring-design.md` section 6.5 (user decision: apps must keep working; restore original fdo attributes from `kdewallet_attributes.json`).

## Findings (user's system, read-only, header bytes and JSON shape only)

- `kdewallet.kwl` 21256 bytes, header `KWALLET\n\r\0\r\n` then bytes `00 01 03 02`: version 0.1, cipher 3 (Blowfish CBC), hash 2 (PBKDF2-SHA512). `kdewallet.salt` is 56 bytes.
- `kdewallet_attributes.json`: JSON object, 115 keys: `$fdo_created`, `$fdo_modified` and per-folder objects; each folder maps entry keys to objects with `$fdo_created`, `$fdo_modified`, `attributes` (string map). Entries written through KWallet's Secret Service compat layer.
- `kwalletd6` and `org.kde.secretservicecompat` are running on the user's session (spec 6.2: warn about competing providers after migration).

## Global Constraints

- All Plan 1-3 constraints (no GUI toolkits, SecretValue/zeroize, no secrets in events except Secret/FileItems/(new) WalletItems, English, rustdoc, early returns, UPPER_SNAKE, no long dash, rustfmt, Conventional Commits without AI attribution, tests never touch real data: fixtures + tempdirs + isolated sessions).
- **Never read the user's real wallet contents in tests or tools.** The real wallet is only opened by the user in the app with their password.
- KWallet constants (verify against the KWallet source before coding): magic `b"KWALLET\n\r\0\r\n"`; cipher 0 = Blowfish ECB (legacy), 2 = GPG (unsupported -> clear error), 3 = Blowfish CBC; hash 0 = SHA1 (legacy), 2 = PBKDF2-SHA512. Support cipher 3 + hash 2 (user's case); support cipher 0/hash 0 only if trivial, otherwise clear "unsupported wallet format" error.
- Wrong password must produce `InvalidInput("Wrong wallet password")`, never garbage items, detected by the wallet's integrity hash.
- Decrypted buffers in `Zeroizing`.
- Mapping (spec 6.5): entries present in the attributes JSON -> label `<entry key>`? (verify what KWallet's compat layer uses as label: probably the entry key is the fdo label) + exact `attributes` + created/modified from `$fdo_*`; native entries -> label `<folder>/<key>`, attributes `kwallet-folder`, `kwallet-key`, `kwallet-type`, `xdg:schema=org.kde.KWallet.Entry`; Password -> text secret; Map -> JSON text (content type `application/json`); Stream -> bytes `application/octet-stream`. Import goes through `plan_transfer` with `TransferSource::Offline`, so duplicates/conflicts/idempotency come from Plan 3.

## Review Focus

1. Wrong password never yields items (integrity check). Task 2.
2. Parser never panics on truncated/garbage input (deterministic no-panic test). Task 2.
3. Compat entries keep exact attributes (apps find them); re-running import yields only duplicates. Tasks 3, 4.
4. Fixtures are produced by a real kwalletd6 in an isolated session, not by kring's own encoder. Task 1.
5. Secrets never leave the worker except in the dedicated wallet items event, cleared on area/wallet change. Tasks 4, 5.

---

### Task 1: Isolated kwalletd6 session and real fixtures

**Files:** `scripts/kwallet-session.sh`, `crates/kring-core/examples/make_kwallet_fixture.rs` (guarded by `dev_guard` like seed_dev), `crates/kring-core/tests/fixtures/kwallet/{fixture.kwl,fixture.salt,fixture_attributes.json,README.md}`.

- Research KWallet's D-Bus API (org.kde.KWallet on kwalletd6): `pamOpen(wallet, passwordHash, sessionTimeout)` (password hash = the PBKDF2 key, opens/creates without GUI), `open`, `createFolder`, `writePassword`, `writeMap`, `writeEntry`, `close`, and the Secret Service compat layer (to create entries with fdo attributes so `_attributes.json` is written). Use web docs / KWallet source (invent.kde.org/frameworks/kwallet) via the web-fetch agent or WebFetch if available.
- `kwallet-session.sh`: like `it-session.sh` (private dbus-run-session, temp HOME/XDG_*, guards, KRING_IT_RUNTIME), starts `kwalletd6` (keep DISPLAY only if strictly required; prefer `QT_QPA_PLATFORM=offscreen`), runs the given command.
- The example creates wallet `fixture` with password `fixture-pw`, folders `Passwords` (password entry `site` = `fixture-secret-1`), `Maps` (map entry `form` = {user: alice, pass: fixture-secret-2}), `Streams` (stream entry `blob` = bytes 00 ff 10), and at least 2 entries through the Secret Service compat layer with attributes (e.g. `{service: fixture, user: bob}`), then closes the wallet and copies the 3 files into the fixtures dir.
- If kwalletd6 cannot run headless, report BLOCKED with what was tried (do not fall back to self-generated fixtures without the controller's ruling).
- Commit `test: real kwalletd6 wallet fixtures generated in an isolated session`.

### Task 2: Wallet decryption and structure parser

**Files:** `crates/kring-core/src/kwallet_file/{mod.rs,format.rs,crypto.rs,parse.rs}`.

**Interfaces:**
- `pub struct WalletHeader { pub major: u8, pub minor: u8, pub cipher: u8, pub hash: u8 }`, `pub fn read_header(bytes: &[u8]) -> Result<WalletHeader>`.
- `pub enum EntryValue { Password(SecretValue), Map(Vec<(String, SecretValue)>), Stream(SecretValue), Unknown(u32) }` (secrets in SecretValue).
- `pub struct WalletEntry { pub folder: String, pub key: String, pub value: EntryValue }`.
- `pub fn open_wallet(kwl: &[u8], salt: &[u8], password: &SecretValue) -> Result<Vec<WalletEntry>>`.
- Implement exactly KWallet's algorithm (key derivation iterations/length, KWallet's CBC with its IV/chaining, the random prefix + size + payload + hash layout, QDataStream big-endian encoding of folders, entries, QString UTF-16BE, QByteArray). Cite the KWallet source file and function for each step in rustdoc.
- Tests: fixture opens with `fixture-pw` and yields the Task 1 entries exactly; wrong password -> InvalidInput("Wrong wallet password"); unsupported cipher/hash -> InvalidInput naming the format; deterministic no-panic test over prefixes/garbage.
- Commit `feat(core): decrypt and parse KWallet wallet files`.

### Task 3: Attributes JSON and mapping to transfer items

**Files:** `crates/kring-core/src/kwallet_file/{attributes.rs,mapping.rs}`.

**Interfaces:**
- `pub struct FdoMeta { pub attributes: Attributes, pub created: u64, pub modified: u64 }`, `pub fn read_attributes(json: &[u8]) -> Result<HashMap<(String /*folder*/, String /*key*/), FdoMeta>>` (missing file -> empty map; tolerant of unknown fields).
- `pub fn to_incoming(entries: &[WalletEntry], meta: &HashMap<..>) -> Vec<Incoming>` with `TransferSource::Offline(i)`; mapping per Global Constraints (verify the compat layer's label/key convention from the KWallet source and the fixture).
- Tests on the fixture: compat entries carry exact attributes and dates; native entries use the fallback mapping; Map serialized as stable JSON (sorted keys); Stream bytes preserved; idempotency: planning the same items against a target that already holds them -> all Duplicate.
- Commit `feat(core): map KWallet entries to Secret Service items`.

### Task 4: Worker commands

**Files:** `crates/kring/src/worker_wallet.rs` (+ tests), worker.rs variants/dispatch, app_state.rs.

- `Command::ScanWallets` -> `Event::Wallets(Vec<WalletInfo { name, path, size, modified, header: Option<WalletHeader>, has_attributes: bool }>)` (lists `*.kwl` in `$XDG_DATA_HOME/kwalletd`, `WorkerConfig.kwallet_dir`).
- `Command::OpenWallet { name, password }` -> `Event::WalletItems { name, items: Vec<OfflineItemView> }` where the view carries label, attributes, folder, key, kind and the secret (dedicated secret-bearing event, like FileItems; cleared on wallet change/area switch).
- `Command::PlanWalletImport { name, password, target }` -> reuse the Plan 3 import path (no conflicts -> apply directly + ImportDone; conflicts -> TransferPreview with offline items revealable from WalletItems).
- After a successful import, if `ProviderInfo.competitors` contains kwalletd / secretservicecompat, emit a notice: "KWallet is still running and may claim org.freedesktop.secrets; disable KWallet's Secret Service integration after migrating".
- Names resolved via a fresh scan only; wrong password -> Error without plan.
- Tests with the fixture in tempdirs; FakeStore.
- Commit `feat(app): worker commands for KWallet wallets`.

### Task 5: UI KWallet area

**Files:** `crates/kring/src/views/{wallets_list.rs,wallet_detail.rs}`, rail tile enabled, dialogs (password), dev preset `KRING_DEV_AREA=kwallet` (guarded), dev-session seeds the fixture wallet into the temp `XDG_DATA_HOME/kwalletd`.

- List: wallets with chips (BLOWFISH CBC / PBKDF2, or UNSUPPORTED), size, "has app attributes".
- Detail: Open (password dialog) -> folders as collapsible groups -> read-only cards like offline files (label, attributes, reveal/copy, kind chip PASSWORD/MAP/STREAM, "app entry" chip when attributes came from the compat layer).
- `Import into...` (target picker with disambiguated names) -> Plan 3 preview -> apply; result toast; competitor notice card.
- Pure helpers tested; screenshots `kring-kwallet-*.png`.
- Commit `feat(ui): KWallet area with migration`.

### Task 6: Docs

- README KWallet section (what is migrated, how attributes are restored, disabling KWallet's Secret Service afterwards), CHANGES.md. Commit `docs: KWallet migration`.
